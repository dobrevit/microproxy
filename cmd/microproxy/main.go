// Command microproxy is a standalone HTTP and HTTPS forward proxy built on the
// github.com/dobrevit/microproxy package.
//
// It is configured from a TOML file, reopens its logs on SIGUSR1 and re-reads
// its configuration on SIGUSR2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dobrevit/microproxy"
)

// shutdownTimeout is how long the requests in flight are given to finish when
// the proxy is asked to stop.
const shutdownTimeout = 10 * time.Second

func main() {
	configFile := flag.String("config", "microproxy.toml", "proxy configuration file")
	proxyInsecure := flag.Bool("i", false, "allow insecure forward proxy connections")
	testConfigOnly := flag.Bool("t", false, "only test configuration file")
	verboseMode := flag.Bool("v", false, "enable verbose debug mode")

	flag.Parse()

	conf, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	if *testConfigOnly {
		if _, err := conf.credentials(); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Configuration file seems ok.")
		os.Exit(0)
	}

	if err := run(conf, *configFile, *verboseMode, *proxyInsecure); err != nil {
		log.Fatal(err)
	}
}

// proxy is the running command: the server plus the log files that only a
// standalone proxy owns.
type proxy struct {
	server   *microproxy.Server
	activity *microproxy.FileLogger
	access   *microproxy.FileAccessLogger
	path     string

	// healthServer is the separate listener the /health endpoint is served
	// on, when the configuration asks for one.
	healthServer *http.Server
}

func run(conf *fileConfig, path string, verbose, insecure bool) error {
	activity, err := microproxy.NewFileLogger(conf.ActivityLog)
	if err != nil {
		return fmt.Errorf("couldn't open activity log file %v: %w", conf.ActivityLog, err)
	}
	defer activity.Close()

	options := []microproxy.Option{
		microproxy.WithLogger(activity),
		microproxy.WithVerbose(verbose),
		microproxy.WithInsecureUpstream(insecure),
	}

	var access *microproxy.FileAccessLogger

	if conf.AccessLog != "" {
		if access, err = microproxy.NewFileAccessLogger(conf.AccessLog); err != nil {
			return fmt.Errorf("couldn't open access log file %v: %w", conf.AccessLog, err)
		}
		defer access.Close()

		options = append(options, microproxy.WithAccessLogger(access))
	}

	credentials, err := conf.credentials()
	if err != nil {
		return err
	}
	options = append(options, microproxy.WithCredentials(credentials))

	server, err := microproxy.New(conf.Config, options...)
	if err != nil {
		return err
	}

	command := &proxy{server: server, activity: activity, access: access, path: path}
	command.handleSignals()

	activity.Printf("starting proxy\n")
	activity.Printf("listening on %v\n", conf.Listen)
	activity.Printf("using configuration file %v\n", path)

	// Every listener serves the same proxy, so the first one to fail stops the
	// command; a clean shutdown makes them all return without an error.
	failures := make(chan error, 3)

	if conf.SOCKSListen != "" {
		activity.Printf("listening for SOCKS on %v\n", conf.SOCKSListen)

		go func() { failures <- ignoreServerClosed(server.ListenAndServeSOCKS()) }()
	}

	if health := server.Health(); health != nil && conf.HTTPListen != "" {
		activity.Printf("serving /health on %v\n", conf.HTTPListen)

		command.healthServer = &http.Server{
			Addr:              conf.HTTPListen,
			Handler:           healthMux(health),
			ReadHeaderTimeout: healthReadHeaderTimeout,
		}

		go func() { failures <- ignoreServerClosed(command.healthServer.ListenAndServe()) }()
	}

	go func() { failures <- ignoreServerClosed(server.ListenAndServe()) }()

	return <-failures
}

// healthReadHeaderTimeout bounds how long a probe may take to send its request.
const healthReadHeaderTimeout = 10 * time.Second

func healthMux(health *microproxy.Health) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/health", health.Handler())

	return mux
}

// ignoreServerClosed turns the error a frontend reports when it was asked to
// stop into a clean exit.
func ignoreServerClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

func (p *proxy) handleSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

	go func() {
		for sig := range signals {
			switch sig {
			case os.Interrupt, syscall.SIGTERM:
				p.activity.Printf("got interrupt signal, exiting\n")
				p.stop()

				return
			case syscall.SIGUSR1:
				p.activity.Printf("got USR1 signal, reopening logs\n")
				p.reopenLogs()
			case syscall.SIGUSR2:
				p.activity.Printf("got USR2 signal, reloading configuration\n")
				p.reload()
			}
		}
	}()
}

func (p *proxy) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := p.server.Shutdown(ctx); err != nil {
		p.activity.Printf("ERROR: couldn't shut down cleanly: %v\n", err)
	}

	if p.healthServer != nil {
		if err := p.healthServer.Shutdown(ctx); err != nil {
			p.activity.Printf("ERROR: couldn't shut down the health endpoint: %v\n", err)
		}
	}

	if p.access != nil {
		if err := p.access.Close(); err != nil {
			p.activity.Printf("ERROR: couldn't close the access log: %v\n", err)
		}
	}

	_ = p.activity.Close()
}

func (p *proxy) reopenLogs() {
	if p.access != nil {
		if err := p.access.Reopen(); err != nil {
			p.activity.Printf("ERROR: couldn't reopen the access log: %v\n", err)
		}
	}

	if err := p.activity.Reopen(); err != nil {
		log.Printf("couldn't reopen the activity log: %v", err)
	}
}

// reload re-reads the configuration file and installs it for the requests that
// follow. A file that can't be used leaves the running proxy untouched.
func (p *proxy) reload() {
	conf, err := loadConfig(p.path)
	if err != nil {
		p.activity.Printf("ERROR: couldn't reload configuration, keeping the current one: %v\n", err)

		return
	}

	credentials, err := conf.credentials()
	if err != nil {
		p.activity.Printf("ERROR: couldn't reload the credentials, keeping the current ones: %v\n", err)

		return
	}

	if err := p.server.Reload(conf.Config); err != nil {
		p.activity.Printf("ERROR: couldn't reload configuration, keeping the current one: %v\n", err)

		return
	}

	if err := p.server.SetCredentials(credentials); err != nil {
		p.activity.Printf("ERROR: couldn't install the reloaded credentials: %v\n", err)

		return
	}

	p.activity.Printf("configuration reloaded\n")
}
