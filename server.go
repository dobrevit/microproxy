package microproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	tcpKeepAliveInterval = 1 * time.Minute
	// readHeaderTimeout bounds how long a client may take to send the headers
	// of a request it has started, which is what a slow loris does not.
	readHeaderTimeout = 1 * time.Minute
	// idleTimeout is how long a client may hold a connection open without
	// sending anything on it. It has to be set for readHeaderTimeout to apply
	// to requests only: with no idle timeout of its own, net/http waits for
	// the next request under the header deadline and drops the keep-alive
	// connections that are simply idle.
	idleTimeout = 5 * time.Minute
)

// Server is a proxy. It is created by New, and serves requests through Serve or
// ListenAndServe, or as the http.Handler that Handler returns.
//
// A Server is safe for concurrent use, and its configuration and credentials
// can be replaced while it is serving.
type Server struct {
	proxy *goproxy.ProxyHttpServer

	conf   atomic.Pointer[compiledConfig]
	auth   atomic.Pointer[authenticator]
	nonces *nonceStore

	log       Logger
	access    AccessLogger
	router    Router
	dialer    ContextDialer
	tlsConfig *tls.Config
	verbose   bool
	health    *Health

	// listenerTLS, when set, makes the HTTP frontend accept TLS connections
	// rather than plain ones. It is the server side, and has nothing to do
	// with tlsConfig, which is how this proxy talks to an https:// upstream.
	listenerTLS *tls.Config

	envRoutes routeCache

	// localAddr is where outgoing connections are made from. It comes from
	// Config.BindIP, which is why a reload can't change it.
	localAddr *net.TCPAddr

	mu         sync.Mutex
	httpServer *http.Server
	listener   net.Listener

	socksListener net.Listener
	socksConns    map[net.Conn]struct{}
	socksDone     bool
	socksActive   sync.WaitGroup
}

// New builds a proxy from cfg. The options replace the parts a configuration
// can't describe: where the logs go, what the credentials are, and how the
// connections are made.
//
// cfg is copied, so the caller may reuse or modify it afterwards.
func New(cfg Config, opts ...Option) (*Server, error) {
	server := &Server{
		nonces: newNonceStore(),
		log:    DiscardLogger,
	}

	for _, opt := range opts {
		if err := opt(server); err != nil {
			return nil, err
		}
	}

	// A proxy that neither authenticates its clients nor limits the networks
	// they may come from is an open relay, so fall back to the loopback.
	if len(cfg.AllowedNetworks) == 0 && server.auth.Load() == nil {
		cfg.AllowedNetworks = []string{DefaultAllowedNetwork}
	}

	if err := server.resolveLocalAddr(cfg.BindIP); err != nil {
		return nil, err
	}

	// WithHealth wins over the configuration, so that a program supplying a
	// tracker of its own does not have to set the flag as well.
	if server.health == nil && cfg.healthEnabled() {
		server.health = NewHealth(cfg.HealthFailureLimit)
	}

	conf, err := cfg.compile(server.directDialer())
	if err != nil {
		return nil, err
	}
	server.conf.Store(conf)

	server.proxy = server.newGoproxy()

	return server, nil
}

// config is the configuration in force. Every handler reads it per request, so
// that a reload applies without re-registering anything.
func (s *Server) config() *compiledConfig {
	return s.conf.Load()
}

// Config returns a copy of the configuration in force.
func (s *Server) Config() Config {
	return s.config().Config.clone()
}

// Reload installs cfg for the requests that follow. The settings that are
// consumed while the proxy is being built — Listen and BindIP — keep their
// startup values, and a change to them is reported through the logger.
//
// The configuration in force is left untouched when cfg can't be used.
func (s *Server) Reload(cfg Config) error {
	if len(cfg.AllowedNetworks) == 0 && s.auth.Load() == nil {
		cfg.AllowedNetworks = []string{DefaultAllowedNetwork}
	}

	conf, err := cfg.compile(s.directDialer())
	if err != nil {
		return err
	}

	s.warnAboutStartupOnlySettings(conf)
	s.conf.Store(conf)

	return nil
}

// warnAboutStartupOnlySettings reports the settings a reload cannot apply.
func (s *Server) warnAboutStartupOnlySettings(conf *compiledConfig) {
	current := s.config()

	settings := []struct {
		name     string
		old, new string
	}{
		{"Listen", current.Listen, conf.Listen},
		{"BindIP", current.BindIP, conf.BindIP},
	}

	for _, setting := range settings {
		if setting.old != setting.new {
			s.log.Printf("WARN: %v only applies at startup, still using %q instead of %q\n",
				setting.name, setting.old, setting.new)
		}
	}
}

// SetCredentials installs the credentials the clients are authenticated
// against. A nil argument turns authentication off.
//
// The digest nonces already issued stay valid, so replacing the credentials
// does not interrupt the exchanges in flight.
func (s *Server) SetCredentials(creds Credentials) error {
	auth, err := newAuthenticator(creds)
	if err != nil {
		return err
	}

	s.auth.Store(auth)

	return nil
}

// Handler returns the proxy as an http.Handler, for a caller that would rather
// run a server of its own.
func (s *Server) Handler() http.Handler {
	return s.proxy
}

// Serve accepts connections on l until it is closed or Shutdown is called.
//
// When WithListenerTLS is in force, l is wrapped so that clients speak the
// proxy protocol inside a TLS connection. Do not pass an already wrapped
// listener as well.
func (s *Server) Serve(l net.Listener) error {
	if s.listenerTLS != nil {
		l = tls.NewListener(l, s.listenerTLS)
	}

	server, err := s.startServing(l)
	if err != nil {
		return err
	}

	s.log.Printf("starting proxy on %v (tls: %v)\n", l.Addr(), s.listenerTLS != nil)

	return server.Serve(l)
}

// ListenAndServe listens on Config.Listen and serves until Shutdown is called.
func (s *Server) ListenAndServe() error {
	addr := s.config().Listen

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("couldn't listen on %v: %w", addr, err)
	}

	return s.Serve(listener)
}

// ErrServerRunning is returned when a server that is already serving is asked
// to serve again.
var ErrServerRunning = errors.New("microproxy: the server is already serving")

func (s *Server) startServing(l net.Listener) (*http.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer != nil {
		return nil, ErrServerRunning
	}

	s.httpServer = &http.Server{
		Handler:           s.proxy,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	s.listener = l

	return s.httpServer, nil
}

// Addr is the address the proxy is listening on, or nil when it is not serving.
// It is how a caller that listened on port 0 learns the port it got.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener == nil {
		return nil
	}

	return s.listener.Addr()
}

// Shutdown stops both frontends, waiting for the requests and the SOCKS
// connections in flight to finish or for ctx to be done.
//
// The connections a CONNECT request tunnelled are hijacked from the http server
// and are not waited for; closing them is up to whatever holds them.
func (s *Server) Shutdown(ctx context.Context) error {
	server, socks := s.stopListening()

	var err error

	if socks != nil {
		err = socks.Close()
	}

	if server != nil {
		if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
			err = shutdownErr
		}
	}

	if waitErr := s.waitForSOCKS(ctx); waitErr != nil {
		err = waitErr
	}

	return err
}

// Close stops the proxy at once, dropping the requests and the SOCKS
// connections in flight.
func (s *Server) Close() error {
	server, socks := s.stopListening()

	var err error

	if socks != nil {
		err = socks.Close()
	}

	if server != nil {
		if closeErr := server.Close(); closeErr != nil {
			err = closeErr
		}
	}

	for _, conn := range s.takeSOCKSConns() {
		_ = conn.Close()
	}

	return err
}

// stopListening takes both listeners out of service, so that neither frontend
// accepts anything new while the connections already open are being finished.
func (s *Server) stopListening() (*http.Server, net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()

	server := s.httpServer
	s.httpServer = nil
	s.listener = nil

	socks := s.socksListener
	s.socksListener = nil
	s.socksDone = true

	return server, socks
}

func (s *Server) takeSOCKSConns() []net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()

	conns := make([]net.Conn, 0, len(s.socksConns))
	for conn := range s.socksConns {
		conns = append(conns, conn)
	}

	return conns
}

// waitForSOCKS waits for the SOCKS connections being served, dropping them when
// ctx runs out.
func (s *Server) waitForSOCKS(ctx context.Context) error {
	done := make(chan struct{})

	go func() {
		s.socksActive.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		for _, conn := range s.takeSOCKSConns() {
			_ = conn.Close()
		}

		return ctx.Err()
	}
}

func (s *Server) newGoproxy() *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()

	proxy.Logger = s.log
	proxy.Verbose = s.verbose
	proxy.Tr.TLSClientConfig = s.tlsConfig
	proxy.Tr.Proxy = s.transportProxy
	proxy.Tr.DialContext = s.transportDial
	proxy.ConnectDialWithReq = s.connectDial

	s.registerHandlers(proxy)

	return proxy
}

// registerHandlers installs the request pipeline. goproxy runs the handlers in
// registration order and stops at the first one that answers, so this is the
// order a request is processed in: refuse the clients and the ports that are
// not allowed, authenticate, and only then route and rewrite the requests that
// made it through.
func (s *Server) registerHandlers(proxy *goproxy.ProxyHttpServer) {
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		s.logResponse(resp, ctx)
		s.recordHealth(resp)

		return resp
	})

	proxy.OnRequest(goproxy.Not(goproxy.ReqConditionFunc(s.connectPortAllowed))).
		HandleConnect(goproxy.AlwaysReject)

	denied := goproxy.ReqConditionFunc(s.clientDenied)
	proxy.OnRequest(denied).HandleConnect(goproxy.AlwaysReject)
	proxy.OnRequest(denied).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return req, goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, "Access denied")
		})

	proxy.OnRequest().Do(goproxy.FuncReqHandler(s.authenticateRequest))
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(s.handleConnect))

	proxy.OnRequest().DoFunc(s.attachRoute)
	proxy.OnRequest().DoFunc(s.setForwardedForHeader)
	proxy.OnRequest().DoFunc(s.setViaHeader)
	proxy.OnRequest().DoFunc(s.addCustomHeaders)
}

func (s *Server) authenticateRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if resp := s.authenticate(req, ctx); resp != nil {
		return nil, resp
	}

	return req, nil
}

// handleConnect authenticates a CONNECT request and writes its access log
// entry: tunnelled traffic never reaches the response handlers, so this is the
// only place an HTTPS request can be logged.
func (s *Server) handleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	// the response is the 407 this proxy sends, not one it received, so there
	// is no body of anybody else's to close
	if resp := s.authenticate(ctx.Req, ctx); resp != nil { //nolint:bodyclose // see above
		ctx.Resp = resp

		return goproxy.RejectConnect, host
	}

	if ctx.Req == nil {
		ctx.Req = &http.Request{}
	}

	s.logConnect(ctx)

	return goproxy.OkConnect, host
}

// clientDenied reports whether the client's address is refused by the network
// ACLs of the configuration in force when the request arrives.
func (s *Server) clientDenied(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	conf := s.config()
	addr := clientIP(req, ctx)

	if addr == nil {
		// fail closed while a whitelist is in force
		return len(conf.allowedNetworks) > 0
	}

	if len(conf.allowedNetworks) > 0 && !networksContain(conf.allowedNetworks, addr) {
		return true
	}

	return networksContain(conf.disallowedNetworks, addr)
}

func clientIP(req *http.Request, ctx *goproxy.ProxyCtx) net.IP {
	if req == nil {
		return nil
	}

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ctx.Warnf("couldn't parse remote address %v: %v", req.RemoteAddr, err)

		return nil
	}

	return net.ParseIP(ip)
}

func networksContain(networks []*net.IPNet, addr net.IP) bool {
	for _, network := range networks {
		if network.Contains(addr) {
			return true
		}
	}

	return false
}

func (s *Server) connectPortAllowed(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	conf := s.config()
	if len(conf.allowedConnectPorts) == 0 {
		return true
	}

	if req == nil {
		return false
	}

	_, allowed := conf.allowedConnectPorts[connectPort(req)]

	return allowed
}

// connectPort is the port a CONNECT request wants to reach. goproxy tunnels a
// host given without a port to the https one, so assume the same here.
func connectPort(req *http.Request) int {
	host := req.Host
	if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}

	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return DefaultAllowedConnectPort
	}

	number, err := strconv.Atoi(port)
	if err != nil {
		return -1
	}

	return number
}

func (s *Server) setForwardedForHeader(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	action := s.config().ForwardedForHeader
	if action == "off" {
		return req, nil
	}

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ctx.Warnf("couldn't parse remote address %v: %v", req.RemoteAddr, err)

		return req, nil
	}

	switch action {
	case "on":
		if header := req.Header.Get(proxyForwardedForHeader); header != "" {
			ip = header + ", " + ip
		}
		req.Header.Set(proxyForwardedForHeader, ip)
	case "delete":
		req.Header.Del(proxyForwardedForHeader)
	case "truncate":
		req.Header.Set(proxyForwardedForHeader, ip)
	}

	return req, nil
}

func (s *Server) setViaHeader(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	conf := s.config()

	switch conf.ViaHeader {
	case "on":
		via := fmt.Sprintf("1.1 %s", conf.ViaProxyName)
		if header := req.Header.Get(proxyViaHeader); header != "" {
			via = fmt.Sprintf("%s, %s", header, via)
		}
		// replace rather than append, otherwise the hops seen so far would
		// be sent twice: once on their own and once inside the new value
		req.Header.Set(proxyViaHeader, via)
	case "delete":
		req.Header.Del(proxyViaHeader)
	}

	return req, nil
}

func (s *Server) addCustomHeaders(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	for _, header := range s.config().AddHeaders {
		if len(header) != 2 {
			continue
		}

		name, value := header[0], header[1]
		if name != "" && value != "" && req.Header.Get(name) == "" {
			req.Header.Add(name, value)
		}
	}

	return req, nil
}

const (
	proxyForwardedForHeader = "X-Forwarded-For"
	proxyViaHeader          = "Via"
)

// routeContextKey is how the route resolved for a request reaches the transport
// hooks, which are given a request or a context but never both.
type routeContextKey struct{}

func withRoute(ctx context.Context, route Route) context.Context {
	return context.WithValue(ctx, routeContextKey{}, route)
}

func routeFrom(ctx context.Context) (Route, bool) {
	route, ok := ctx.Value(routeContextKey{}).(Route)

	return route, ok
}

// attachRoute resolves the upstream for a request once and records it on the
// request context, so that the transport's Proxy and DialContext hooks agree on
// it and neither has to resolve it again from an address that may well be an
// upstream proxy's rather than the target's.
func (s *Server) attachRoute(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	route, err := s.route(requestHost(req))
	if err != nil {
		ctx.Warnf("couldn't route %v: %v", req.URL, err)

		return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
			http.StatusBadGateway, "no route to host")
	}

	return req.WithContext(withRoute(req.Context(), route)), nil
}

func requestHost(req *http.Request) string {
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}

	return req.Host
}

// transportProxy tells the transport which upstream proxy to speak to, which is
// only ever an HTTP one: a request that goes through a SOCKS upstream is dialled
// by transportDial instead and reaches the origin server directly.
func (s *Server) transportProxy(req *http.Request) (*url.URL, error) {
	route, err := s.routeForRequest(req)
	if err != nil {
		return nil, err
	}

	return route.Proxy, nil
}

// transportDial opens the connections the transport makes. Without a route on
// the context the address is dialled as given, which is what happens when the
// transport is reaching an upstream proxy rather than the target.
func (s *Server) transportDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if route, ok := routeFrom(ctx); ok && route.Proxy == nil && route.Dialer != nil {
		return route.Dialer.DialContext(ctx, network, addr)
	}

	return s.dial(ctx, network, addr)
}

// connectDial opens the connection a CONNECT request is tunnelled through.
func (s *Server) connectDial(req *http.Request, network, addr string) (net.Conn, error) {
	route, err := s.routeForRequest(req)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if req != nil {
		ctx = req.Context()
	}

	if route.Direct() {
		s.log.Printf("dialing directly to %v\n", addr)
	}

	return s.dialRoute(ctx, route, network, addr)
}

// routeForRequest returns the route resolved for req, resolving it if the
// request never went through attachRoute, as a CONNECT request does not.
func (s *Server) routeForRequest(req *http.Request) (Route, error) {
	if req == nil {
		return Route{}, nil
	}

	if route, ok := routeFrom(req.Context()); ok {
		return route, nil
	}

	return s.route(requestHost(req))
}

// connectDialToProxy tunnels through an upstream HTTP proxy, re-encoding the
// credentials its url carries as Basic for that hop only.
func (s *Server) connectDialToProxy(proxyURL *url.URL, network, addr string) (net.Conn, error) {
	if proxyURL.User == nil || proxyURL.User.Username() == "" {
		return s.proxy.NewConnectDialToProxy(proxyURL.String())(network, addr)
	}

	credentials, err := url.QueryUnescape(proxyURL.User.String())
	if err != nil {
		return nil, fmt.Errorf("can't decode the credentials of upstream proxy %v: %w", proxyURL.Redacted(), err)
	}

	authorize := func(req *http.Request) {
		req.Header.Set(proxyAuthorizationHeader,
			"Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}

	return s.proxy.NewConnectDialToProxyWithHandler(proxyURL.String(), authorize)(network, addr)
}

// directDialer is how a SOCKS upstream is reached, and what a Router is given
// to build its own dialers on top of.
func (s *Server) directDialer() ContextDialer {
	return DialerFunc(s.dial)
}

// dial opens a connection the way this proxy is configured to: from BindIP, and
// with the read and write deadlines the configuration asks for.
func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := s.baseDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	conf := s.config()

	return newTimedConn(conn, conf.ReadTimeout, conf.WriteTimeout), nil
}

func (s *Server) baseDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.dialer != nil {
		return s.dialer.DialContext(ctx, network, addr)
	}

	dialer := &net.Dialer{
		LocalAddr: s.localAddr,
		KeepAlive: tcpKeepAliveInterval,
	}

	return dialer.DialContext(ctx, network, addr)
}

// resolveLocalAddr turns BindIP into the local address outgoing connections are
// made from.
func (s *Server) resolveLocalAddr(bindIP string) error {
	if bindIP == "" {
		return nil
	}

	ip := net.ParseIP(bindIP)
	if ip == nil {
		return fmt.Errorf("couldn't use %q as outgoing request address", bindIP)
	}

	s.localAddr = &net.TCPAddr{IP: ip}

	return nil
}
