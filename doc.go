// Package microproxy is an embeddable HTTP and HTTPS forward proxy.
//
// It offers Basic and Digest authentication, client network ACLs, CONNECT port
// restrictions, header rewriting, an access log, and per-domain routing to
// upstream HTTP or SOCKS5 proxies. Everything is configured from Go; nothing is
// read from a file unless the program chooses to read one.
//
// The simplest useful proxy listens on an ephemeral port and sends everything
// through a SOCKS5 server, which is what fronting a VPN client looks like:
//
//	srv, err := microproxy.New(microproxy.Config{
//		ForwardProxyURL: "socks5://127.0.0.1:1080",
//		AllowedNetworks: []string{"127.0.0.1/32"},
//	})
//	if err != nil {
//		return err
//	}
//
//	listener, err := net.Listen("tcp", "127.0.0.1:0")
//	if err != nil {
//		return err
//	}
//
//	go srv.Serve(listener)
//	defer srv.Shutdown(context.Background())
//
//	// the port the clients have to be pointed at
//	port := listener.Addr().(*net.TCPAddr).Port
//
// The same can be done with a dialer instead of a url, which is what a program
// that owns the tunnel rather than a SOCKS port in front of it wants:
//
//	srv, err := microproxy.New(cfg, microproxy.WithDialer(tunnel))
//
// Authentication is a credential store the program supplies, so users can be
// added and removed at runtime without writing an htpasswd file:
//
//	users := microproxy.NewBasicUsers("proxy")
//	users.Set("alice", "open sesame")
//
//	srv, err := microproxy.New(cfg, microproxy.WithCredentials(users))
//
// A Config can be replaced while the proxy is serving with Server.Reload, and
// the credentials with Server.SetCredentials. Config.Listen and Config.BindIP
// are the exception: they are consumed while the proxy is being built.
//
// The cmd/microproxy command is a standalone proxy built on this package, and
// is what keeps the TOML configuration file, the signal handling and the log
// files that microproxy has always had.
package microproxy
