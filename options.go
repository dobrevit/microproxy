package microproxy

import "crypto/tls"

// Option is a part of a proxy that a Config can't describe, because it is a
// piece of the embedding program rather than data: where the logs go, what the
// credentials are, how the connections are made.
type Option func(*Server) error

// WithLogger sends what the proxy reports to logger. The default discards it;
// NewFileLogger and NewSlogLogger are the ready-made ones.
func WithLogger(logger Logger) Option {
	return func(s *Server) error {
		if logger == nil {
			logger = DiscardLogger
		}
		s.log = logger

		return nil
	}
}

// WithAccessLogger records every request the proxy serves. The default records
// nothing.
func WithAccessLogger(access AccessLogger) Option {
	return func(s *Server) error {
		s.access = access

		return nil
	}
}

// WithCredentials authenticates the clients against creds. A BasicCredentials
// makes the proxy challenge with the Basic scheme and a DigestCredentials with
// Digest. The default is to not authenticate at all, which is also what limits
// an otherwise unconfigured proxy to the loopback.
//
// The credentials can be replaced afterwards with Server.SetCredentials.
func WithCredentials(creds Credentials) Option {
	return func(s *Server) error {
		return s.SetCredentials(creds)
	}
}

// WithRouter decides the upstream per target host, replacing the routing that
// Config.Proxies, Config.Rules and Config.ForwardProxyURL describe.
func WithRouter(router Router) Option {
	return func(s *Server) error {
		s.router = router

		return nil
	}
}

// WithDialer makes every connection the proxy opens on behalf of a client go
// through dialer, instead of through the network directly. This is how the
// traffic is handed to a tunnel the embedding program owns.
//
// It replaces the dialing, not the routing: a request that a rule sends to an
// upstream proxy still goes there, with dialer opening the connection to the
// proxy. Config.BindIP no longer applies, since the dialer decides where the
// connection comes from.
func WithDialer(dialer ContextDialer) Option {
	return func(s *Server) error {
		s.dialer = dialer

		return nil
	}
}

// WithListenerTLS makes the HTTP frontend accept TLS connections: clients
// connect to the proxy over TLS and speak the proxy protocol inside it, which
// is what a browser calls an "HTTPS proxy".
//
// This keeps the Proxy-Authorization credentials and the host names of CONNECT
// requests off the local network, which a plain proxy sends in the clear. It
// does not decrypt anything a client tunnels: what goes through CONNECT is
// still opaque to the proxy.
//
// The certificate is the proxy's own, for the name its clients reach it by. Use
// tls.Config.GetCertificate to serve one that can be replaced without a
// restart. A MinVersion of TLS 1.2 is applied when config does not set one, and
// config is copied, so later changes to it are not picked up.
//
// This is the server side. WithTLSClientConfig is the unrelated client side,
// used when this proxy talks to an https:// upstream.
//
// The SOCKS frontend is unaffected: SOCKS5 has no TLS convention and no client
// speaks one.
func WithListenerTLS(config *tls.Config) Option {
	return func(s *Server) error {
		if config == nil {
			s.listenerTLS = nil

			return nil
		}

		listenerTLS := config.Clone()
		if listenerTLS.MinVersion == 0 {
			listenerTLS.MinVersion = tls.VersionTLS12
		}

		s.listenerTLS = listenerTLS

		return nil
	}
}

// WithTLSClientConfig is the TLS configuration used when the proxy itself
// speaks TLS as a client, which is to an https:// upstream proxy. See
// WithListenerTLS for the server side.
func WithTLSClientConfig(config *tls.Config) Option {
	return func(s *Server) error {
		s.tlsConfig = config

		return nil
	}
}

// WithInsecureUpstream disables certificate verification towards an https://
// upstream proxy. It is the -i flag of the command, and is a bad idea anywhere
// else.
func WithInsecureUpstream(insecure bool) Option {
	return func(s *Server) error {
		if s.tlsConfig == nil {
			s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		s.tlsConfig.InsecureSkipVerify = insecure

		return nil
	}
}

// WithHealth tracks whether the proxy is answering requests successfully,
// overriding Config.HealthCheckEnabled. Passing nil turns tracking off.
//
// The state is readable through Server.Health, and Health.Handler serves it as
// an endpoint for a container or a load balancer to probe.
func WithHealth(health *Health) Option {
	return func(s *Server) error {
		s.health = health

		return nil
	}
}

// WithVerbose makes the proxy report every request it serves through its
// logger.
func WithVerbose(verbose bool) Option {
	return func(s *Server) error {
		s.verbose = verbose

		return nil
	}
}
