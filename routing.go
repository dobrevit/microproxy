package microproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/proxy"
)

// ContextDialer establishes the connections the proxy makes on behalf of a
// client. It is what a program embedding this package implements to send the
// traffic somewhere of its own: a VPN tunnel, a SOCKS port, a test double.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialerFunc adapts a function to ContextDialer. It also satisfies the Dial
// method that golang.org/x/net/proxy expects, so that it can be handed to a
// SOCKS5 dialer as the way to reach the SOCKS server itself.
type DialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialContext implements ContextDialer.
func (f DialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// Dial implements the dialer that golang.org/x/net/proxy expects, with the
// background context.
func (f DialerFunc) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}

// Route is how the proxy reaches one target host.
//
// The zero Route is a direct connection. At most one field is set: Proxy for
// the upstreams that speak HTTP, Dialer for everything else.
type Route struct {
	// Proxy is an HTTP or HTTPS upstream proxy. Tunnelled traffic reaches it
	// with CONNECT and plain HTTP with an absolute-form request line, which is
	// why it can't be reduced to a Dialer.
	Proxy *url.URL

	// Dialer establishes the connection to the target itself. A SOCKS5
	// upstream is expressed this way, as is any custom transport.
	Dialer ContextDialer
}

// Direct reports whether the route connects to the target without an upstream.
func (r Route) Direct() bool {
	return r.Proxy == nil && r.Dialer == nil
}

// Router decides how a target host is reached. host is the "host:port" of the
// target, never of an upstream proxy.
//
// A Router has to be safe for concurrent use, and its answer has to depend on
// nothing but the host: connections are pooled per host, so a route that varies
// between two requests to the same target would not be honoured for the second.
type Router interface {
	Route(host string) (Route, error)
}

// RouterFunc adapts a function to Router.
type RouterFunc func(host string) (Route, error)

// Route implements Router.
func (f RouterFunc) Route(host string) (Route, error) { return f(host) }

// SupportedProxySchemes are the upstream proxy url schemes this package knows
// how to reach.
//
// http and https are spoken by the proxy itself; socks5 and socks5h are handed
// to a SOCKS5 dialer, which always resolves the target name at the SOCKS
// server, so the two behave identically here.
var SupportedProxySchemes = []string{"http", "https", "socks5", "socks5h"}

func isSOCKS(scheme string) bool {
	return scheme == "socks5" || scheme == "socks5h"
}

// newRoute turns an upstream proxy url into the route that reaches it. forward
// is how the SOCKS server itself is dialled; nil means directly.
func newRoute(proxyURL *url.URL, forward ContextDialer) (Route, error) {
	switch {
	case proxyURL == nil:
		return Route{}, nil
	case proxyURL.Scheme == "http", proxyURL.Scheme == "https":
		return Route{Proxy: proxyURL}, nil
	case isSOCKS(proxyURL.Scheme):
		dialer, err := newSOCKS5Dialer(proxyURL, forward)
		if err != nil {
			return Route{}, err
		}

		return Route{Dialer: dialer}, nil
	default:
		return Route{}, fmt.Errorf("unsupported upstream proxy scheme '%s', expected one of %v",
			proxyURL.Scheme, SupportedProxySchemes)
	}
}

func newSOCKS5Dialer(proxyURL *url.URL, forward ContextDialer) (ContextDialer, error) {
	var user, password string

	if proxyURL.User != nil {
		user = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}

	dialer, err := SOCKS5Dialer(proxyURL.Host, user, password, forward)
	if err != nil {
		return nil, fmt.Errorf("couldn't use '%s' as a SOCKS5 proxy: %w", proxyURL.Redacted(), err)
	}

	return dialer, nil
}

// SOCKS5Dialer reaches targets through the SOCKS5 server at addr, which is how
// a proxy is pointed at a VPN client or any other SOCKS port. user and password
// may be empty when the server wants no authentication.
//
// The target host name is resolved by the SOCKS server rather than locally, so
// the names a client asks for are looked up on the far side of the tunnel.
//
// forward is how the SOCKS server itself is reached; nil dials it directly.
func SOCKS5Dialer(addr, user, password string, forward ContextDialer) (ContextDialer, error) {
	var auth *proxy.Auth

	if user != "" || password != "" {
		auth = &proxy.Auth{User: user, Password: password}
	}

	dialer, err := proxy.SOCKS5("tcp", addr, auth, forwardDialer(forward))
	if err != nil {
		return nil, err
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("the SOCKS5 dialer for %v does not support contexts", addr)
	}

	return contextDialer, nil
}

// forwardDialer adapts our dialer to the one x/net/proxy dials the SOCKS server
// with, so that reaching it still honours bind_ip and the connection timeouts.
func forwardDialer(forward ContextDialer) proxy.Dialer {
	if forward == nil {
		return proxy.Direct
	}

	return DialerFunc(forward.DialContext)
}

// routeCache memoizes the routes built for the upstream proxies that are not
// known until a request arrives, which today means the ones coming from the
// environment. Building a SOCKS5 dialer per request would otherwise be work
// repeated for every connection.
type routeCache struct {
	mu     sync.Mutex
	routes map[string]Route
}

func (c *routeCache) get(proxyURL *url.URL, forward ContextDialer) (Route, error) {
	if proxyURL == nil {
		return Route{}, nil
	}

	// Only the routes that carry state are worth caching.
	if !isSOCKS(proxyURL.Scheme) {
		return newRoute(proxyURL, forward)
	}

	key := proxyURL.String()

	c.mu.Lock()
	defer c.mu.Unlock()

	if route, cached := c.routes[key]; cached {
		return route, nil
	}

	route, err := newRoute(proxyURL, forward)
	if err != nil {
		return Route{}, err
	}

	if c.routes == nil {
		c.routes = make(map[string]Route)
	}
	c.routes[key] = route

	return route, nil
}

// route returns how host is reached under the configuration in force. The most
// specific matching rule wins, then the generic proxy, then the environment.
func (s *Server) route(host string) (Route, error) {
	if s.router != nil {
		return s.router.Route(host)
	}

	conf := s.config()
	hostname := hostnameOf(host)

	// rules are ordered from the most to the least specific domain
	for i := range conf.proxyRules {
		if conf.proxyRules[i].matches(hostname) {
			return conf.proxyRules[i].route, nil
		}
	}

	if conf.hasGenericRoute {
		return conf.genericRoute, nil
	}

	return s.environmentRoute(host)
}

// environmentRoute consults HTTP_PROXY and friends. net/http reads them through
// a url, and NO_PROXY is matched against the host, so the lookup needs both.
func (s *Server) environmentRoute(host string) (Route, error) {
	target := &url.URL{Scheme: "https", Host: host}

	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: target})
	if err != nil {
		return Route{}, err
	}

	return s.envRoutes.get(proxyURL, s.directDialer())
}

// hostnameOf strips the port from a "host:port", leaving a bare host or an
// address that has none untouched.
func hostnameOf(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return hostname
	}

	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}
