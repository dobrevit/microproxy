package microproxy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultListenAddress is used when Config.Listen is empty.
	DefaultListenAddress = "127.0.0.1:3128"
	// DefaultAllowedNetwork is the only network allowed when neither
	// Config.AllowedNetworks nor authentication is configured.
	DefaultAllowedNetwork = "127.0.0.1/32"
	// DefaultAllowedConnectPort is the only port CONNECT may reach when
	// Config.AllowedConnectPorts is empty.
	DefaultAllowedConnectPort = 443

	// DefaultReadTimeout bounds how long a single read on a proxied connection
	// may take.
	DefaultReadTimeout = 15 * time.Minute
	// DefaultWriteTimeout bounds how long a single write on a proxied
	// connection may take.
	DefaultWriteTimeout = 15 * time.Minute

	// GenericProxyRule is the Rules key standing for "any host". It is more
	// specific than ForwardProxyURL and less specific than any domain rule.
	GenericProxyRule = "."
)

// Config is the data-only description of a proxy. Every field can be set from
// Go; the toml tags exist so that a program that does keep a configuration file
// can decode one into this struct.
//
// Callers construct a Config, hand it to New, and are free to reuse or modify
// it afterwards: New takes its own copy of the slices and maps.
type Config struct {
	// Listen is the "host:port" the HTTP frontend binds to in ListenAndServe.
	// Serve ignores it and takes the listener from the caller. Applied at
	// startup only.
	Listen string `toml:"listen"`

	// SOCKSListen is the "host:port" the SOCKS5 frontend binds to in
	// ListenAndServeSOCKS. Empty means no SOCKS frontend unless ServeSOCKS is
	// called with a listener of the caller's own. Applied at startup only.
	SOCKSListen string `toml:"socks_listen"`

	// BindIP is the local address outgoing connections are made from. Applied
	// at startup only.
	BindIP string `toml:"bind_ip"`

	// AllowedNetworks, when non-empty, is the whitelist of client networks;
	// every other client is refused. Entries are CIDR blocks or bare IP
	// addresses. When it is empty and no credentials are configured, New
	// installs DefaultAllowedNetwork.
	AllowedNetworks []string `toml:"allowed_networks"`

	// DisallowedNetworks is the blacklist of client networks, applied after
	// AllowedNetworks.
	DisallowedNetworks []string `toml:"disallowed_networks"`

	// AllowedConnectPorts limits the ports CONNECT may reach. Empty means
	// DefaultAllowedConnectPort only.
	AllowedConnectPorts []int `toml:"allowed_connect_ports"`

	// ForwardedForHeader is what to do with X-Forwarded-For: "on", "off",
	// "delete" or "truncate". Empty means "on".
	ForwardedForHeader string `toml:"forwarded_for_header"`

	// ViaHeader is what to do with Via: "on", "off" or "delete". Empty means
	// "on".
	ViaHeader string `toml:"via_header"`

	// ViaProxyName is the name this proxy announces in Via. Empty means the
	// host name.
	ViaProxyName string `toml:"via_proxy_name"`

	// AddHeaders are [name, value] pairs added to a request that does not
	// already carry the header.
	AddHeaders [][]string `toml:"add_headers"`

	// Proxies maps an alias to an upstream proxy url and Rules maps a domain
	// to one of those aliases. The longest matching domain wins. See
	// GenericProxyRule and ForwardProxyURL for the fallbacks.
	Proxies map[string]string `toml:"proxies"`
	Rules   map[string]string `toml:"rules"`

	// ForwardProxyURL is the upstream proxy for the hosts no rule matches.
	// Empty falls back to the environment (HTTP_PROXY and friends).
	ForwardProxyURL string `toml:"forward_proxy_url"`

	// ReadTimeout and WriteTimeout bound a single read or write on a proxied
	// connection. Zero means the Default values; a negative value disables
	// the deadline.
	ReadTimeout  time.Duration `toml:"read_timeout"`
	WriteTimeout time.Duration `toml:"write_timeout"`

	// HealthCheckEnabled turns health tracking on when it is "on". The state
	// is then readable through Server.Health, which also serves it over HTTP.
	// Applied at startup only.
	HealthCheckEnabled string `toml:"enable_health_check"`

	// HealthFailureLimit is how many consecutive failures make the proxy
	// unhealthy. Zero means DefaultHealthFailureLimit.
	HealthFailureLimit int `toml:"health_failure_limit"`
}

// healthEnabled reports whether the configuration asks for health tracking.
func (c Config) healthEnabled() bool {
	return c.HealthCheckEnabled == "on"
}

// proxyRule routes a domain and its subdomains to an upstream proxy.
type proxyRule struct {
	domain string
	route  Route
}

// matches reports whether host is the rule's domain or a subdomain of it. A bare
// suffix test would also match hosts like "notexample.com" for "example.com".
func (r *proxyRule) matches(host string) bool {
	return host == r.domain || strings.HasSuffix(host, "."+r.domain)
}

// compiledConfig is a Config with everything a request needs precomputed, so
// that serving one needs no parsing, sorting or allocation.
type compiledConfig struct {
	Config

	allowedNetworks     []*net.IPNet
	disallowedNetworks  []*net.IPNet
	allowedConnectPorts map[int]struct{}
	proxyRules          []proxyRule

	genericRoute    Route
	hasGenericRoute bool
}

// Validate reports whether the configuration can be used, without building a
// server from it. It is what a "test the configuration and exit" flag wants.
func (c Config) Validate() error {
	_, err := c.compile(nil)

	return err
}

// compile applies the defaults and precomputes the derived state, including the
// dialers the upstream proxies are reached through. forward is how a SOCKS
// server is dialled; nil means directly.
//
// The receiver is a copy, so neither the caller's Config nor the slices and
// maps it points at are modified.
func (c Config) compile(forward ContextDialer) (*compiledConfig, error) {
	conf := &compiledConfig{Config: c.clone()}

	if conf.Listen == "" {
		conf.Listen = DefaultListenAddress
	}

	if len(conf.AllowedConnectPorts) == 0 {
		conf.AllowedConnectPorts = []int{DefaultAllowedConnectPort}
	}

	if conf.ForwardedForHeader == "" {
		conf.ForwardedForHeader = "on"
	}

	if conf.ViaHeader == "" {
		conf.ViaHeader = "on"
	}

	if conf.ReadTimeout == 0 {
		conf.ReadTimeout = DefaultReadTimeout
	}

	if conf.WriteTimeout == 0 {
		conf.WriteTimeout = DefaultWriteTimeout
	}

	var err error

	if conf.allowedNetworks, err = parseNetworks(conf.AllowedNetworks); err != nil {
		return nil, err
	}

	if conf.disallowedNetworks, err = parseNetworks(conf.DisallowedNetworks); err != nil {
		return nil, err
	}

	conf.allowedConnectPorts = make(map[int]struct{}, len(conf.AllowedConnectPorts))
	for _, port := range conf.AllowedConnectPorts {
		conf.allowedConnectPorts[port] = struct{}{}
	}

	if err := validateIP(conf.BindIP); err != nil {
		return nil, err
	}

	if err := validateForwardedForHeaderAction(conf.ForwardedForHeader); err != nil {
		return nil, err
	}

	if err := validateViaHeaderAction(conf.ViaHeader); err != nil {
		return nil, err
	}

	if err := validateChoice("health check setting", conf.HealthCheckEnabled, "", "on", "off"); err != nil {
		return nil, err
	}

	if err := conf.resolveViaProxyName(); err != nil {
		return nil, err
	}

	if err := conf.compileProxyRules(forward); err != nil {
		return nil, err
	}

	return conf, nil
}

// clone copies the reference types so that a Config the caller keeps a handle
// on can't be changed underneath a running server.
func (c Config) clone() Config {
	clone := c

	clone.AllowedNetworks = append([]string(nil), c.AllowedNetworks...)
	clone.DisallowedNetworks = append([]string(nil), c.DisallowedNetworks...)
	clone.AllowedConnectPorts = append([]int(nil), c.AllowedConnectPorts...)

	if c.AddHeaders != nil {
		clone.AddHeaders = make([][]string, 0, len(c.AddHeaders))
		for _, header := range c.AddHeaders {
			clone.AddHeaders = append(clone.AddHeaders, append([]string(nil), header...))
		}
	}

	clone.Proxies = cloneStringMap(c.Proxies)
	clone.Rules = cloneStringMap(c.Rules)

	return clone
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}

	clone := make(map[string]string, len(m))
	for k, v := range m {
		clone[k] = v
	}

	return clone
}

// parseNetworks accepts CIDR blocks and bare IP addresses, which are treated as
// single host networks.
func parseNetworks(networks []string) ([]*net.IPNet, error) {
	if len(networks) == 0 {
		return nil, nil
	}

	parsed := make([]*net.IPNet, 0, len(networks))

	for _, network := range networks {
		cidr, err := parseNetwork(network)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse network %s: %w", network, err)
		}
		parsed = append(parsed, cidr)
	}

	return parsed, nil
}

func parseNetwork(network string) (*net.IPNet, error) {
	if _, cidr, err := net.ParseCIDR(network); err == nil {
		return cidr, nil
	}

	ip := net.ParseIP(network)
	if ip == nil {
		return nil, fmt.Errorf("invalid network address: %s", network)
	}

	bits := 128
	if ip.To4() != nil {
		bits = 32
	}

	_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", network, bits))
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %s", network)
	}

	return cidr, nil
}

func validateIP(addr string) error {
	if addr != "" && net.ParseIP(addr) == nil {
		return fmt.Errorf("incorrect IP address %s", addr)
	}

	return nil
}

func validateChoice(what, value string, valid ...string) error {
	for _, v := range valid {
		if value == v {
			return nil
		}
	}

	return fmt.Errorf("incorrect %s '%s'", what, value)
}

func validateForwardedForHeaderAction(action string) error {
	return validateChoice("'Forwarded-For' header action", action, "on", "off", "delete", "truncate")
}

func validateViaHeaderAction(action string) error {
	return validateChoice("'Via' header action", action, "on", "off", "delete")
}

func (c *compiledConfig) resolveViaProxyName() error {
	if c.ViaProxyName != "" || c.ViaHeader != "on" {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("os.Hostname() failed: %w", err)
	}

	c.ViaProxyName = hostname

	return nil
}

// compileProxyRules resolves the domain -> alias -> url indirection once per
// load, builds the dialer each upstream is reached through, and orders the
// rules so that the most specific domain matches first.
func (c *compiledConfig) compileProxyRules(forward ContextDialer) error {
	for domain, alias := range c.Rules {
		rawURL, exists := c.Proxies[alias]
		if !exists {
			return fmt.Errorf("rule '%s' refers to unknown proxy alias '%s'", domain, alias)
		}

		route, err := parseRoute(rawURL, forward)
		if err != nil {
			return fmt.Errorf("proxy '%s': %w", alias, err)
		}

		if domain == GenericProxyRule {
			c.genericRoute, c.hasGenericRoute = route, true

			continue
		}

		c.proxyRules = append(c.proxyRules, proxyRule{
			domain: strings.TrimPrefix(domain, "."),
			route:  route,
		})
	}

	sort.Slice(c.proxyRules, func(i, j int) bool {
		return len(c.proxyRules[i].domain) > len(c.proxyRules[j].domain)
	})

	// ForwardProxyURL serves the hosts no rule matches, but an explicit "."
	// rule is more specific and wins over it.
	if !c.hasGenericRoute && c.ForwardProxyURL != "" {
		route, err := parseRoute(c.ForwardProxyURL, forward)
		if err != nil {
			return fmt.Errorf("forward_proxy_url: %w", err)
		}
		c.genericRoute, c.hasGenericRoute = route, true
	}

	return nil
}

// parseRoute turns a configured upstream proxy url into the route that reaches
// it, reporting the urls that can't be used while the configuration can still
// be corrected rather than on the first request that needs them.
func parseRoute(rawURL string, forward ContextDialer) (Route, error) {
	proxyURL, err := ParseProxyURL(rawURL)
	if err != nil {
		return Route{}, err
	}

	return newRoute(proxyURL, forward)
}

// ParseProxyURL parses an upstream proxy url, rejecting the ones that carry no
// host to connect to or a scheme this package can't reach.
func ParseProxyURL(rawURL string) (*url.URL, error) {
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse url '%s': %w", rawURL, err)
	}

	if proxyURL.Host == "" {
		return nil, fmt.Errorf("url '%s' has no host, it has to look like 'http://host:port'", rawURL)
	}

	if err := validateChoice("upstream proxy scheme", proxyURL.Scheme, SupportedProxySchemes...); err != nil {
		return nil, fmt.Errorf("url '%s': %w", rawURL, err)
	}

	return proxyURL, nil
}
