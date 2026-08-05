## About

`microproxy` is a lightweight non-caching forward proxy. It is both a Go
package you embed in your own program and a standalone executable.

It accepts HTTP, HTTPS (`CONNECT`) and SOCKS5 connections, and forwards them
directly, through an upstream HTTP proxy, or through an upstream SOCKS5 server —
which is how it is put in front of a VPN client.

## Main features

* Usable as a library: everything is configured from Go, nothing is read from a
  file unless your program chooses to read one.
* Two frontends over one policy: HTTP/HTTPS and SOCKS5 share the same ACLs,
  credentials, routing and access log.
* Basic and Digest access authentication, against a credential store you supply
  or an `htpasswd`/`htdigest` file.
* IP-based black and white access lists.
* Per-domain routing to upstream HTTP or SOCKS5 proxies.
* Ability to log all requests.
* Ability to tweak the `X-Forwarded-For` and `Via` headers.
* Ability to specify the IP address for outgoing connections.
* A health endpoint for a container or a load balancer to probe.
* Live reload of the configuration and the credentials.
* Single executable with no external dependencies.
* Reasonable memory usage.

## Using it as a library

```
$ go get github.com/dobrevit/microproxy
```

A proxy on an ephemeral port sending everything through a SOCKS5 server:

```go
srv, err := microproxy.New(microproxy.Config{
	ForwardProxyURL: "socks5://127.0.0.1:1080",
	AllowedNetworks: []string{"127.0.0.1/32"},
})
if err != nil {
	return err
}

listener, err := net.Listen("tcp", "127.0.0.1:0")
if err != nil {
	return err
}

go srv.Serve(listener)
defer srv.Shutdown(context.Background())

port := listener.Addr().(*net.TCPAddr).Port // where to point the clients
```

`Serve` takes a listener of your own, so binding port 0 and reading the port
back is how you avoid a fixed port. `ListenAndServe` uses `Config.Listen`
instead, and `Handler` returns the proxy as an `http.Handler` if you would
rather run the server yourself.

To accept SOCKS5 as well, serve a second listener — the same `Server`, the same
policy:

```go
socks, err := net.Listen("tcp", "127.0.0.1:0")
if err != nil {
	return err
}

go srv.ServeSOCKS(socks)
```

Instead of a url, the traffic can be handed to a dialer your program owns, which
is what to do when it holds the tunnel itself:

```go
srv, err := microproxy.New(cfg, microproxy.WithDialer(tunnel))
```

Users can be added and removed while the proxy is running:

```go
users := microproxy.NewBasicUsers("proxy")
users.Set("alice", "open sesame")

srv, err := microproxy.New(cfg, microproxy.WithCredentials(users))
...
users.Remove("alice")
```

`Server.Reload` replaces the configuration of a running proxy and
`Server.SetCredentials` its credentials. `Config.Listen`, `Config.SOCKSListen`
and `Config.BindIP` are the exception: they are consumed while the proxy is
being built and keep their startup values.

The options are `WithLogger`, `WithAccessLogger`, `WithCredentials`,
`WithRouter`, `WithDialer`, `WithTLSClientConfig`, `WithInsecureUpstream` and
`WithVerbose`. See the package documentation for the details.

## Using it as a command

```
$ go build -o microproxy ./cmd/microproxy
$ ./microproxy --config microproxy.toml
```

To enable debug mode, add the `-v` switch. To only test the configuration file
add `-t`, i.e. `$ ./microproxy --config microproxy.toml -t`.

### Configuration file options

The command uses [TOML](https://github.com/toml-lang/toml) for its
configuration file. Below is a list of supported options.

* `listen="ip:port"` -- ip address and port where to listen for incoming proxy requests. Default: `127.0.0.1:3128`
* `socks_listen="ip:port"` -- ip address and port where to listen for incoming SOCKS5 connections. Unset means no SOCKS frontend.
* `access_log="path"` -- path to a file where to write requested through proxy urls.
* `activity_log="path"` -- path to a file where to write debug and auxiliary information.
* `allowed_connect_ports=[port1, port2, ...]` -- list of allowed ports to CONNECT to. Applies to SOCKS5 requests as well. Default: `[443]`
* `auth_file="path"` -- path to a file with users' passwords. If you use the `digest` auth. scheme this file has to be in the format used by Apache's [htdigest](http://httpd.apache.org/docs/2.4/programs/htdigest.html) utility, for the `basic` scheme it has to be in the format used by Apache's [htpasswd](http://httpd.apache.org/docs/2.4/programs/htpasswd.html) utility with the -p option, i.e. created as `$ htpasswd -c -p auth.txt username`.
* `auth_type="type"` -- authentication scheme type. Available options are:
  * `"basic"` -- use the Basic authentication scheme.
  * `"digest"` -- use the Digest authentication scheme.
* `auth_realm="realmstring"` -- realm name which is to be reported to the client for the proxy authentication scheme.
* `forwarded_for_header="action"` -- specifies how to handle the `X-Forwarded-For` HTTP protocol header. Available options are:
  * `"on"` -- set the `X-Forwarded-For` header with the client's IP address, this is the default choice.
  * `"off"` -- do nothing, i.e. leave the header as is.
  * `"delete"` -- delete the `X-Forwarded-For` header, this turns on stealth mode.
  * `"truncate"` -- delete all old `X-Forwarded-For` headers and insert a new one with the client's IP address.
* `via_header="action"` -- specifies how to handle the `Via` HTTP protocol header. Available options are:
  * `"on"` -- set the `Via` header, this is the default choice.
  * `"off"` -- do nothing with the `Via` header.
  * `"delete"` -- delete the `Via` header.
* `via_proxy_name="name"` -- this value will be used as the host name in the `Via` header, by default the server's host name will be used.
* `allowed_networks=["net1", ...]` -- list of whitelisted networks in CIDR format. A bare IP address is a single host.
* `disallowed_networks=["net1", ...]` -- list of blacklisted networks in CIDR format.
* `bind_ip="ip"` -- specify which IP will be used for outgoing connections.
* `add_headers=[["header1", "value1"], ["header2", "value2"]...]` -- adds the specified headers to outgoing HTTP requests, this option will not work for HTTPS connections.
* `read_timeout`/`write_timeout` -- how long a single read or write on a proxied connection may take, e.g. `"15m"`. A negative value disables the deadline. Default: 15 minutes.
* `enable_health_check="on"` -- track whether the proxy is serving requests successfully and expose the result at `/health`. Needs `http_listen`.
* `http_listen="ip:port"` -- ip address and port the `/health` endpoint is served on. This is not a proxy listener; nothing is proxied there.
* `health_failure_limit=N` -- how many consecutive failures make the proxy unhealthy. Default: 5.
* `forward_proxy_url="http://user:password@host:port"` -- specify the proxy to forward requests to. Uses the basic auth type for the forward proxy.
* `[proxies]` -- table of named upstream proxies, e.g. `name="http://user:password@host:port"`. Used together with `[rules]`.
* `[rules]` -- table mapping a domain to the name of the proxy from `[proxies]` that serves it, e.g. `"example.com"="name"`. A rule matches the domain itself and its subdomains, so `"example.com"` matches `example.com` and `www.example.com`, but not `notexample.com`. The special domain `"."` matches every host.

If neither `allowed_networks` nor authentication is configured, the proxy only
accepts connections from `127.0.0.1/32`, so that an unconfigured one is never an
open relay.

### Upstream proxies

An upstream proxy url may be `http://`, `https://`, `socks5://` or `socks5h://`.
The HTTP ones are reached with `CONNECT`; the SOCKS ones are dialled, and the
target host name is resolved by the SOCKS server rather than locally, so
`socks5` and `socks5h` behave the same way here.

Upstream proxy selection, from the highest to the lowest priority:

1. the most specific matching `[rules]` entry;
2. the `"."` rule, if there is one;
3. `forward_proxy_url`;
4. the `http_proxy`/`https_proxy`/`no_proxy` environment variables.

If none of them applies, the connection is made directly. Example:

```toml
forward_proxy_url="http://fallback:3128"

[proxies]
internal="http://user:password@internal-proxy:3128"
partner="http://partner-proxy:3128"
vpn="socks5://127.0.0.1:1080"

[rules]
"example.com"="internal"
"api.partner.net"="partner"
"internal.corp"="vpn"
```

### SOCKS5 support

The SOCKS5 frontend implements the `CONNECT` command of
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) and the username/password
authentication of [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). `BIND` and
`UDP ASSOCIATE` are refused.

When credentials are configured, SOCKS clients have to present them: a Basic
store verifies the password directly, and a Digest store verifies it by
computing the digest it would have produced. When no credentials are configured,
SOCKS clients are accepted without authentication and the network ACLs are the
only thing limiting them.

### Health

`enable_health_check="on"` makes the proxy count the responses it serves: a run
of consecutive failures marks it unhealthy and a single success clears the run.
`/health` on `http_listen` answers 200 while it is healthy and 503 once it is
not, which is what the container image's healthcheck probes.

A program embedding the package gets the same thing through the API, and can
read the state directly rather than over HTTP:

```go
srv, err := microproxy.New(cfg, microproxy.WithHealth(microproxy.NewHealth(5)))
...
if !srv.Health().Healthy() {
	// take this proxy out of rotation
}
```

`Health.Handler` returns an `http.Handler` to mount wherever suits.

### Signal handling

On `USR1` microproxy reopens the access and activity log files.

On `USR2` microproxy re-reads its configuration file and applies it to the
requests that follow. A file that can't be parsed or validated is reported in
the activity log and the running configuration is kept, so a typo never takes
the proxy down. `listen`, `socks_listen`, `bind_ip`, `access_log` and
`activity_log` are used while the proxy is being set up and keep their startup
values; a reload that changes them says so in the activity log. Digest nonces
already issued stay valid across a reload, so clients are not asked to
authenticate again.

On `INT` or `TERM` microproxy stops accepting new connections and gives the ones
in flight ten seconds to finish.

## Licensing

All source code included in this distribution is covered by the MIT License
found in the LICENSE file.
