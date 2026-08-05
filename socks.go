package microproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// The SOCKS5 protocol, RFC 1928, and its username/password authentication,
// RFC 1929.
const (
	socksVersion5   = 0x05
	userPassVersion = 0x01

	authNone         = 0x00
	authUserPass     = 0x02
	authNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	replySuccess              = 0x00
	replyGeneralFailure       = 0x01
	replyNotAllowed           = 0x02
	replyNetworkUnreachable   = 0x03
	replyHostUnreachable      = 0x04
	replyConnectionRefused    = 0x05
	replyCommandNotSupported  = 0x07
	replyAddrTypeNotSupported = 0x08

	userPassSuccess = 0x00
	userPassFailure = 0x01
)

// socksHandshakeTimeout bounds how long a client may take to get through the
// negotiation, so that an idle connection can't hold a goroutine forever.
const socksHandshakeTimeout = 30 * time.Second

// errSOCKSRefused is what a handler returns when it has already told the client
// why it was refused.
var errSOCKSRefused = errors.New("microproxy: the SOCKS request was refused")

// ServeSOCKS accepts SOCKS5 connections on l until it is closed or the server
// is shut down.
//
// The clients reaching it are subject to the same configuration as the ones
// speaking HTTP: the network ACLs, the CONNECT port restrictions, the
// credentials and the upstream routing all apply, and the connections are
// written to the same access log.
//
// Only the CONNECT command is implemented; BIND and UDP ASSOCIATE are refused.
func (s *Server) ServeSOCKS(l net.Listener) error {
	if err := s.startSOCKS(l); err != nil {
		return err
	}

	defer s.stopSOCKS()

	s.log.Printf("starting SOCKS proxy on %v\n", l.Addr())

	for {
		conn, err := l.Accept()
		if err != nil {
			if s.socksClosing() {
				return nil
			}

			return fmt.Errorf("couldn't accept a SOCKS connection: %w", err)
		}

		if !s.trackSOCKSConn(conn) {
			// the server stopped between the accept and here
			_ = conn.Close()

			return nil
		}

		go func() {
			defer s.untrackSOCKSConn(conn)
			defer conn.Close()

			s.serveSOCKSConn(conn)
		}()
	}
}

// ListenAndServeSOCKS listens on Config.SOCKSListen and serves SOCKS5 there.
func (s *Server) ListenAndServeSOCKS() error {
	addr := s.config().SOCKSListen
	if addr == "" {
		return errors.New("microproxy: SOCKSListen is not configured")
	}

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("couldn't listen on %v: %w", addr, err)
	}

	return s.ServeSOCKS(listener)
}

// SOCKSAddr is the address the SOCKS frontend is listening on, or nil when it
// is not serving.
func (s *Server) SOCKSAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.socksListener == nil {
		return nil
	}

	return s.socksListener.Addr()
}

func (s *Server) startSOCKS(l net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.socksListener != nil {
		return ErrServerRunning
	}

	s.socksListener = l
	s.socksDone = false

	return nil
}

func (s *Server) stopSOCKS() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.socksListener = nil
	s.socksDone = true
}

func (s *Server) socksClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.socksDone
}

// trackSOCKSConn remembers a connection about to be served, so that Close can
// drop it and Shutdown can wait for it. It reports false when the server has
// stopped in the meantime, in which case the connection must not be served.
func (s *Server) trackSOCKSConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.socksDone {
		return false
	}

	if s.socksConns == nil {
		s.socksConns = make(map[net.Conn]struct{})
	}

	s.socksConns[conn] = struct{}{}
	s.socksActive.Add(1)

	return true
}

func (s *Server) untrackSOCKSConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, tracked := s.socksConns[conn]; !tracked {
		return
	}

	delete(s.socksConns, conn)
	s.socksActive.Done()
}

func (s *Server) serveSOCKSConn(client net.Conn) {
	entry := &AccessEntry{
		Time:          time.Now(),
		RemoteAddr:    client.RemoteAddr().String(),
		Method:        "CONNECT",
		ContentLength: -1,
	}

	target, err := s.socksHandshake(client, entry)
	if err != nil {
		if !errors.Is(err, errSOCKSRefused) {
			s.log.Printf("SOCKS handshake with %v failed: %v\n", client.RemoteAddr(), err)
		}

		s.logSOCKS(entry, err)

		return
	}

	entry.URL = target

	upstream, err := s.socksDial(client, target)
	if err != nil {
		s.logSOCKS(entry, err)

		return
	}
	defer upstream.Close()

	entry.StatusCode = 200
	s.logSOCKS(entry, nil)

	// The negotiation is over; from here the deadlines are the ones the
	// configuration asks for, applied by the wrapper around each side.
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}

	conf := s.config()
	relay(newTimedConn(client, conf.ReadTimeout, conf.WriteTimeout), upstream)
}

// socksHandshake negotiates the authentication and reads the request, leaving
// the client waiting for the reply that socksDial sends.
func (s *Server) socksHandshake(client net.Conn, entry *AccessEntry) (string, error) {
	if err := client.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return "", err
	}

	if s.socksClientDenied(client.RemoteAddr()) {
		// The client has not authenticated yet, so it is refused as soon as
		// the protocol allows a reply to be sent at all.
		_ = writeSOCKSMethod(client, authNoAcceptable)

		return "", fmt.Errorf("%w: %v is not an allowed client", errSOCKSRefused, client.RemoteAddr())
	}

	user, err := s.socksAuthenticate(client)
	if err != nil {
		return "", err
	}
	entry.User = user

	target, err := s.socksReadRequest(client)
	if err != nil {
		return "", err
	}

	return target, nil
}

func (s *Server) socksClientDenied(addr net.Addr) bool {
	conf := s.config()

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return len(conf.allowedNetworks) > 0
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return len(conf.allowedNetworks) > 0
	}

	if len(conf.allowedNetworks) > 0 && !networksContain(conf.allowedNetworks, ip) {
		return true
	}

	return networksContain(conf.disallowedNetworks, ip)
}

// socksAuthenticate performs the method negotiation and, when credentials are
// configured, the username/password exchange of RFC 1929.
func (s *Server) socksAuthenticate(client net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", fmt.Errorf("couldn't read the SOCKS greeting: %w", err)
	}

	if header[0] != socksVersion5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return "", fmt.Errorf("couldn't read the SOCKS authentication methods: %w", err)
	}

	auth := s.auth.Load()
	if auth == nil {
		if !offers(methods, authNone) {
			_ = writeSOCKSMethod(client, authNoAcceptable)

			return "", fmt.Errorf("%w: the client insists on authenticating", errSOCKSRefused)
		}

		return "", writeSOCKSMethod(client, authNone)
	}

	if !offers(methods, authUserPass) {
		_ = writeSOCKSMethod(client, authNoAcceptable)

		return "", fmt.Errorf("%w: the client offers no username/password authentication", errSOCKSRefused)
	}

	if err := writeSOCKSMethod(client, authUserPass); err != nil {
		return "", err
	}

	return s.socksVerifyUserPass(client, auth)
}

func (s *Server) socksVerifyUserPass(client net.Conn, auth *authenticator) (string, error) {
	version := make([]byte, 1)
	if _, err := io.ReadFull(client, version); err != nil {
		return "", fmt.Errorf("couldn't read the SOCKS authentication request: %w", err)
	}

	if version[0] != userPassVersion {
		return "", fmt.Errorf("unsupported SOCKS authentication version %d", version[0])
	}

	user, err := readSOCKSString(client)
	if err != nil {
		return "", fmt.Errorf("couldn't read the user name: %w", err)
	}

	password, err := readSOCKSString(client)
	if err != nil {
		return "", fmt.Errorf("couldn't read the password: %w", err)
	}

	if !auth.verifyPassword(user, password) {
		_, _ = client.Write([]byte{userPassVersion, userPassFailure})

		return "", fmt.Errorf("%w: failed SOCKS auth. attempt: user=%v, addr=%v",
			errSOCKSRefused, user, client.RemoteAddr())
	}

	if _, err := client.Write([]byte{userPassVersion, userPassSuccess}); err != nil {
		return "", err
	}

	return user, nil
}

// socksReadRequest reads the request and returns the "host:port" it asks for.
func (s *Server) socksReadRequest(client net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", fmt.Errorf("couldn't read the SOCKS request: %w", err)
	}

	if header[0] != socksVersion5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	if header[1] != cmdConnect {
		_ = writeSOCKSReply(client, replyCommandNotSupported, nil)

		return "", fmt.Errorf("%w: unsupported SOCKS command %d", errSOCKSRefused, header[1])
	}

	host, err := readSOCKSAddress(client, header[3])
	if err != nil {
		if errors.Is(err, errSOCKSRefused) {
			_ = writeSOCKSReply(client, replyAddrTypeNotSupported, nil)
		}

		return "", err
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(client, port); err != nil {
		return "", fmt.Errorf("couldn't read the target port: %w", err)
	}

	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}

// socksDial opens the connection to the target and tells the client how it
// went, so that a refusal reaches it with the reason the protocol has for it.
func (s *Server) socksDial(client net.Conn, target string) (net.Conn, error) {
	if !s.socksPortAllowed(target) {
		_ = writeSOCKSReply(client, replyNotAllowed, nil)

		return nil, fmt.Errorf("%w: %v is not an allowed port", errSOCKSRefused, target)
	}

	route, err := s.route(target)
	if err != nil {
		_ = writeSOCKSReply(client, replyGeneralFailure, nil)

		return nil, fmt.Errorf("couldn't route %v: %w", target, err)
	}

	upstream, err := s.dialRoute(context.Background(), route, "tcp", target)
	if err != nil {
		_ = writeSOCKSReply(client, replyForDialError(err), nil)

		return nil, fmt.Errorf("couldn't connect to %v: %w", target, err)
	}

	if err := writeSOCKSReply(client, replySuccess, upstream.LocalAddr()); err != nil {
		upstream.Close()

		return nil, err
	}

	return upstream, nil
}

func (s *Server) socksPortAllowed(target string) bool {
	conf := s.config()
	if len(conf.allowedConnectPorts) == 0 {
		return true
	}

	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}

	number, err := strconv.Atoi(port)
	if err != nil {
		return false
	}

	_, allowed := conf.allowedConnectPorts[number]

	return allowed
}

func (s *Server) logSOCKS(entry *AccessEntry, err error) {
	if s.access == nil {
		return
	}

	entry.Err = err
	s.access.LogAccess(entry)
}

// dialRoute opens a connection to addr the way route says to. It is what the
// SOCKS frontend and the CONNECT handler have in common.
func (s *Server) dialRoute(ctx context.Context, route Route, network, addr string) (net.Conn, error) {
	switch {
	case route.Proxy != nil:
		return s.connectDialToProxy(route.Proxy, network, addr)
	case route.Dialer != nil:
		return route.Dialer.DialContext(ctx, network, addr)
	default:
		return s.dial(ctx, network, addr)
	}
}

func offers(methods []byte, method byte) bool {
	for _, offered := range methods {
		if offered == method {
			return true
		}
	}

	return false
}

func writeSOCKSMethod(client net.Conn, method byte) error {
	_, err := client.Write([]byte{socksVersion5, method})

	return err
}

// writeSOCKSReply answers a request. bound is the local address of the
// connection that was opened, which the protocol reports back and most clients
// ignore.
func writeSOCKSReply(client net.Conn, reply byte, bound net.Addr) error {
	response := []byte{socksVersion5, reply, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}

	if tcpAddr, ok := bound.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			response = append([]byte{socksVersion5, reply, 0x00, addrIPv4}, ip4...)
		} else {
			response = append([]byte{socksVersion5, reply, 0x00, addrIPv6}, tcpAddr.IP.To16()...)
		}

		response = binary.BigEndian.AppendUint16(response, uint16(tcpAddr.Port)) //nolint:gosec // a port always fits
	}

	_, err := client.Write(response)

	return err
}

func readSOCKSAddress(client net.Conn, addrType byte) (string, error) {
	switch addrType {
	case addrIPv4:
		return readIP(client, net.IPv4len)
	case addrIPv6:
		return readIP(client, net.IPv6len)
	case addrDomain:
		name, err := readSOCKSString(client)
		if err != nil {
			return "", fmt.Errorf("couldn't read the target host: %w", err)
		}

		return name, nil
	default:
		return "", fmt.Errorf("%w: unsupported SOCKS address type %d", errSOCKSRefused, addrType)
	}
}

func readIP(client net.Conn, length int) (string, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(client, buf); err != nil {
		return "", fmt.Errorf("couldn't read the target address: %w", err)
	}

	return net.IP(buf).String(), nil
}

// readSOCKSString reads a length-prefixed string, which is how the protocol
// writes user names, passwords and host names alike.
func readSOCKSString(client net.Conn) (string, error) {
	length := make([]byte, 1)
	if _, err := io.ReadFull(client, length); err != nil {
		return "", err
	}

	buf := make([]byte, length[0])
	if _, err := io.ReadFull(client, buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

func replyForDialError(err error) byte {
	var opErr *net.OpError

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return replyHostUnreachable
	case errors.As(err, &opErr) && opErr.Op == "dial":
		var syscallErr *net.DNSError
		if errors.As(err, &syscallErr) {
			return replyHostUnreachable
		}

		return replyConnectionRefused
	default:
		return replyNetworkUnreachable
	}
}

// closeWriter is implemented by the connections that can signal the end of what
// they are sending without dropping what they are still receiving.
type closeWriter interface {
	CloseWrite() error
}

// relay copies between the two sides until both are done, closing each
// direction as it ends so that neither side waits for a peer that has finished.
func relay(client, upstream net.Conn) {
	var wg sync.WaitGroup

	wg.Add(2)

	copyAndSignal := func(dst, src net.Conn) {
		defer wg.Done()

		_, _ = io.Copy(dst, src)

		if closer, ok := dst.(closeWriter); ok {
			_ = closer.CloseWrite()

			return
		}

		_ = dst.SetDeadline(time.Now())
	}

	go copyAndSignal(upstream, client)
	go copyAndSignal(client, upstream)

	wg.Wait()
}
