package microproxy

import (
	"bytes"
	"crypto/md5" //nolint:gosec // RFC 7616 defines Digest authentication in terms of MD5
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	proxyAuthorizationHeader = "Proxy-Authorization"
	proxyAuthenticateHeader  = "Proxy-Authenticate"
)

var unauthorizedMsg = []byte("407 Proxy Authentication Required")

// Credentials is what the two credential store interfaces have in common. A
// store is consulted concurrently, so its methods have to be safe for use from
// several goroutines.
type Credentials interface {
	// Realm is the protection space announced in the 407 challenge.
	Realm() string
}

// BasicCredentials verifies a user and password sent with the Basic scheme.
// The password reaches it in the clear, so the store is the right place to
// apply a constant-time comparison against whatever it keeps.
type BasicCredentials interface {
	Credentials

	VerifyBasic(user, password string) bool
}

// DigestCredentials supplies the HA1 digest, MD5(user:realm:password), that the
// Digest scheme is verified against. The password itself never travels, so a
// store can only ever hold or derive HA1.
//
// realm is the one the client echoed back, which a store is free to reject in
// favour of its own.
type DigestCredentials interface {
	Credentials

	HA1(user, realm string) (string, bool)
}

// authenticator is the authentication in force. It is immutable: changing
// credentials builds a new one and swaps it in.
type authenticator struct {
	basic  BasicCredentials
	digest DigestCredentials
	realm  string
}

// newAuthenticator returns the authenticator for creds, or nil when creds is
// nil, which is how authentication is turned off.
func newAuthenticator(creds Credentials) (*authenticator, error) {
	if creds == nil {
		return nil, nil
	}

	auth := &authenticator{realm: creds.Realm()}

	// A store that implements both is used for Digest: it is the stronger of
	// the two schemes and the one whose challenge a Basic-only client ignores.
	switch typed := creds.(type) {
	case DigestCredentials:
		auth.digest = typed
	case BasicCredentials:
		auth.basic = typed
	default:
		return nil, fmt.Errorf("credentials of type %T implement neither BasicCredentials nor DigestCredentials", creds)
	}

	return auth, nil
}

// verifyPassword checks a user and password that arrived in the clear, which is
// what SOCKS5 negotiates and what neither HTTP scheme uses.
//
// A digest store never holds the password, so the digest it would have produced
// is computed and compared instead.
func (a *authenticator) verifyPassword(user, password string) bool {
	switch {
	case a.basic != nil:
		return a.basic.VerifyBasic(user, password)
	case a.digest != nil:
		expected, known := a.digest.HA1(user, a.realm)
		if !known {
			return false
		}

		return subtle.ConstantTimeCompare(
			[]byte(expected), []byte(DigestHA1(user, a.realm, password))) == 1
	default:
		return true
	}
}

// basicAuthData and digestAuthData are the fields of a Proxy-Authorization
// header, as sent by the client.
type basicAuthData struct {
	user     string
	password string
}

type digestAuthData struct {
	user     string
	realm    string
	nonce    string
	method   string
	uri      string
	response string
	qop      string
	nc       string
	cnonce   string
}

// nonceInfo is the state kept for an issued digest nonce.
type nonceInfo struct {
	issued           time.Time
	lastUsed         time.Time
	lastNonceCounter uint64
}

const (
	// nonceInactiveInterval is how long an unused nonce stays valid.
	nonceInactiveInterval = 12 * time.Hour
	// nonceSweepInterval is how often the expired ones are collected.
	nonceSweepInterval = 30 * time.Minute
)

// nonceStore owns the nonces the proxy has issued. It belongs to the server
// rather than to the credentials, so that replacing the credentials does not
// invalidate the digest exchanges already in flight.
type nonceStore struct {
	mu        sync.Mutex
	nonces    map[string]*nonceInfo
	lastSweep time.Time

	// random is where nonces are drawn from. It is nil outside the tests,
	// which is crypto/rand.Reader; on Go 1.24 that one cannot fail, so the
	// error path is only reachable by substituting a source that does.
	random io.Reader
}

func newNonceStore() *nonceStore {
	return &nonceStore{
		nonces:    make(map[string]*nonceInfo),
		lastSweep: time.Now(),
	}
}

// issue returns a fresh nonce and, from time to time, drops the stale ones.
// Sweeping here rather than from a ticker keeps the store free of a goroutine
// that would have to be shut down with the server.
func (s *nonceStore) issue() (string, error) {
	source := s.random
	if source == nil {
		source = rand.Reader
	}

	buf := make([]byte, 16)
	if _, err := io.ReadFull(source, buf); err != nil {
		return "", fmt.Errorf("couldn't generate a nonce: %w", err)
	}

	nonce := hex.EncodeToString(buf)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastSweep) >= nonceSweepInterval {
		s.expireLocked(now)
		s.lastSweep = now
	}

	s.nonces[nonce] = &nonceInfo{issued: now, lastUsed: now}

	return nonce, nil
}

// verify checks that nonce was issued by this proxy and that its counter has
// moved on, and only then runs check, which compares the response digest. All
// of it happens under one lock so that two requests replaying the same counter
// cannot both be accepted.
func (s *nonceStore) verify(nonce string, nc uint64, check func() bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, known := s.nonces[nonce]
	if !known {
		return false
	}

	// The nonce counter has to strictly increase; anything else is a replay.
	if nc <= info.lastNonceCounter {
		return false
	}

	if !check() {
		return false
	}

	info.lastUsed = time.Now()
	info.lastNonceCounter = nc

	return true
}

func (s *nonceStore) expireLocked(now time.Time) {
	limit := now.Add(-nonceInactiveInterval)

	for nonce, info := range s.nonces {
		if info.lastUsed.Before(limit) {
			delete(s.nonces, nonce)
		}
	}
}

func basicUnauthorized(req *http.Request, realm string) *http.Response {
	return unauthorizedResponse(req, fmt.Sprintf("Basic realm=%q", realm))
}

func digestUnauthorized(req *http.Request, realm, nonce string) *http.Response {
	return unauthorizedResponse(req, fmt.Sprintf("Digest realm=%q, qop=auth, nonce=%q", realm, nonce))
}

func unauthorizedResponse(req *http.Request, challenge string) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusProxyAuthRequired,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{proxyAuthenticateHeader: []string{challenge}},
		Body:          io.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
		ContentLength: int64(len(unauthorizedMsg)),
	}
}

// getDigestAuthData parses a Digest Proxy-Authorization header. The header is
// removed from the request either way: it is meant for this hop only.
func getDigestAuthData(req *http.Request) *digestAuthData {
	authHeader := strings.SplitN(req.Header.Get(proxyAuthorizationHeader), " ", 2)
	req.Header.Del(proxyAuthorizationHeader)

	if len(authHeader) != 2 || authHeader[0] != "Digest" {
		return nil
	}

	m := parseDigestParams(authHeader[1])

	return &digestAuthData{
		user:     m["username"],
		realm:    m["realm"],
		nonce:    m["nonce"],
		uri:      m["uri"],
		response: m["response"],
		qop:      m["qop"],
		nc:       m["nc"],
		cnonce:   m["cnonce"],
		method:   req.Method,
	}
}

// parseDigestParams splits a comma separated list of key=value pairs, honouring
// the commas that appear inside a quoted value.
func parseDigestParams(header string) map[string]string {
	params := make(map[string]string, 8)

	var (
		start  int
		quoted bool
	)

	flush := func(end int) {
		token := strings.TrimSpace(header[start:end])
		if key, value, found := strings.Cut(token, "="); found {
			params[strings.TrimSpace(key)] = strings.Trim(value, `"`)
		}
	}

	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				flush(i)
				start = i + 1
			}
		}
	}

	flush(len(header))

	return params
}

func getBasicAuthData(req *http.Request) *basicAuthData {
	authHeader := strings.SplitN(req.Header.Get(proxyAuthorizationHeader), " ", 2)
	req.Header.Del(proxyAuthorizationHeader)

	if len(authHeader) != 2 || authHeader[0] != "Basic" {
		return nil
	}

	rawUserPassword, err := base64.StdEncoding.DecodeString(authHeader[1])
	if err != nil {
		return nil
	}

	user, password, found := strings.Cut(string(rawUserPassword), ":")
	if !found {
		return nil
	}

	return &basicAuthData{user: user, password: password}
}

// verifyDigest recomputes the response digest the client should have sent and
// compares it with the one it did send.
func verifyDigest(creds DigestCredentials, nonces *nonceStore, data *digestAuthData) bool {
	ha1, known := creds.HA1(data.user, data.realm)
	if !known {
		return false
	}

	nc, err := strconv.ParseUint(data.nc, 16, 64)
	if err != nil {
		return false
	}

	return nonces.verify(data.nonce, nc, func() bool {
		ha2 := md5hex(data.method + ":" + data.uri)
		expected := md5hex(strings.Join(
			[]string{ha1, data.nonce, data.nc, data.cnonce, data.qop, ha2}, ":"))

		return subtle.ConstantTimeCompare([]byte(expected), []byte(data.response)) == 1
	})
}

func md5hex(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s))) //nolint:gosec // the digest scheme is specified with MD5, this is not a security choice
}

// authenticate checks req against the authentication in force. It returns the
// 407 response to send back when authentication is required and fails, and nil
// when the request may proceed.
func (s *Server) authenticate(req *http.Request, ctx *goproxy.ProxyCtx) *http.Response {
	auth := s.auth.Load()
	if auth == nil {
		return nil
	}

	// Standing an empty request in for a missing one keeps every branch below
	// safe to dereference it: the header parsing reads it, and the responses
	// are built by goproxy.NewResponse, which copies its TransferEncoding
	// without checking. goproxy itself always passes one, but this is reached
	// from the CONNECT handler too, whose request is the caller's to provide.
	if req == nil {
		req = &http.Request{}
	}

	switch {
	case auth.digest != nil:
		return s.authenticateDigest(auth, req, ctx)
	case auth.basic != nil:
		return s.authenticateBasic(auth, req, ctx)
	default:
		return nil
	}
}

func (s *Server) authenticateBasic(auth *authenticator, req *http.Request, ctx *goproxy.ProxyCtx) *http.Response {
	data := getBasicAuthData(req)

	if data == nil || !auth.basic.VerifyBasic(data.user, data.password) {
		if data != nil {
			ctx.Warnf("failed basic auth. attempt: user=%v, addr=%v", data.user, remoteAddr(req))
		}

		return basicUnauthorized(req, auth.realm)
	}

	ctx.UserData = data.user

	return nil
}

func (s *Server) authenticateDigest(auth *authenticator, req *http.Request, ctx *goproxy.ProxyCtx) *http.Response {
	data := getDigestAuthData(req)

	if data == nil || !verifyDigest(auth.digest, s.nonces, data) {
		if data != nil {
			ctx.Warnf("failed digest auth. attempt: user=%v, realm=%v, addr=%v",
				data.user, data.realm, remoteAddr(req))
		}

		nonce, err := s.nonces.issue()
		if err != nil {
			ctx.Warnf("%v", err)

			return goproxy.NewResponse(req, goproxy.ContentTypeText,
				http.StatusInternalServerError, "internal proxy error")
		}

		return digestUnauthorized(req, auth.realm, nonce)
	}

	ctx.UserData = data.user

	return nil
}

func remoteAddr(req *http.Request) string {
	if req == nil || req.RemoteAddr == "" {
		return "-"
	}

	return req.RemoteAddr
}
