package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
)

type BasicAuthFunc func(authData *BasicAuthData) *BasicAuthResponse
type DigestAuthFunc func(authData *DigestAuthData, op int) *DigestAuthResponse

var unauthorizedMsg = []byte("407 Proxy Authentication Required")

const (
	proxyAuthorizatonHeader = "Proxy-Authorization"
	proxyAuthenticateHeader = "Proxy-Authenticate"
)

func basicUnauthorized(req *http.Request, realm string) *http.Response {
	header := fmt.Sprintf("Basic realm=%s", realm)

	return &http.Response{
		StatusCode:    407,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{proxyAuthenticateHeader: []string{header}},
		Body:          ioutil.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
		ContentLength: int64(len(unauthorizedMsg)),
	}
}

func digestUnauthorized(req *http.Request, realm string, authFunc DigestAuthFunc) *http.Response {
	authResult := authFunc(nil, getNonce)
	nonce := authResult.data
	header := fmt.Sprintf("Digest realm=\"%s\", qop=auth, nonce=\"%s\"", realm, nonce)

	return &http.Response{
		StatusCode:    407,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{proxyAuthenticateHeader: []string{header}},
		Body:          ioutil.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
		ContentLength: int64(len(unauthorizedMsg)),
	}
}

func getDigestAuthData(req *http.Request) *DigestAuthData {
	authHeader := strings.SplitN(req.Header.Get(proxyAuthorizatonHeader), " ", 2)
	req.Header.Del(proxyAuthorizatonHeader)

	if len(authHeader) != 2 || authHeader[0] != "Digest" {
		return nil
	}

	m := make(map[string]string)

	quotedStringsRegexp := regexp.MustCompile("\"(.*?)\"")
	commasRegexp := regexp.MustCompile(",")

	h := authHeader[1]
	quotes := quotedStringsRegexp.FindAllStringSubmatchIndex(h, -1)
	commas := commasRegexp.FindAllStringSubmatchIndex(h, -1)

	separateCommas := make([]int, 0)
	var quotedComma bool

	for _, commaIndices := range commas {
		commaIndex := commaIndices[0]
		quotedComma = false
		for _, quoteIndices := range quotes {
			if len(quoteIndices) == 4 && commaIndex >= quoteIndices[2] && commaIndex <= quoteIndices[3] {
				quotedComma = true
				break
			}
		}
		if !quotedComma {
			separateCommas = append(separateCommas, commaIndex)
		}
	}

	tokens := make([]string, 0)
	s := 0

	for _, val := range separateCommas {
		e := val
		tokens = append(tokens, strings.Trim(h[s:e], " "))
		s = e + 1
	}

	tokens = append(tokens, strings.Trim(h[s:len(h)], " "))

	for _, token := range tokens {
		kv := strings.SplitN(token, "=", 2)
		m[kv[0]] = strings.Trim(kv[1], "\"")
	}

	var data DigestAuthData

	if v, ok := m["username"]; ok {
		data.user = v
	}

	if v, ok := m["realm"]; ok {
		data.realm = v
	}

	if v, ok := m["nonce"]; ok {
		data.nonce = v
	}

	if v, ok := m["uri"]; ok {
		data.uri = v
	}

	if v, ok := m["response"]; ok {
		data.response = v
	}

	if v, ok := m["qop"]; ok {
		data.qop = v
	}

	if v, ok := m["nc"]; ok {
		data.nc = v
	}

	if v, ok := m["cnonce"]; ok {
		data.cnonce = v
	}

	data.method = req.Method

	return &data
}

func getBasicAuthData(req *http.Request) *BasicAuthData {
	authHeader := strings.SplitN(req.Header.Get(proxyAuthorizatonHeader), " ", 2)
	req.Header.Del(proxyAuthorizatonHeader)

	if len(authHeader) != 2 || authHeader[0] != "Basic" {
		return nil
	}

	rawUserPassword, err := base64.StdEncoding.DecodeString(authHeader[1])
	if err != nil {
		return nil
	}

	userPassword := strings.SplitN(string(rawUserPassword), ":", 2)
	if len(userPassword) != 2 {
		return nil
	}

	data := BasicAuthData{user: userPassword[0], password: userPassword[1]}

	return &data
}

func basicAuth(req *http.Request, authFunc BasicAuthFunc) (bool, *BasicAuthData) {
	data := getBasicAuthData(req)
	if data == nil {
		return false, data
	}

	resp := authFunc(data)

	return resp.status, data
}

func digestAuth(req *http.Request, authFunc DigestAuthFunc) (bool, *DigestAuthData) {
	data := getDigestAuthData(req)
	if data == nil {
		return false, data
	}

	authResponse := authFunc(data, validateUser)

	switch authResponse.status {
	case authOk:
		return true, data
	case authFailed:
		return false, data
	default:
		panic("unreachable point")
	}

	//return false, data
}

func Basic(realm string, authFunc BasicAuthFunc) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		status, data := basicAuth(req, authFunc)
		if !status {
			if data != nil {
				ctx.Warnf("failed basic auth. attempt: user=%v, addr=%v", data.user, req.RemoteAddr)
			}
			return nil, basicUnauthorized(req, realm)
		}
		return req, nil
	})
}

func Digest(realm string, authFunc DigestAuthFunc) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		status, data := digestAuth(req, authFunc)
		if !status {
			if data != nil {
				ctx.Warnf("failed digest auth. attempt: user=%v, realm=%v, addr=%v", data.user, data.realm, req.RemoteAddr)
			}
			return nil, digestUnauthorized(req, realm, authFunc)
		}
		return req, nil
	})
}

func basicConnect(realm string, authFunc BasicAuthFunc) goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		status, data := basicAuth(ctx.Req, authFunc)
		if !status {
			if data != nil {
				ctx.Warnf("failed basic auth. CONNECT method attempt: user=%v, addr=%v", data.user, ctx.Req.RemoteAddr)
			}
			ctx.Resp = basicUnauthorized(ctx.Req, realm)
			return goproxy.RejectConnect, host
		}
		return goproxy.OkConnect, host
	})
}

func digestConnect(realm string, authFunc DigestAuthFunc) goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		status, data := digestAuth(ctx.Req, authFunc)
		if !status {
			if data != nil {
				ctx.Warnf("failed digest auth. CONNECT method attempt: user=%v, realm=%v, addr=%v",
					data.user, data.realm, ctx.Req.RemoteAddr)
			}
			ctx.Resp = digestUnauthorized(ctx.Req, realm, authFunc)
			return goproxy.RejectConnect, host
		}
		return goproxy.OkConnect, host
	})
}

func setProxyBasicAuth(proxy *goproxy.ProxyHttpServer, realm string, authFunc BasicAuthFunc) {
	proxy.OnRequest().Do(Basic(realm, authFunc))
	proxy.OnRequest().HandleConnect(basicConnect(realm, authFunc))
}

func setProxyDigestAuth(proxy *goproxy.ProxyHttpServer, realm string, authFunc DigestAuthFunc) {
	proxy.OnRequest().Do(Digest(realm, authFunc))
	proxy.OnRequest().HandleConnect(digestConnect(realm, authFunc))
}
