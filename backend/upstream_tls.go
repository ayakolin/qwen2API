package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// newBrowserHTTPClient builds an *http.Client whose TLS handshake mimics a real
// Chrome browser (via uTLS) instead of Go's default fingerprint. Aliyun WAF and
// similar anti-bot front ends fingerprint the TLS ClientHello (JA3/JA4): Go's
// stdlib hello is flagged as a bot and served a JS challenge page, while a
// genuine browser hello passes. The old Python gateway used httpx and was never
// challenged from this host, confirming the block is fingerprint-based.
//
// The connection speaks whichever protocol the server negotiates via ALPN
// (HTTP/2 or HTTP/1.1). The dialer honors ALL_PROXY / HTTPS_PROXY (SOCKS5) so an
// upstream proxy can still be layered underneath when configured.
func newBrowserHTTPClient(headerTimeout time.Duration) *http.Client {
	rt := &browserTransport{
		dialTimeout:      30 * time.Second,
		handshakeTimeout: 20 * time.Second,
		headerTimeout:    headerTimeout,
	}
	rt.h2 = &http2.Transport{
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
		// Connections are pre-dialed by RoundTrip; this is only a safety net.
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return rt.dialUTLS(ctx, network, addr)
		},
	}
	rt.h1 = &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rt.dialUTLS(ctx, network, addr)
		},
	}
	return &http.Client{Transport: rt, Timeout: 5 * time.Minute}
}

// browserTransport dispatches each request over a uTLS connection, choosing the
// HTTP/2 or HTTP/1.1 transport based on the ALPN protocol negotiated during the
// handshake. h2 client connections are cached per host so HTTP/2 multiplexing
// and connection reuse still work.
type browserTransport struct {
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	headerTimeout    time.Duration

	h2 *http2.Transport
	h1 *http.Transport

	mu      sync.Mutex
	h2conns map[string]*http2.ClientConn // host -> reusable h2 connection
}

func (rt *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return rt.h1.RoundTrip(req)
	}
	host := authorityAddr(req.URL.Host)

	// Reuse a live h2 connection for this host if one is cached and healthy.
	if cc := rt.cachedH2(host); cc != nil {
		if resp, err := cc.RoundTrip(req); err == nil {
			return resp, nil
		}
		rt.dropH2(host)
	}

	conn, err := rt.dialUTLS(req.Context(), "tcp", host)
	if err != nil {
		return nil, err
	}
	uconn := conn.(*utls.UConn)
	switch uconn.ConnectionState().NegotiatedProtocol {
	case "h2":
		cc, err := rt.h2.NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, err
		}
		rt.storeH2(host, cc)
		return cc.RoundTrip(req)
	default: // "http/1.1" or empty
		return rt.roundTripHTTP1(uconn, req)
	}
}

func (rt *browserTransport) cachedH2(host string) *http2.ClientConn {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	cc := rt.h2conns[host]
	if cc != nil && cc.CanTakeNewRequest() {
		return cc
	}
	return nil
}

func (rt *browserTransport) storeH2(host string, cc *http2.ClientConn) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.h2conns == nil {
		rt.h2conns = map[string]*http2.ClientConn{}
	}
	rt.h2conns[host] = cc
}

func (rt *browserTransport) dropH2(host string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.h2conns, host)
}

// dialUTLS opens a TCP connection (optionally via proxy) and performs a uTLS
// handshake mimicking Chrome, offering both h2 and http/1.1 via ALPN.
func (rt *browserTransport) dialUTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		addr = net.JoinHostPort(addr, "443")
	}
	rawConn, err := proxyAwareDial(ctx, network, addr, rt.dialTimeout)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}
	uconn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
	if rt.handshakeTimeout > 0 {
		_ = uconn.SetDeadline(time.Now().Add(rt.handshakeTimeout))
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	return uconn, nil
}

// roundTripHTTP1 speaks one HTTP/1.1 exchange over an established TLS conn.
func (rt *browserTransport) roundTripHTTP1(conn net.Conn, req *http.Request) (*http.Response, error) {
	tr := &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
		ResponseHeaderTimeout: rt.headerTimeout,
		DisableKeepAlives:     true,
	}
	return tr.RoundTrip(req)
}

func authorityAddr(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, "443")
	}
	return host
}

// proxyAwareDial dials addr directly, or through a SOCKS5 proxy resolved from
// the environment (ALL_PROXY / HTTPS_PROXY) when one is configured.
func proxyAwareDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err == nil && proxyURL != nil {
		switch proxyURL.Scheme {
		case "socks5", "socks5h":
			var auth *proxy.Auth
			if proxyURL.User != nil {
				pw, _ := proxyURL.User.Password()
				auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pw}
			}
			d, derr := proxy.SOCKS5("tcp", proxyURL.Host, auth, &net.Dialer{Timeout: timeout})
			if derr != nil {
				return nil, derr
			}
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return d.Dial(network, addr)
		}
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}
