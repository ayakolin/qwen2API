package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// newBrowserHTTPClient builds an *http.Client whose TLS handshake mimics a real
// Chrome browser (via uTLS) instead of Go's default fingerprint. Aliyun WAF and
// similar anti-bot front ends fingerprint the TLS ClientHello (JA3/JA4): Go's
// stdlib hello is flagged as a bot and served a JS challenge page, while a
// genuine browser hello passes. The old Python gateway used httpx with HTTP/2
// and was never challenged from this host, so we mirror that: HTTP/2 over a
// Chrome-shaped ClientHello.
//
// The dialer honors HTTP(S)_PROXY / ALL_PROXY (SOCKS5) so an upstream proxy can
// still be layered underneath when configured.
func newBrowserHTTPClient(headerTimeout time.Duration) *http.Client {
	dialTimeout := 30 * time.Second
	handshakeTimeout := 20 * time.Second

	dialUTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			addr = net.JoinHostPort(addr, "443")
		}
		rawConn, err := proxyAwareDial(ctx, network, addr, dialTimeout)
		if err != nil {
			return nil, err
		}
		cfg := &utls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}
		uconn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
		if handshakeTimeout > 0 {
			_ = uconn.SetDeadline(time.Now().Add(handshakeTimeout))
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("utls handshake: %w", err)
		}
		_ = uconn.SetDeadline(time.Time{})
		if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "h2" {
			uconn.Close()
			return nil, fmt.Errorf("utls: server negotiated %q, expected h2", proto)
		}
		return uconn, nil
	}

	transport := &http2.Transport{
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialUTLS(ctx, network, addr)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
	}
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
