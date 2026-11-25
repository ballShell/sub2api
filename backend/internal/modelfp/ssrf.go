package modelfp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyutil"
)

const (
	ssrfDialTimeout      = 10 * time.Second
	ssrfDialKeepAlive    = 30 * time.Second
	ssrfDNSLookupTimeout = 5 * time.Second
)

// ErrSSRFBlocked indicates an outbound probe or discovery URL violated SSRF policy.
var ErrSSRFBlocked = infraerrors.BadRequest(
	"MODELFP_SSRF_BLOCKED",
	"target URL is blocked by SSRF policy",
)

var (
	loopbackPrefixes = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	blockedIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	blockedIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	}
	blockedMetadataHostnames = map[string]struct{}{
		"metadata":                   {},
		"metadata.google.internal":   {},
		"metadata.goog":              {},
		"metadata.azure.com":         {},
		"metadata.azure.internal":    {},
		"metadata.tencentyun.com":    {},
		"metadata.internal":          {},
		"instance-data":              {},
		"instance-data.ec2.internal": {},
	}
)

type lookupNetIPFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// ValidateBaseURL parses and validates an outbound upstream base URL against SSRF rules.
func ValidateBaseURL(ctx context.Context, rawURL string) (*url.URL, error) {
	return validateBaseURL(ctx, rawURL, false)
}

func validateBaseURL(ctx context.Context, rawURL string, allowLoopback bool) (*url.URL, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: base URL is required", ErrSSRFBlocked)
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL syntax", ErrSSRFBlocked)
	}

	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: unsupported URL scheme %q", ErrSSRFBlocked, scheme)
	}
	parsed.Scheme = scheme

	if parsed.User != nil {
		return nil, fmt.Errorf("%w: URL must not contain userinfo", ErrSSRFBlocked)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: base URL must not contain query parameters or fragments", ErrSSRFBlocked)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: URL host is required", ErrSSRFBlocked)
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return nil, fmt.Errorf("%w: URL host is required", ErrSSRFBlocked)
	}

	if portStr := parsed.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("%w: invalid port %q", ErrSSRFBlocked, portStr)
		}
	}

	if err := validateHostLiteral(host, allowLoopback); err != nil {
		return nil, err
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed, nil
}

func validateHostLiteral(host string, allowLoopback bool) error {
	clean := normalizeHost(host)
	if clean == "" {
		return fmt.Errorf("%w: empty host", ErrSSRFBlocked)
	}
	if isBlockedHostname(clean, allowLoopback) {
		return fmt.Errorf("%w: blocked host %q", ErrSSRFBlocked, clean)
	}
	if addr, err := netip.ParseAddr(clean); err == nil {
		if isBlockedAddr(addr, allowLoopback) {
			return fmt.Errorf("%w: blocked IP address %s", ErrSSRFBlocked, addr.Unmap().String())
		}
	}
	return nil
}

func normalizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

func isBlockedHostname(host string, allowLoopback bool) bool {
	if host == "" {
		return true
	}
	if !allowLoopback {
		if host == "localhost" ||
			strings.HasSuffix(host, ".localhost") ||
			host == "localhost.localdomain" ||
			host == "ip6-localhost" ||
			host == "ip6-loopback" {
			return true
		}
	}
	if _, blocked := blockedMetadataHostnames[host]; blocked {
		return true
	}
	if strings.HasSuffix(host, ".metadata.google.internal") || strings.HasSuffix(host, ".local") {
		return true
	}
	return false
}

func isBlockedAddr(addr netip.Addr, allowLoopback bool) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsUnspecified() ||
		addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() {
		return true
	}
	if !allowLoopback {
		if addr.IsLoopback() || matchesAnyPrefix(addr, loopbackPrefixes) {
			return true
		}
	}
	if addr.Is4() {
		return matchesAnyPrefix(addr, blockedIPv4Prefixes)
	}
	return matchesAnyPrefix(addr, blockedIPv6Prefixes)
}

func matchesAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func newSSRFSafeTransport(proxyURL string, allowLoopback bool) (*http.Transport, error) {
	tr := &http.Transport{
		// Never inherit HTTP_PROXY/HTTPS_PROXY from environment so direct probes
		// cannot bypass socket-level DNS/IP validation.
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}

	_, parsedProxy, err := proxyurl.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	if parsedProxy == nil {
		tr.DialContext = newSSRFSafeDialContextWithLookup(allowLoopback, nil)
		return tr, nil
	}

	if err := proxyutil.ConfigureTransportProxy(tr, parsedProxy); err != nil {
		return nil, fmt.Errorf("configure proxy transport: %w", err)
	}
	return tr, nil
}

func newSSRFSafeDialContextWithLookup(
	allowLoopback bool,
	lookupFn lookupNetIPFunc,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if lookupFn == nil {
		lookupFn = net.DefaultResolver.LookupNetIP
	}
	dialer := &net.Dialer{
		Timeout:   ssrfDialTimeout,
		KeepAlive: ssrfDialKeepAlive,
		Control:   makeSSRFDialControl(allowLoopback),
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid target address", ErrSSRFBlocked)
		}
		if err := validateHostLiteral(host, allowLoopback); err != nil {
			return nil, err
		}

		cleanHost := normalizeHost(host)
		if ip, parseErr := netip.ParseAddr(cleanHost); parseErr == nil {
			if isBlockedAddr(ip, allowLoopback) {
				return nil, fmt.Errorf("%w: blocked IP address %s", ErrSSRFBlocked, ip.Unmap().String())
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().WithZone("").String(), port))
		}

		lookupCtx, cancel := context.WithTimeout(ctx, ssrfDNSLookupTimeout)
		defer cancel()
		addrs, err := lookupFn(lookupCtx, "ip", cleanHost)
		if err != nil {
			return nil, fmt.Errorf("resolve host %q: %w", cleanHost, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve host %q: no addresses returned", cleanHost)
		}

		// Reject the entire dial if any DNS record resolves to a blocked IP
		// so dual-record DNS rebinding cannot slip through.
		validated := make([]netip.Addr, 0, len(addrs))
		for _, ip := range addrs {
			if isBlockedAddr(ip, allowLoopback) {
				return nil, fmt.Errorf("%w: host %q resolved to blocked IP %s", ErrSSRFBlocked, cleanHost, ip.Unmap().String())
			}
			validated = append(validated, ip.Unmap().WithZone(""))
		}

		var lastErr error
		for _, ip := range validated {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
			if errors.Is(dialErr, ErrSSRFBlocked) {
				return nil, dialErr
			}
		}
		if lastErr == nil {
			return nil, errors.New("dial failed with no reachable addresses")
		}
		return nil, lastErr
	}
}

func makeSSRFDialControl(allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: invalid socket address", ErrSSRFBlocked)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || isBlockedAddr(addr, allowLoopback) {
			return fmt.Errorf("%w: socket target %s is blocked", ErrSSRFBlocked, host)
		}
		return nil
	}
}
