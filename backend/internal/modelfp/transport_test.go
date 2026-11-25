package modelfp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateBaseURLBlocksSSRF(t *testing.T) {
	blocked := []string{
		"",
		"   ",
		"http://127.0.0.1:8080",
		"http://127.0.1.1/v1",
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.1/v1",
		"http://172.16.0.1/v1",
		"http://192.168.1.10/v1",
		"http://100.64.0.1/v1",
		"http://100.100.100.200/latest/meta-data",
		"http://0.0.0.0:8080",
		"http://[::1]:8080",
		"http://[::]:8080",
		"http://[fc00::1]/v1",
		"http://[fd00:ec2::254]/latest/meta-data",
		"http://[fe80::1]/v1",
		"http://[::ffff:127.0.0.1]:8080",
		"http://[::ffff:169.254.169.254]/v1",
		"ftp://example.com",
		"file:///etc/passwd",
		"http://localhost/v1",
		"http://api.localhost/v1",
		"https://metadata.google.internal/computeMetadata/v1",
		"https://metadata.azure.internal/metadata/instance",
		"https://user:pass@api.example.com/v1",
		"https://api.example.com/v1?token=leak",
		"https://api.example.com/v1#frag",
	}
	for _, u := range blocked {
		if _, err := ValidateBaseURL(context.Background(), u); err == nil {
			t.Fatalf("expected SSRF rejection for %q", u)
		}
	}

	// Verify DNS resolution inside ValidateBaseURL rejects non-literal hostnames resolving to blocked IPs.
	for _, tc := range []struct {
		host string
		ip   string
	}{
		{"loopback-dns.example.com", "127.0.0.1"},
		{"rfc1918-dns.example.com", "10.20.30.40"},
		{"metadata-dns.example.com", "169.254.169.254"},
		{"cgnat-dns.example.com", "100.64.10.1"},
		{"ula-dns.example.com", "fc00::1"},
	} {
		_, err := validateBaseURLWithLookup(context.Background(), "https://"+tc.host+"/v1", false, func(_ context.Context, _, host string) ([]netip.Addr, error) {
			if host != tc.host {
				t.Fatalf("unexpected DNS lookup host %q", host)
			}
			return []netip.Addr{netip.MustParseAddr(tc.ip)}, nil
		})
		if !errors.Is(err, ErrSSRFBlocked) {
			t.Fatalf("expected ValidateBaseURL DNS check to block %s (%s), got %v", tc.host, tc.ip, err)
		}
	}

	allowed := []string{
		"https://api.example.com",
		"https://api.openai.com/v1/",
		"https://8.8.8.8/v1",
		"https://[2606:4700:4700::1111]/v1",
	}
	for _, u := range allowed {
		parsed, err := validateBaseURLWithLookup(context.Background(), u, false, func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		})
		if err != nil {
			t.Fatalf("expected %q to be allowed, got %v", u, err)
		}
		if parsed == nil || parsed.Host == "" {
			t.Fatalf("expected parsed URL for %q, got %+v", u, parsed)
		}
	}
}

func TestSSRFSafeTransportDialContextAndProxy(t *testing.T) {
	rt, err := newSSRFSafeTransport("", false)
	if err != nil {
		t.Fatalf("newSSRFSafeTransport failed: %v", err)
	}
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport for direct SSRF transport, got %T", rt)
	}
	if tr.Proxy != nil {
		t.Fatalf("expected direct SSRF transport Proxy to be nil")
	}
	if tr.DialContext == nil {
		t.Fatalf("expected DialContext to be non-nil")
	}

	blockedTargets := []string{
		"127.0.0.1:8080",
		"[::1]:8080",
		"10.0.0.1:443",
		"172.16.0.5:443",
		"192.168.1.5:443",
		"169.254.169.254:80",
		"100.64.0.5:443",
		"0.0.0.0:80",
		"[fc00::1]:443",
		"[fe80::1]:443",
		"[::]:443",
		"localhost:8080",
		"metadata.google.internal:80",
	}
	for _, addr := range blockedTargets {
		conn, dialErr := tr.DialContext(context.Background(), "tcp", addr)
		if conn != nil {
			_ = conn.Close()
		}
		if dialErr == nil || !errors.Is(dialErr, ErrSSRFBlocked) {
			t.Fatalf("expected ErrSSRFBlocked for DialContext %s, got conn=%v err=%v", addr, conn, dialErr)
		}
	}

	// Verify DNS resolution checks reject hostnames resolving to private/metadata IPs (anti-DNS-rebinding).
	rebindDial := newSSRFSafeDialContextWithLookup(false, func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "rebind.example.com" {
			return []netip.Addr{
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("169.254.169.254"),
			}, nil
		}
		return nil, errors.New("unexpected lookup")
	})
	if conn, dialErr := rebindDial(context.Background(), "tcp", "rebind.example.com:443"); dialErr == nil || !errors.Is(dialErr, ErrSSRFBlocked) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("expected DNS rebinding check to block mixed public+metadata IPs, got err=%v", dialErr)
	}

	// Verify proxied requests enforce destination IP/DNS policy BEFORE forwarding through the proxy.
	var proxyHits atomic.Int32
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxySrv.Close()

	proxiedClient := NewHTTPProbeClient(withLookupNetIPForTest(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "internal-only.example.com" {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
		return nil, errors.New("nxdomain")
	}))
	for _, targetURL := range []string{"http://internal-only.example.com", "http://unresolvable-vpc.corp"} {
		res := proxiedClient.ExecuteProbe(context.Background(), ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  targetURL,
			APIKey:   "sk-proxied-secret",
			ProxyURL: proxySrv.URL,
		}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
		if res.ErrorCode != "ssrf_blocked" {
			t.Fatalf("expected proxied SSRF target %s blocked with ssrf_blocked, got %+v", targetURL, res)
		}
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("expected proxy to receive 0 requests for SSRF targets, got %d", proxyHits.Load())
	}

	// Verify HTTP 302 redirect to metadata IP is blocked even when AllowLoopbackForTest is enabled.
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirectSrv.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	res := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: redirectSrv.URL, APIKey: "sk-redirect-secret",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if res.ErrorCode != "ssrf_blocked" {
		t.Fatalf("expected redirect to metadata IP to return ssrf_blocked, got %+v", res)
	}
	if strings.Contains(res.ErrorMessage, "sk-redirect-secret") {
		t.Fatalf("redirect error leaked API key: %s", res.ErrorMessage)
	}
}

func TestRedirectsDisabledWithoutCredentialLeak(t *testing.T) {
	var evilHits atomic.Int32
	evilSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer evilSrv.Close()

	var sameHostHits atomic.Int32
	var redirector *httptest.Server
	redirector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages", "/v1beta/models":
			http.Redirect(w, r, evilSrv.URL+"/steal", http.StatusTemporaryRedirect)
		case "/v1/chat/completions":
			// Even same-origin redirects must not be followed.
			http.Redirect(w, r, redirector.URL+"/v1/next", http.StatusFound)
		case "/v1/next":
			sameHostHits.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer redirector.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	res := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol:     ProtocolAnthropic,
		BaseURL:      redirector.URL,
		APIKey:       "sk-ant-redirect-secret",
		ExtraHeaders: map[string]string{"X-Custom-Secret": "hdr-secret-999"},
	}, "claude-sonnet-4-6", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)

	if res.ErrorCode != "ssrf_blocked" {
		t.Fatalf("expected cross-origin redirect to return ssrf_blocked, got %+v", res)
	}
	if evilHits.Load() != 0 {
		t.Fatalf("expected cross-origin target not to receive credentials, got %d hits", evilHits.Load())
	}
	if strings.Contains(res.ErrorMessage, "sk-ant-redirect-secret") || strings.Contains(res.ErrorMessage, "hdr-secret-999") {
		t.Fatalf("cross-origin redirect error leaked secrets: %s", res.ErrorMessage)
	}

	// Same-host redirect must also be blocked without making a second request.
	sameRes := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  redirector.URL,
		APIKey:   "sk-same-origin-secret",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if sameRes.ErrorCode != "ssrf_blocked" || sameHostHits.Load() != 0 {
		t.Fatalf("expected same-origin redirect blocked with 0 target hits, got hits=%d res=%+v", sameHostHits.Load(), sameRes)
	}

	// Trailing-dot redirect boundary check (example.com -> example.com.) must also be rejected.
	hc, err := client.clientForTarget(ProbeTarget{Protocol: ProtocolOpenAIChat, BaseURL: "https://example.com"}, defaultProbeTimeout)
	if err != nil {
		t.Fatalf("clientForTarget failed: %v", err)
	}
	origReq, _ := http.NewRequest(http.MethodGet, "https://example.com/v1/models", nil)
	dotReq, _ := http.NewRequest(http.MethodGet, "https://example.com./v1/models", nil)
	if err := hc.CheckRedirect(dotReq, []*http.Request{origReq}); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("expected trailing-dot redirect to be rejected with ErrSSRFBlocked, got %v", err)
	}

	if _, err := client.DiscoverModels(context.Background(), ProbeTarget{
		Protocol: ProtocolGemini,
		BaseURL:  redirector.URL,
		APIKey:   "gem-redirect-secret",
	}); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("expected DiscoverModels cross-origin redirect to return ErrSSRFBlocked, got %v", err)
	}
	if evilHits.Load() != 0 {
		t.Fatalf("expected DiscoverModels cross-origin redirect not to reach evilSrv, got %d hits", evilHits.Load())
	}
}

func TestNormalizeProtocolEndpoint(t *testing.T) {
	// Review Focus #1: never produce /v1/v1/... and preserve custom prefixes
	cases := []struct {
		base, want   string
		proto        Protocol
		model        string
		forDiscovery bool
	}{
		{"https://api.example.com", "https://api.example.com/v1/chat/completions", ProtocolOpenAIChat, "gpt-4o", false},
		{"https://api.example.com/v1/", "https://api.example.com/v1/chat/completions", ProtocolOpenAIChat, "gpt-4o", false},
		{"https://api.example.com/openai/v1", "https://api.example.com/openai/v1/responses", ProtocolOpenAIResponses, "gpt-5", false},
		{"https://api.example.com/v1", "https://api.example.com/v1/messages", ProtocolAnthropic, "claude-sonnet-4-6", false},
		{"https://generativelanguage.googleapis.com", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent", ProtocolGemini, "gemini-2.5-pro", false},
		{"https://generativelanguage.googleapis.com/v1beta/", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent", ProtocolGemini, "gemini-2.5-pro", false},
		{"https://generativelanguage.googleapis.com/v1beta", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent", ProtocolGemini, "models/gemini-2.5-pro", false},
		{"https://generativelanguage.googleapis.com/v1beta", "https://generativelanguage.googleapis.com/v1beta/models/org%2Fgemini%20custom:generateContent", ProtocolGemini, "org/gemini custom", false},
		{"https://open.bigmodel.cn/api/paas/v4/", "https://open.bigmodel.cn/api/paas/v4/chat/completions", ProtocolOpenAIChat, "glm-4", false},
		{"https://api.example.com/openai", "https://api.example.com/openai/v1/chat/completions", ProtocolOpenAIChat, "gpt-4o", false},
		// Discovery URLs
		{"https://api.example.com", "https://api.example.com/v1/models", ProtocolOpenAIChat, "", true},
		{"https://api.example.com/openai/v1/", "https://api.example.com/openai/v1/models", ProtocolOpenAIResponses, "", true},
		{"https://api.example.com/v1", "https://api.example.com/v1/models", ProtocolAnthropic, "", true},
		{"https://generativelanguage.googleapis.com", "https://generativelanguage.googleapis.com/v1beta/models", ProtocolGemini, "", true},
		{"https://generativelanguage.googleapis.com/v1beta/", "https://generativelanguage.googleapis.com/v1beta/models", ProtocolGemini, "", true},
	}
	for _, tc := range cases {
		got, err := NormalizeProtocolEndpoint(tc.base, tc.proto, tc.model, tc.forDiscovery)
		if err != nil || got != tc.want {
			t.Fatalf("base=%s proto=%s discovery=%v: got %q (%v), want %q", tc.base, tc.proto, tc.forDiscovery, got, err, tc.want)
		}
		if strings.Contains(got, "%25") {
			t.Fatalf("detected double-escaped percent encoding in %q", got)
		}
	}

	if _, err := NormalizeProtocolEndpoint("https://api.example.com", Protocol("unknown"), "m", false); err == nil {
		t.Fatalf("expected error for unknown protocol")
	}
	if _, err := NormalizeProtocolEndpoint("https://api.example.com", ProtocolOpenAIChat, "", false); err == nil {
		t.Fatalf("expected error for empty model when not discovering")
	}
}

func TestOpenAIChatRetriesWithoutLogprobsOn400(t *testing.T) {
	// Review Focus #3: HTTP 400 on logprobs retries once without logprobs
	calls := 0
	var payloads []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-secret-value-123" {
			t.Fatalf("unexpected auth header %q", r.Header.Get("Authorization"))
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		payloads = append(payloads, body)

		if calls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"logprobs is not supported"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"model":"gpt-4o","choices":[{"message":{"content":"hello"}}],"usage":{"prompt_tokens":4120,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4096}}}`))
	}))
	defer srv.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	res := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-secret-value-123",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorLogprobs, Prompt: "hi", MaxTokens: 1}, true)

	if calls != 2 || res.ErrorCode != "" || res.LogprobsSupported {
		t.Fatalf("expected 2 calls fallback without error, got calls=%d res=%+v", calls, res)
	}
	if res.PromptTokens != 4120 || res.CachedPromptTokens != 4096 || res.OutputTokens != 5 {
		t.Fatalf("expected prompt/cached/output tokens parsed, got %+v", res)
	}
	if res.Text != "hello" || res.ResponseModel != "gpt-4o" {
		t.Fatalf("unexpected text/model: %+v", res)
	}
	if payloads[0]["stream"] != false || payloads[0]["logprobs"] != true {
		t.Fatalf("expected stream=false and logprobs=true on first request: %+v", payloads[0])
	}
	for _, forbidden := range []string{"logprobs", "top_logprobs", "seed"} {
		if _, exists := payloads[1][forbidden]; exists {
			t.Fatalf("expected %q stripped on retry payload, got %+v", forbidden, payloads[1])
		}
	}
}

func TestOpenAIChatLogprobsAndMetadataExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"model": "gpt-4o-2024-08-06",
			"system_fingerprint": "fp_abc123",
			"choices": [{
				"message": {"content": "blue", "reasoning_content": "thinking"},
				"logprobs": {
					"content": [{
						"token": "blue",
						"logprob": -0.1,
						"top_logprobs": [
							{"token": "blue", "logprob": -0.1},
							{"token": " red", "logprob": -2.5}
						]
					}]
				}
			}],
			"usage": {"prompt_tokens": 18, "completion_tokens": 1}
		}`))
	}))
	defer srv.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	res := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-test",
	}, "gpt-4o", ProbeDefinition{ID: "lp1", Kind: DetectorLogprobs, Prompt: "color", MaxTokens: 1, TopLogprobs: 20}, true)

	if res.ErrorCode != "" || !res.LogprobsSupported || len(res.Logprobs) != 2 {
		t.Fatalf("expected 2 logprobs entries, got %+v", res)
	}
	if res.Logprobs[1].Token != " red" {
		t.Fatalf("expected whitespace preserved in token %q", res.Logprobs[1].Token)
	}
	if res.SystemFingerprint != "fp_abc123" || !res.HasReasoningField || res.ResponseModel != "gpt-4o-2024-08-06" {
		t.Fatalf("expected metadata fields populated, got %+v", res)
	}
}

func TestTransportErrorRedactsAPIKey(t *testing.T) {
	// Review Focus #2: secret never leaks in error message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid key sk-super-secret-999"}}`))
	}))
	defer srv.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	res := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolAnthropic, BaseURL: srv.URL, APIKey: "sk-super-secret-999",
	}, "claude-sonnet-4-6", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)

	if res.ErrorCode != "auth_error" || strings.Contains(res.ErrorMessage, "sk-super-secret-999") {
		t.Fatalf("expected redacted auth_error, got %+v", res)
	}
	if !strings.Contains(res.ErrorMessage, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] placeholder in error message, got %q", res.ErrorMessage)
	}

	// Non-JSON HTML or arbitrary JSON without envelope must not echo raw body.
	rawHTMLSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html><body>upstream failed for sk-html-secret-777</body></html>`))
	}))
	defer rawHTMLSrv.Close()
	htmlRes := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: rawHTMLSrv.URL, APIKey: "sk-html-secret-777",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if htmlRes.ErrorCode != "upstream_error" || strings.Contains(htmlRes.ErrorMessage, "<html>") || strings.Contains(htmlRes.ErrorMessage, "sk-html-secret-777") {
		t.Fatalf("expected status-only error for non-JSON body, got %+v", htmlRes)
	}
	if htmlRes.ErrorMessage != "upstream HTTP 502 Bad Gateway" {
		t.Fatalf("unexpected non-JSON error message: %q", htmlRes.ErrorMessage)
	}

	// JSON-escaped secrets in error messages (including arbitrary \uXXXX escapes like \u0073k-...) must be redacted.
	escapedSecret := `sk-<secret>&"999`
	escapedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid key sk-\\u003csecret\\u003e\\u0026\\\"999 and sk-\u003csecret\u003e\u0026\"999"}}`))
	}))
	defer escapedSrv.Close()
	escRes := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: escapedSrv.URL, APIKey: escapedSecret,
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if escRes.ErrorCode != "auth_error" || strings.Contains(escRes.ErrorMessage, "secret") {
		t.Fatalf("expected JSON-escaped secret redacted, got %+v", escRes)
	}

	unicodeEscapedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid key \\u0073k-super-secret-999"}}`))
	}))
	defer unicodeEscapedSrv.Close()
	uniRes := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: unicodeEscapedSrv.URL, APIKey: "sk-super-secret-999",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if uniRes.ErrorCode != "auth_error" ||
		strings.Contains(uniRes.ErrorMessage, "super-secret-999") ||
		strings.Contains(uniRes.ErrorMessage, `\u0073`) ||
		!strings.Contains(uniRes.ErrorMessage, "upstream HTTP 401") {
		t.Fatalf("expected \\u0073k- escaped secret replaced with generic HTTP 401 fallback, got %+v", uniRes)
	}
	directRedacted := redactSecrets(`bad key \u0073k-super-secret-999`, ProbeTarget{APIKey: "sk-super-secret-999"})
	if strings.Contains(directRedacted, "super-secret-999") || strings.Contains(directRedacted, `\u0073`) {
		t.Fatalf("expected direct redactSecrets to strip \\u0073k- secret, got %q", directRedacted)
	}

	// Multiline error containing a secret using mixed \uXXXX and \/ JSON escapes.
	multilineSecret := "sk-multi/secret/999"
	multilineMixed := "line one\nline two: \\u0073k-multi\\/secret\\/999\nline three"
	multiRedacted := redactSecretsWithStatus(multilineMixed, http.StatusUnauthorized, ProbeTarget{APIKey: multilineSecret})
	if strings.Contains(multiRedacted, "multi") || strings.Contains(multiRedacted, "999") || !strings.Contains(multiRedacted, "upstream HTTP 401") {
		t.Fatalf("expected multiline mixed-escape secret replaced with generic HTTP 401 fallback, got %q", multiRedacted)
	}

	// Partially-escaped key whose unescaped prefix matches sk-... regex followed by \uXXXX tail must not leak tail.
	partialSecret := "sk-prefix1234tail99"
	partialMsg := `invalid key sk-prefix1234\u0074ail99`
	partialRedacted := redactSecretsWithStatus(partialMsg, http.StatusUnauthorized, ProbeTarget{APIKey: partialSecret})
	if partialRedacted != "upstream HTTP 401 Unauthorized" ||
		strings.Contains(partialRedacted, "tail99") ||
		strings.Contains(partialRedacted, "prefix1234") ||
		strings.Contains(partialRedacted, `\u0074`) {
		t.Fatalf("expected partially-escaped key replaced with generic HTTP 401 fallback without tail leak, got %q", partialRedacted)
	}
	if partialDirect := redactSecrets(partialMsg, ProbeTarget{APIKey: partialSecret}); partialDirect != "upstream error (redacted)" {
		t.Fatalf("expected direct redactSecrets to return redacted fallback for partially-escaped key, got %q", partialDirect)
	}
	partialSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid key sk-prefix1234\\u0074ail99"}}`))
	}))
	defer partialSrv.Close()
	partialHTTPRes := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: partialSrv.URL, APIKey: partialSecret,
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if partialHTTPRes.ErrorCode != "auth_error" ||
		partialHTTPRes.ErrorMessage != "upstream HTTP 401 Unauthorized" ||
		strings.Contains(partialHTTPRes.ErrorMessage, "tail99") {
		t.Fatalf("expected partially-escaped HTTP error replaced with generic HTTP 401 fallback, got %+v", partialHTTPRes)
	}

	// Unpaired high surrogate \uD800 immediately followed by \u0073k-... must not swallow \u0073 and must redact key.
	surrogateSecret := "sk-surrogate-secret-999"
	surrogateMsg := `bad key \uD800\u0073k-surrogate-secret-999`
	surrogateRedacted := redactSecretsWithStatus(surrogateMsg, http.StatusUnauthorized, ProbeTarget{APIKey: surrogateSecret})
	if surrogateRedacted != "upstream HTTP 401 Unauthorized" ||
		strings.Contains(surrogateRedacted, "surrogate-secret-999") ||
		strings.Contains(surrogateRedacted, "k-surrogate") ||
		strings.Contains(surrogateRedacted, `\u0073`) ||
		strings.Contains(surrogateRedacted, `\uD800`) {
		t.Fatalf("expected unpaired high surrogate + \\u0073k- secret replaced with generic HTTP 401 fallback, got %q", surrogateRedacted)
	}
	if surrogateDirect := redactSecrets(surrogateMsg, ProbeTarget{APIKey: surrogateSecret}); surrogateDirect != "upstream error (redacted)" {
		t.Fatalf("expected direct redactSecrets to return redacted fallback for unpaired surrogate + secret, got %q", surrogateDirect)
	}
	surrogateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"bad key \\uD800\\u0073k-surrogate-secret-999"}}`))
	}))
	defer surrogateSrv.Close()
	surrogateHTTPRes := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: surrogateSrv.URL, APIKey: surrogateSecret,
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if surrogateHTTPRes.ErrorCode != "auth_error" ||
		surrogateHTTPRes.ErrorMessage != "upstream HTTP 401 Unauthorized" ||
		strings.Contains(surrogateHTTPRes.ErrorMessage, "surrogate-secret-999") {
		t.Fatalf("expected unpaired surrogate HTTP error replaced with generic HTTP 401 fallback, got %+v", surrogateHTTPRes)
	}

	if got := unescapeJSONSequences(`\uD800\u0073k-abc`); got != "\uFFFDsk-abc" {
		t.Fatalf("expected lone high surrogate to emit replacement char without swallowing \\u0073, got %q", got)
	}
	if got := unescapeJSONSequences(`\uD83D\uDE00`); got != "😀" {
		t.Fatalf("expected valid surrogate pair to decode to emoji, got %q", got)
	}
	if got := unescapeJSONSequences(`\uDC00\u0073k-abc`); got != "\uFFFDsk-abc" {
		t.Fatalf("expected lone low surrogate to emit replacement char without swallowing \\u0073, got %q", got)
	}
	if got := unescapeJSONSequences(`\uD800\uD83D\uDE00`); got != "\uFFFD😀" {
		t.Fatalf("expected lone high surrogate followed by valid surrogate pair to decode cleanly, got %q", got)
	}

	// Also check DiscoverModels redaction and HTTP error taxonomy
	statusCases := []struct {
		status int
		want   string
	}{
		{http.StatusForbidden, "auth_error"},
		{http.StatusNotFound, "model_not_found"},
		{http.StatusTooManyRequests, "rate_limited"},
		{http.StatusBadGateway, "upstream_error"},
	}
	for _, tc := range statusCases {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":{"message":"rejected header sk-extra-secret-42 and sk-super-secret-999"}}`))
		}))
		got := client.ExecuteProbe(context.Background(), ProbeTarget{
			Protocol: ProtocolOpenAIChat, BaseURL: errSrv.URL, APIKey: "sk-super-secret-999",
			ExtraHeaders: map[string]string{"X-Custom-Auth": "sk-extra-secret-42"},
		}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
		errSrv.Close()
		if got.ErrorCode != tc.want {
			t.Fatalf("status=%d: got ErrorCode=%q, want %q (%+v)", tc.status, got.ErrorCode, tc.want, got)
		}
		if strings.Contains(got.ErrorMessage, "sk-super-secret-999") || strings.Contains(got.ErrorMessage, "sk-extra-secret-42") {
			t.Fatalf("secret leaked in error message: %q", got.ErrorMessage)
		}
	}

	// Timeout classification
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	timeoutRes := client.ExecuteProbe(ctx, ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: slowSrv.URL, APIKey: "sk-timeout-secret",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if timeoutRes.ErrorCode != "timeout" {
		t.Fatalf("expected timeout error code, got %+v", timeoutRes)
	}
}

func TestProtocolAdapters(t *testing.T) {
	t.Run("openai_responses", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/responses" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer resp-key" {
				t.Fatalf("unexpected auth header %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body["stream"] != false || body["input"] != "count r" || body["instructions"] != "be concise" {
				t.Fatalf("unexpected responses request body: %+v", body)
			}
			_, _ = w.Write([]byte(`{
				"id": "resp_1",
				"model": "gpt-5-2025-08-07",
				"output": [
					{"type": "reasoning", "summary": [{"type": "summary_text", "text": "thinking"}]},
					{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "5"}]}
				],
				"usage": {
					"input_tokens": 110,
					"output_tokens": 12,
					"input_tokens_details": {"cached_tokens": 64},
					"output_tokens_details": {"reasoning_tokens": 9}
				}
			}`))
		}))
		defer srv.Close()

		client := NewHTTPProbeClient(WithAllowLoopbackForTest())
		res := client.ExecuteProbe(context.Background(), ProbeTarget{
			Protocol: ProtocolOpenAIResponses, BaseURL: srv.URL, APIKey: "resp-key",
		}, "gpt-5", ProbeDefinition{ID: "bh1", Kind: DetectorBehavior, Prompt: "count r", SystemPrompt: "be concise", MaxTokens: 64}, false)

		if res.ErrorCode != "" || res.Text != "5" || res.ResponseModel != "gpt-5-2025-08-07" {
			t.Fatalf("unexpected responses result: %+v", res)
		}
		if !res.HasReasoningField || res.PromptTokens != 110 || res.CachedPromptTokens != 64 || res.OutputTokens != 12 {
			t.Fatalf("unexpected responses metadata/usage: %+v", res)
		}
	})

	t.Run("anthropic_x_api_key_and_bearer", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			authMode string
			wantHdr  string
			wantVal  string
		}{
			{"default x-api-key", "", "x-api-key", "ant-secret"},
			{"explicit bearer", "bearer", "Authorization", "Bearer ant-secret"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/messages" {
						t.Fatalf("unexpected path %s", r.URL.Path)
					}
					if r.Header.Get("anthropic-version") != "2023-06-01" {
						t.Fatalf("missing anthropic-version header: %q", r.Header.Get("anthropic-version"))
					}
					if r.Header.Get(tc.wantHdr) != tc.wantVal {
						t.Fatalf("header %s = %q, want %q", tc.wantHdr, r.Header.Get(tc.wantHdr), tc.wantVal)
					}
					if tc.authMode == "bearer" && r.Header.Get("x-api-key") != "" {
						t.Fatalf("expected x-api-key omitted in bearer mode")
					}
					_, _ = w.Write([]byte(`{
						"id": "msg_1",
						"model": "claude-sonnet-4-6",
						"content": [
							{"type": "thinking", "thinking": "step by step"},
							{"type": "text", "text": "{\"sum\":55}"}
						],
						"usage": {
							"input_tokens": 42,
							"cache_creation_input_tokens": 100,
							"cache_read_input_tokens": 4096,
							"output_tokens": 11
						}
					}`))
				}))
				defer srv.Close()

				client := NewHTTPProbeClient(WithAllowLoopbackForTest())
				res := client.ExecuteProbe(context.Background(), ProbeTarget{
					Protocol: ProtocolAnthropic, BaseURL: srv.URL, APIKey: "ant-secret", AuthMode: tc.authMode,
				}, "claude-sonnet-4-6", ProbeDefinition{ID: "bh1", Kind: DetectorBehavior, Prompt: "json", MaxTokens: 64}, false)

				if res.ErrorCode != "" || res.Text != "{\"sum\":55}" || !res.HasReasoningField {
					t.Fatalf("unexpected anthropic result: %+v", res)
				}
				if res.PromptTokens != 4238 || res.CachedPromptTokens != 4096 || res.OutputTokens != 11 {
					t.Fatalf("unexpected anthropic usage (want PromptTokens=4238 CachedPromptTokens=4096 OutputTokens=11): %+v", res)
				}
			})
		}
	})

	t.Run("gemini_logprobs_and_400_retry", func(t *testing.T) {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1beta/models/gemini-2.5-pro:generateContent" {
				t.Fatalf("unexpected gemini path %s", r.URL.Path)
			}
			if r.Header.Get("x-goog-api-key") != "gem-secret" {
				t.Fatalf("unexpected x-goog-api-key %q", r.Header.Get("x-goog-api-key"))
			}
			var body struct {
				GenerationConfig map[string]any `json:"generationConfig"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode gemini request: %v", err)
			}
			if atomic.AddInt32(&calls, 1) == 1 {
				if body.GenerationConfig["responseLogprobs"] != true {
					t.Fatalf("expected responseLogprobs=true on first call: %+v", body.GenerationConfig)
				}
				_, _ = w.Write([]byte(`{
					"modelVersion": "gemini-2.5-pro-001",
					"candidates": [{
						"content": {"parts": [{"thought": true, "text": "hmm"}, {"text": "silver"}]},
						"logprobsResult": {
							"topCandidates": [{
								"candidates": [
									{"token": "silver", "logProbability": -0.2},
									{"token": "grey", "logProbability": -1.6}
								]
							}]
						}
					}],
					"usageMetadata": {
						"promptTokenCount": 520,
						"cachedContentTokenCount": 256,
						"candidatesTokenCount": 3
					}
				}`))
				return
			}
		}))
		defer srv.Close()

		client := NewHTTPProbeClient(WithAllowLoopbackForTest())
		res := client.ExecuteProbe(context.Background(), ProbeTarget{
			Protocol: ProtocolGemini, BaseURL: srv.URL, APIKey: "gem-secret",
		}, "gemini-2.5-pro", ProbeDefinition{ID: "lp1", Kind: DetectorLogprobs, Prompt: "pale", MaxTokens: 1, TopLogprobs: 20}, true)

		if res.ErrorCode != "" || !res.LogprobsSupported || len(res.Logprobs) != 2 {
			t.Fatalf("unexpected gemini logprobs result: %+v", res)
		}
		if res.Text != "silver" || !res.HasReasoningField || res.ResponseModel != "gemini-2.5-pro-001" {
			t.Fatalf("unexpected gemini text/meta: %+v", res)
		}
		if res.PromptTokens != 520 || res.CachedPromptTokens != 256 || res.OutputTokens != 3 {
			t.Fatalf("unexpected gemini usage: %+v", res)
		}

		// Gemini 400 retry strips responseLogprobs/logprobs
		retryCalls := 0
		retrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			retryCalls++
			var body struct {
				GenerationConfig map[string]any `json:"generationConfig"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if retryCalls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"message":"responseLogprobs not supported"}}`))
				return
			}
			if _, ok := body.GenerationConfig["responseLogprobs"]; ok {
				t.Fatalf("expected responseLogprobs stripped on retry")
			}
			if _, ok := body.GenerationConfig["logprobs"]; ok {
				t.Fatalf("expected logprobs stripped on retry")
			}
			_, _ = w.Write([]byte(`{
				"modelVersion": "gemini-2.5-flash",
				"candidates": [{"content": {"parts": [{"text": "ok"}]}}],
				"usageMetadata": {"promptTokenCount": 4200, "cachedContentTokenCount": 4096, "candidatesTokenCount": 1}
			}`))
		}))
		defer retrySrv.Close()

		retryRes := client.ExecuteProbe(context.Background(), ProbeTarget{
			Protocol: ProtocolGemini, BaseURL: retrySrv.URL, APIKey: "gem-secret",
		}, "gemini-2.5-flash", ProbeDefinition{ID: "lp1", Kind: DetectorLogprobs, Prompt: "hi", MaxTokens: 1}, true)
		if retryCalls != 2 || retryRes.ErrorCode != "" || retryRes.LogprobsSupported || retryRes.PromptTokens != 4200 {
			t.Fatalf("expected gemini retry success without logprobs, got calls=%d res=%+v", retryCalls, retryRes)
		}
	})
}

func TestDiscoverModelsAllProtocols(t *testing.T) {
	client := NewHTTPProbeClient(WithAllowLoopbackForTest())

	for _, proto := range []Protocol{ProtocolOpenAIChat, ProtocolOpenAIResponses, ProtocolAnthropic} {
		t.Run(string(proto), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
				_, _ = w.Write([]byte(`{"data":[{"id":"model-a"},{"id":"model-b"},{"id":"model-a"},{"id":" "}]}`))
			}))
			defer srv.Close()

			models, err := client.DiscoverModels(context.Background(), ProbeTarget{
				Protocol: proto, BaseURL: srv.URL, APIKey: "secret-disc",
			})
			if err != nil {
				t.Fatalf("DiscoverModels failed: %v", err)
			}
			if len(models) != 2 || models[0] != "model-a" || models[1] != "model-b" {
				t.Fatalf("unexpected discovered models: %v", models)
			}
		})
	}

	t.Run("anthropic_pagination_and_page_bound", func(t *testing.T) {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&calls, 1)
			after := r.URL.Query().Get("after_id")
			switch n {
			case 1:
				if after != "" {
					t.Fatalf("unexpected after_id on page 1: %q", after)
				}
				_, _ = w.Write([]byte(`{"data":[{"id":"claude-opus-4-6"}],"has_more":true,"last_id":"cur_1"}`))
			case 2:
				if after != "cur_1" {
					t.Fatalf("expected after_id=cur_1 on page 2, got %q", after)
				}
				_, _ = w.Write([]byte(`{"data":[{"id":"claude-sonnet-4-6"},{"id":"claude-opus-4-6"}],"has_more":true,"last_id":"cur_2"}`))
			case 3:
				if after != "cur_2" {
					t.Fatalf("expected after_id=cur_2 on page 3, got %q", after)
				}
				_, _ = w.Write([]byte(`{"data":[{"id":"claude-haiku-4-5"}],"has_more":false,"last_id":"cur_3"}`))
			default:
				t.Fatalf("unexpected extra page call %d", n)
			}
		}))
		defer srv.Close()

		models, err := client.DiscoverModels(context.Background(), ProbeTarget{
			Protocol: ProtocolAnthropic, BaseURL: srv.URL, APIKey: "ant-page-key",
		})
		if err != nil {
			t.Fatalf("DiscoverModels anthropic paginated failed: %v", err)
		}
		if len(models) != 3 || models[0] != "claude-opus-4-6" || models[1] != "claude-sonnet-4-6" || models[2] != "claude-haiku-4-5" {
			t.Fatalf("unexpected paginated anthropic models: %v", models)
		}

		// Verify infinite pagination stops at maxDiscoverModelPages (10).
		var loopCalls int32
		loopSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			idx := atomic.AddInt32(&loopCalls, 1)
			_, _ = fmt.Fprintf(w, `{"data":[{"id":"m-%d"}],"has_more":true,"last_id":"cur_%d"}`, idx, idx)
		}))
		defer loopSrv.Close()

		capped, err := client.DiscoverModels(context.Background(), ProbeTarget{
			Protocol: ProtocolAnthropic, BaseURL: loopSrv.URL, APIKey: "ant-loop-key",
		})
		if err != nil {
			t.Fatalf("DiscoverModels capped pagination failed: %v", err)
		}
		if loopCalls != maxDiscoverModelPages || len(capped) != maxDiscoverModelPages {
			t.Fatalf("expected exactly %d pages/models, got calls=%d len=%d", maxDiscoverModelPages, loopCalls, len(capped))
		}
	})

	t.Run("gemini_and_pagination", func(t *testing.T) {
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1beta/models" {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			if r.Header.Get("x-goog-api-key") != "gem-key" {
				t.Fatalf("missing x-goog-api-key")
			}
			n := atomic.AddInt32(&calls, 1)
			pageToken := r.URL.Query().Get("pageToken")
			switch n {
			case 1:
				if pageToken != "" {
					t.Fatalf("unexpected pageToken on first call: %q", pageToken)
				}
				_, _ = w.Write([]byte(`{
					"models": [
						{"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent", "countTokens"]},
						{"name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"]}
					],
					"nextPageToken": "tok_2"
				}`))
			case 2:
				if pageToken != "tok_2" {
					t.Fatalf("expected pageToken=tok_2, got %q", pageToken)
				}
				_, _ = w.Write([]byte(`{
					"models": [
						{"name": "models/gemini-2.5-flash"},
						{"name": "models/gemini-2.5-pro"}
					],
					"nextPageToken": "tok_3"
				}`))
			case 3:
				if pageToken != "tok_3" {
					t.Fatalf("expected pageToken=tok_3, got %q", pageToken)
				}
				_, _ = w.Write([]byte(`{
					"models": [
						{"name": "models/gemini-2.5-flash-lite", "supportedGenerationMethods": ["generateContent"]}
					]
				}`))
			default:
				t.Fatalf("unexpected extra gemini page call %d", n)
			}
		}))
		defer srv.Close()

		models, err := client.DiscoverModels(context.Background(), ProbeTarget{
			Protocol: ProtocolGemini, BaseURL: srv.URL, APIKey: "gem-key",
		})
		if err != nil {
			t.Fatalf("DiscoverModels gemini failed: %v", err)
		}
		if len(models) != 3 || models[0] != "gemini-2.5-pro" || models[1] != "gemini-2.5-flash" || models[2] != "gemini-2.5-flash-lite" {
			t.Fatalf("unexpected gemini models: %v", models)
		}
	})
}

func TestResponseBody256KBLimit(t *testing.T) {
	oversized := strings.Repeat("x", maxResponseBodyBytes+1024)
	validProbePrefix := `{"model":"gpt-4o","choices":[{"message":{"content":"ok"}}]}`
	validModelsPrefix := `{"data":[{"id":"gpt-4o"}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Mode") {
		case "error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"message":"boom sk-body-secret ` + oversized + `"}}`))
		case "trailing-spaces-over":
			if r.URL.Path == "/v1/models" {
				_, _ = w.Write([]byte(validModelsPrefix + strings.Repeat(" ", maxResponseBodyBytes+16-len(validModelsPrefix))))
				return
			}
			_, _ = w.Write([]byte(validProbePrefix + strings.Repeat(" ", maxResponseBodyBytes+16-len(validProbePrefix))))
		case "trailing-spaces-exact":
			if r.URL.Path == "/v1/models" {
				_, _ = w.Write([]byte(validModelsPrefix + strings.Repeat(" ", maxResponseBodyBytes-len(validModelsPrefix))))
				return
			}
			_, _ = w.Write([]byte(validProbePrefix + strings.Repeat(" ", maxResponseBodyBytes-len(validProbePrefix))))
		default:
			if r.URL.Path == "/v1/models" {
				_, _ = w.Write([]byte(`{"data":[{"id":"` + oversized + `"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"` + oversized + `"}}]}`))
		}
	}))
	defer srv.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	res200 := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-body-secret",
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if res200.ErrorCode != "upstream_error" || !strings.Contains(res200.ErrorMessage, "256 KiB") {
		t.Fatalf("expected oversized 200 body to fail with upstream_error (256 KiB limit), got %+v", res200)
	}

	// Complete valid JSON padded with trailing spaces > 256 KiB must still be rejected.
	resPadOver := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-body-secret",
		ExtraHeaders: map[string]string{"X-Mode": "trailing-spaces-over"},
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if resPadOver.ErrorCode != "upstream_error" || !strings.Contains(resPadOver.ErrorMessage, "256 KiB") {
		t.Fatalf("expected valid JSON + trailing spaces > 256 KiB to be rejected, got %+v", resPadOver)
	}
	if _, err := client.DiscoverModels(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-body-secret",
		ExtraHeaders: map[string]string{"X-Mode": "trailing-spaces-over"},
	}); err == nil || !strings.Contains(err.Error(), "256 KiB") {
		t.Fatalf("expected DiscoverModels valid JSON + trailing spaces > 256 KiB to fail, got %v", err)
	}

	// Exact 256 KiB response succeeds.
	resPadExact := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-body-secret",
		ExtraHeaders: map[string]string{"X-Mode": "trailing-spaces-exact"},
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if resPadExact.ErrorCode != "" || resPadExact.Text != "ok" {
		t.Fatalf("expected exact 256 KiB valid JSON to succeed, got %+v", resPadExact)
	}

	res500 := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-body-secret",
		ExtraHeaders: map[string]string{"X-Mode": "error"},
	}, "gpt-4o", ProbeDefinition{ID: "p1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 16}, false)
	if res500.ErrorCode != "upstream_error" || strings.Contains(res500.ErrorMessage, "sk-body-secret") || len(res500.ErrorMessage) > 1024 {
		t.Fatalf("expected redacted bounded 500 error, got %+v", res500)
	}

	if _, err := client.DiscoverModels(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: srv.URL, APIKey: "sk-body-secret",
	}); err == nil {
		t.Fatalf("expected oversized DiscoverModels response to return error")
	}

	// Oversized HTTP 400 response must be rejected immediately without triggering logprobs retry.
	var oversized400Calls atomic.Int32
	oversized400Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oversized400Calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"sk-body-secret ` + oversized + `"}}`))
	}))
	defer oversized400Srv.Close()

	res400 := client.ExecuteProbe(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat, BaseURL: oversized400Srv.URL, APIKey: "sk-body-secret",
	}, "gpt-4o", ProbeDefinition{ID: "lp1", Kind: DetectorLogprobs, Prompt: "hi", MaxTokens: 1}, true)
	if oversized400Calls.Load() != 1 {
		t.Fatalf("expected oversized 400 response not to retry, got %d calls", oversized400Calls.Load())
	}
	if res400.ErrorCode != "upstream_error" || !strings.Contains(res400.ErrorMessage, "256 KiB") || strings.Contains(res400.ErrorMessage, "sk-body-secret") {
		t.Fatalf("expected immediate 256 KiB limit error without secret leak, got %+v", res400)
	}
}

func TestDiscoverModelsSSRFAndRedaction(t *testing.T) {
	strictClient := NewHTTPProbeClient()
	if _, err := strictClient.DiscoverModels(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  "http://169.254.169.254",
		APIKey:   "sk-disc-secret",
	}); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("expected ErrSSRFBlocked from DiscoverModels, got %v", err)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"bad token sk-disc-secret"}}`))
	}))
	defer errSrv.Close()

	testClient := NewHTTPProbeClient(WithAllowLoopbackForTest())
	_, err := testClient.DiscoverModels(context.Background(), ProbeTarget{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  errSrv.URL,
		APIKey:   "sk-disc-secret",
	})
	if err == nil || strings.Contains(err.Error(), "sk-disc-secret") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("expected redacted error from DiscoverModels, got %v", err)
	}

	// Verify proxy transport setup and credential redaction on invalid proxy URL
	if _, trErr := newSSRFSafeTransport("http://user:proxy-pass@proxy.example.com:8080", false); trErr != nil {
		t.Fatalf("expected valid http proxy URL to configure transport, got %v", trErr)
	}
	if _, trErr := newSSRFSafeTransport("ftp://user:proxy-pass@proxy.example.com:21", false); trErr == nil || strings.Contains(trErr.Error(), "proxy-pass") {
		t.Fatalf("expected invalid proxy scheme error without password leak, got %v", trErr)
	}
}

func TestCustomExtraHeadersAlwaysRedacted(t *testing.T) {
	customPass := "my-custom-pass-99"
	tenantSecret := "tenant-route-tag-88"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":{"message":"rejected pass=%s route=%s"}}`, r.Header.Get("X-Relay-Pass"), r.Header.Get("X-Tenant-Route"))
	}))
	defer srv.Close()

	client := NewHTTPProbeClient(WithAllowLoopbackForTest())
	target := ProbeTarget{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  srv.URL,
		APIKey:   "sk-primary-1234",
		ExtraHeaders: map[string]string{
			"X-Relay-Pass":   customPass,
			"X-Tenant-Route": tenantSecret,
		},
	}

	probeRes := client.ExecuteProbe(context.Background(), target, "gpt-4o", ProbeDefinition{
		ID:        "lp-1",
		Kind:      DetectorLogprobs,
		Prompt:    "hi",
		MaxTokens: 1,
	}, true)
	if probeRes.ErrorCode != errorCodeAuthError {
		t.Fatalf("expected auth error, got %+v", probeRes)
	}
	if strings.Contains(probeRes.ErrorMessage, customPass) || strings.Contains(probeRes.ErrorMessage, tenantSecret) {
		t.Fatalf("expected custom header values scrubbed from ExecuteProbe error, got %q", probeRes.ErrorMessage)
	}
	if !strings.Contains(probeRes.ErrorMessage, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] marker in ExecuteProbe error, got %q", probeRes.ErrorMessage)
	}

	_, discErr := client.DiscoverModels(context.Background(), target)
	if discErr == nil {
		t.Fatalf("expected DiscoverModels to fail with 401")
	}
	if strings.Contains(discErr.Error(), customPass) || strings.Contains(discErr.Error(), tenantSecret) {
		t.Fatalf("expected custom header values scrubbed from DiscoverModels error, got %v", discErr)
	}
	if !strings.Contains(discErr.Error(), "[REDACTED]") {
		t.Fatalf("expected [REDACTED] marker in DiscoverModels error, got %v", discErr)
	}
}
