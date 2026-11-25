package modelfp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/geminicli"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai_compat"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Compile-time assertions verifying Sub2API's real repositories satisfy our narrow interfaces.
var (
	_ AccountLookup = (service.AccountRepository)(nil)
	_ ProxyLookup   = (service.ProxyRepository)(nil)
)

type stubAccountLookup struct {
	accounts map[int64]*service.Account
	err      error
}

func (s *stubAccountLookup) GetByID(_ context.Context, id int64) (*service.Account, error) {
	if s.err != nil {
		return nil, s.err
	}
	acc, ok := s.accounts[id]
	if !ok {
		return nil, service.ErrAccountNotFound
	}
	return acc, nil
}

type stubProxyLookup struct {
	proxies map[int64]*service.Proxy
	err     error
}

func (s *stubProxyLookup) GetByID(_ context.Context, id int64) (*service.Proxy, error) {
	if s.err != nil {
		return nil, s.err
	}
	p, ok := s.proxies[id]
	if !ok {
		return nil, service.ErrProxyNotFound
	}
	return p, nil
}

func testPublicLookup(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

func newTestResolver(accounts AccountLookup, proxies ProxyLookup, extraOpts ...ResolverOption) *TargetResolver {
	opts := append([]ResolverOption{withResolverLookupNetIPForTest(testPublicLookup)}, extraOpts...)
	return NewTargetResolverWithOptions(accounts, proxies, opts...)
}

func TestResolveAccountRejectsUnsupportedTypes(t *testing.T) {
	ctx := context.Background()
	parentID := int64(99)

	accounts := &stubAccountLookup{
		accounts: map[int64]*service.Account{
			1: {
				ID: 1, Name: "openai-oauth", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
				Credentials: map[string]any{"access_token": "tok"},
			},
			2: {
				ID: 2, Name: "anthropic-setup", Platform: service.PlatformAnthropic, Type: service.AccountTypeSetupToken,
				Credentials: map[string]any{"access_token": "tok"},
			},
			3: {
				ID: 3, Name: "shadow-apikey", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				ParentAccountID: &parentID,
				Credentials:     map[string]any{"api_key": "sk-shadow"},
			},
			4: {
				ID: 4, Name: "aws-bedrock", Platform: service.PlatformAnthropic, Type: service.AccountTypeBedrock,
				Credentials: map[string]any{"api_key": "br-key"},
			},
			5: {
				ID: 5, Name: "vertex-sa", Platform: service.PlatformAnthropic, Type: service.AccountTypeServiceAccount,
				Credentials: map[string]any{"project_id": "proj"},
			},
			6: {
				ID: 6, Name: "antigravity-key", Platform: service.PlatformAntigravity, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "ag-key", "base_url": "https://relay.example.com"},
			},
			7: {
				ID: 7, Name: "grok-key", Platform: service.PlatformGrok, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "xai-key"},
			},
			8: {
				ID: 8, Name: "opencode-go", Platform: service.PlatformOpenCodeGo, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "oc-key"},
			},
			9: {
				ID: 9, Name: "missing-key", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{},
			},
		},
	}

	resolver := newTestResolver(accounts, &stubProxyLookup{})

	for _, id := range []int64{1, 2, 3, 4, 5, 6, 7, 8} {
		_, err := resolver.ResolveAccount(ctx, id, "")
		if !errors.Is(err, ErrUnsupportedAccountType) {
			t.Fatalf("account #%d: expected ErrUnsupportedAccountType, got %v", id, err)
		}
		if code := infraerrors.Code(err); code != 400 {
			t.Fatalf("account #%d: expected HTTP 400, got %d", id, code)
		}
		if reason := infraerrors.Reason(err); reason != "MODELFP_UNSUPPORTED_ACCOUNT_TYPE" {
			t.Fatalf("account #%d: expected reason MODELFP_UNSUPPORTED_ACCOUNT_TYPE, got %q", id, reason)
		}
	}

	if _, err := resolver.ResolveAccount(ctx, 404, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account: expected ErrNotFound, got %v", err)
	}
	if _, err := resolver.ResolveAccount(ctx, 9, ""); err == nil || infraerrors.Code(err) != 400 {
		t.Fatalf("missing api_key: expected 400 error, got %v", err)
	}
	if _, err := resolver.ResolveAccount(ctx, 1, Protocol("invalid")); err == nil || infraerrors.Code(err) != 400 {
		t.Fatalf("invalid protocol override: expected 400 error, got %v", err)
	}
}

func TestResolveAccountAppliesMappingHeadersAndProxy(t *testing.T) {
	ctx := context.Background()
	proxyID := int64(42)
	rawSecret := "sk-account-secret-123456789"
	proxyPass := "super-proxy-pass-999"

	accounts := &stubAccountLookup{
		accounts: map[int64]*service.Account{
			7: {
				ID:       7,
				Name:     "GateAI",
				Platform: service.PlatformOpenAI,
				Type:     service.AccountTypeAPIKey,
				ProxyID:  &proxyID,
				Credentials: map[string]any{
					"api_key":  rawSecret,
					"base_url": "https://relay.example.com/v1/",
					"model_mapping": map[string]any{
						"gpt-4o":  "gpt-4o-2024-11-20",
						"gpt-5*":  "gpt-5-2025-08-07",
						"o3-mini": "o3-mini-2025-01-31",
						"bad-map": "",
					},
					"header_override_enabled": true,
					"header_overrides": map[string]any{
						"X-Custom-Tenant":     "tenant-42",
						"X-Trace-Source":      "modelfp",
						"Authorization":       "Bearer attacker-override",
						"x-api-key":           "attacker-key",
						"x-goog-api-key":      "attacker-goog-key",
						"Host":                "evil.example.com",
						"Connection":          "close",
						"Content-Length":      "999",
						"Transfer-Encoding":   "chunked",
						"Proxy-Authorization": "Basic dXNlcjpwYXNz",
					},
				},
				Extra: map[string]any{
					openai_compat.ExtraKeyResponsesSupported: false,
				},
			},
			8: {
				ID:       8,
				Name:     "NameWithSecret " + rawSecret + " and " + proxyPass,
				Platform: service.PlatformAnthropic,
				Type:     service.AccountTypeUpstream,
				ProxyID:  &proxyID,
				Credentials: map[string]any{
					"api_key":  rawSecret,
					"base_url": "https://anthropic-relay.example.com",
				},
			},
		},
	}

	proxies := &stubProxyLookup{
		proxies: map[int64]*service.Proxy{
			42: {
				ID:       42,
				Name:     "jp-egress",
				Protocol: "http",
				Host:     "proxy.example.com",
				Port:     8080,
				Username: "gwuser",
				Password: proxyPass,
				Status:   service.StatusActive,
			},
		},
	}

	resolver := newTestResolver(accounts, proxies)

	resolved, err := resolver.ResolveAccount(ctx, 7, "")
	if err != nil {
		t.Fatalf("ResolveAccount(7) failed: %v", err)
	}

	if resolved.Target.Source != TargetSourceAccount {
		t.Fatalf("expected source=%q, got %q", TargetSourceAccount, resolved.Target.Source)
	}
	if resolved.Target.AccountID == nil || *resolved.Target.AccountID != 7 {
		t.Fatalf("expected account_id=7, got %v", resolved.Target.AccountID)
	}
	if resolved.Target.Protocol != ProtocolOpenAIChat {
		t.Fatalf("expected protocol=%q, got %q", ProtocolOpenAIChat, resolved.Target.Protocol)
	}
	if resolved.Target.BaseURL != "https://relay.example.com/v1" {
		t.Fatalf("expected normalized BaseURL without trailing slash, got %q", resolved.Target.BaseURL)
	}
	if resolved.Target.APIKey != rawSecret {
		t.Fatalf("expected APIKey preserved on Target")
	}
	if resolved.Target.ProxyID == nil || *resolved.Target.ProxyID != 42 {
		t.Fatalf("expected ProxyID=42, got %v", resolved.Target.ProxyID)
	}
	if resolved.Target.ProxyURL != "http://gwuser:"+proxyPass+"@proxy.example.com:8080" {
		t.Fatalf("unexpected ProxyURL %q", resolved.Target.ProxyURL)
	}
	if resolved.TargetLabel != "account #7 (GateAI)" {
		t.Fatalf("expected TargetLabel %q, got %q", "account #7 (GateAI)", resolved.TargetLabel)
	}
	if strings.Contains(resolved.TargetLabel, rawSecret) || strings.Contains(resolved.TargetLabel, proxyPass) {
		t.Fatalf("TargetLabel leaked secrets: %q", resolved.TargetLabel)
	}

	// Non-blocked headers preserved; blocked auth/hop-by-hop headers stripped.
	if got := resolved.Target.ExtraHeaders["x-custom-tenant"]; got != "tenant-42" {
		t.Fatalf("expected x-custom-tenant=tenant-42, got %q (headers=%v)", got, resolved.Target.ExtraHeaders)
	}
	if got := resolved.Target.ExtraHeaders["x-trace-source"]; got != "modelfp" {
		t.Fatalf("expected x-trace-source=modelfp, got %q", got)
	}
	for _, blocked := range []string{"authorization", "x-api-key", "x-goog-api-key", "host", "connection", "content-length", "transfer-encoding", "proxy-authorization"} {
		if _, exists := resolved.Target.ExtraHeaders[blocked]; exists {
			t.Fatalf("blocked header %q must not be present in ExtraHeaders", blocked)
		}
	}

	// Verify MapAccountModel keeps exact, wildcard, and unmapped behavior while caller keeps claimed_model.
	if got := resolver.MapAccountModel(resolved, "gpt-4o"); got != "gpt-4o-2024-11-20" {
		t.Fatalf("expected exact mapping gpt-4o-2024-11-20, got %q", got)
	}
	if got := resolver.MapAccountModel(resolved, "gpt-5-mini"); got != "gpt-5-2025-08-07" {
		t.Fatalf("expected wildcard mapping gpt-5-2025-08-07, got %q", got)
	}
	if got := resolver.MapAccountModel(resolved, "gpt-4.1"); got != "gpt-4.1" {
		t.Fatalf("expected passthrough gpt-4.1, got %q", got)
	}

	// DefaultModels should list non-wildcard keys with non-empty targets cleanly.
	joinedDefaults := strings.Join(resolved.DefaultModels, ",")
	if !strings.Contains(joinedDefaults, "gpt-4o") || !strings.Contains(joinedDefaults, "o3-mini") || strings.Contains(joinedDefaults, "gpt-5*") || strings.Contains(joinedDefaults, "bad-map") {
		t.Fatalf("unexpected DefaultModels: %v", resolved.DefaultModels)
	}

	// Verify AccountTypeUpstream on Anthropic and label secret sanitization.
	upstreamRes, err := resolver.ResolveAccount(ctx, 8, "")
	if err != nil {
		t.Fatalf("ResolveAccount(8 upstream) failed: %v", err)
	}
	if upstreamRes.Target.Protocol != ProtocolAnthropic || upstreamRes.Target.BaseURL != "https://anthropic-relay.example.com" {
		t.Fatalf("unexpected upstream anthropic target: %+v", upstreamRes.Target)
	}
	if strings.Contains(upstreamRes.TargetLabel, rawSecret) || strings.Contains(upstreamRes.TargetLabel, proxyPass) {
		t.Fatalf("TargetLabel must scrub secrets even from account name, got %q", upstreamRes.TargetLabel)
	}
}

func TestResolveAccountInfersResponsesProtocol(t *testing.T) {
	ctx := context.Background()

	accounts := &stubAccountLookup{
		accounts: map[int64]*service.Account{
			10: {
				ID: 10, Name: "OpenAI-Default", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "sk-openai-1"},
				Extra:       map[string]any{openai_compat.ExtraKeyResponsesSupported: true},
			},
			11: {
				ID: 11, Name: "OpenAI-NoExtra", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "sk-openai-2"},
			},
			12: {
				ID: 12, Name: "OpenAI-CC", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "sk-openai-3"},
				Extra:       map[string]any{openai_compat.ExtraKeyResponsesSupported: false},
			},
			13: {
				ID: 13, Name: "Anthropic-Bearer", Platform: service.PlatformAnthropic, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "sk-ant-1"},
				Extra:       map[string]any{"anthropic_apikey_auth_scheme": service.AnthropicAPIKeyAuthSchemeAuthorizationBearer},
			},
			14: {
				ID: 14, Name: "Gemini-Direct", Platform: service.PlatformGemini, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "AIzaSyTestKey123456"},
			},
			15: {
				ID: 15, Name: "Kimi-Adaptive", Platform: service.PlatformKimi, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":      "sk-kimi-123456789",
					"account_mode": service.AccountModePayG,
					"api_protocol": service.APIProtocolAdaptive,
					"api_base_urls": map[string]any{
						service.APIProtocolChatCompletions: "https://custom-kimi.example.com/cc/v1",
						service.APIProtocolResponses:       "https://custom-kimi.example.com/resp/v1",
						service.APIProtocolAnthropic:       "https://custom-kimi.example.com/anth",
					},
				},
			},
			16: {
				ID: 16, Name: "Zhipu-Anthropic", Platform: service.PlatformZhipu, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":      "sk-zhipu-123456789",
					"api_protocol": service.APIProtocolAnthropic,
					"base_url":     "https://open.bigmodel.cn/api/anthropic",
				},
			},
			17: {
				ID: 17, Name: "DeepSeek-Responses", Platform: service.PlatformDeepseek, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":      "sk-ds-123456789",
					"api_protocol": service.APIProtocolResponses,
				},
			},
			18: {
				ID: 18, Name: "MiniMax-CC", Platform: service.PlatformMiniMax, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key": "sk-mm-123456789",
				},
			},
			19: {
				ID: 19, Name: "DeepSeek-Versioned-Responses", Platform: service.PlatformDeepseek, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":      "sk-ds-v1-123456789",
					"api_protocol": service.APIProtocolResponses,
					"base_url":     "https://relay.example.com/v1",
				},
			},
		},
	}

	resolver := newTestResolver(accounts, &stubProxyLookup{})

	// OpenAI with ShouldUseResponsesAPI == true -> ProtocolOpenAIResponses
	for _, id := range []int64{10, 11} {
		res, err := resolver.ResolveAccount(ctx, id, "")
		if err != nil {
			t.Fatalf("account #%d failed: %v", id, err)
		}
		if res.Target.Protocol != ProtocolOpenAIResponses {
			t.Fatalf("account #%d: expected %q, got %q", id, ProtocolOpenAIResponses, res.Target.Protocol)
		}
		if res.Target.BaseURL != "https://api.openai.com" {
			t.Fatalf("account #%d: expected default OpenAI BaseURL, got %q", id, res.Target.BaseURL)
		}
	}

	// Explicit protocolOverride overrides inferred default.
	overridden, err := resolver.ResolveAccount(ctx, 10, ProtocolOpenAIChat)
	if err != nil {
		t.Fatalf("override failed: %v", err)
	}
	if overridden.Target.Protocol != ProtocolOpenAIChat {
		t.Fatalf("expected overridden protocol %q, got %q", ProtocolOpenAIChat, overridden.Target.Protocol)
	}

	// OpenAI probed false -> ProtocolOpenAIChat, override to Responses works.
	ccRes, err := resolver.ResolveAccount(ctx, 12, "")
	if err != nil {
		t.Fatalf("account #12 failed: %v", err)
	}
	if ccRes.Target.Protocol != ProtocolOpenAIChat {
		t.Fatalf("expected %q, got %q", ProtocolOpenAIChat, ccRes.Target.Protocol)
	}
	respOverride, err := resolver.ResolveAccount(ctx, 12, ProtocolOpenAIResponses)
	if err != nil {
		t.Fatalf("account #12 override failed: %v", err)
	}
	if respOverride.Target.Protocol != ProtocolOpenAIResponses {
		t.Fatalf("expected %q, got %q", ProtocolOpenAIResponses, respOverride.Target.Protocol)
	}

	// Anthropic bearer scheme
	antRes, err := resolver.ResolveAccount(ctx, 13, "")
	if err != nil {
		t.Fatalf("account #13 failed: %v", err)
	}
	if antRes.Target.Protocol != ProtocolAnthropic || antRes.Target.AuthMode != "bearer" || antRes.Target.BaseURL != "https://api.anthropic.com" {
		t.Fatalf("unexpected anthropic resolved target: %+v", antRes.Target)
	}

	// Gemini default base URL
	gemRes, err := resolver.ResolveAccount(ctx, 14, "")
	if err != nil {
		t.Fatalf("account #14 failed: %v", err)
	}
	if gemRes.Target.Protocol != ProtocolGemini || gemRes.Target.BaseURL != geminicli.AIStudioBaseURL {
		t.Fatalf("unexpected gemini resolved target: %+v", gemRes.Target)
	}

	// CN providers: adaptive defaults to openai_chat and respects split protocol URLs on override
	kimiDefault, err := resolver.ResolveAccount(ctx, 15, "")
	if err != nil {
		t.Fatalf("kimi default failed: %v", err)
	}
	if kimiDefault.Target.Protocol != ProtocolOpenAIChat || kimiDefault.Target.BaseURL != "https://custom-kimi.example.com/cc/v1" {
		t.Fatalf("unexpected kimi default: %+v", kimiDefault.Target)
	}
	kimiResp, err := resolver.ResolveAccount(ctx, 15, ProtocolOpenAIResponses)
	if err != nil {
		t.Fatalf("kimi responses override failed: %v", err)
	}
	if kimiResp.Target.BaseURL != "https://custom-kimi.example.com/resp/v1" {
		t.Fatalf("expected kimi responses URL, got %q", kimiResp.Target.BaseURL)
	}
	kimiAnth, err := resolver.ResolveAccount(ctx, 15, ProtocolAnthropic)
	if err != nil {
		t.Fatalf("kimi anthropic override failed: %v", err)
	}
	if kimiAnth.Target.BaseURL != "https://custom-kimi.example.com/anth" {
		t.Fatalf("expected kimi anthropic URL, got %q", kimiAnth.Target.BaseURL)
	}

	// Zhipu Anthropic protocol vs CC override uses GetOpenAIFormatBaseURL (not the /anthropic URL!)
	zhipuDefault, err := resolver.ResolveAccount(ctx, 16, "")
	if err != nil {
		t.Fatalf("zhipu default failed: %v", err)
	}
	if zhipuDefault.Target.Protocol != ProtocolAnthropic || zhipuDefault.Target.BaseURL != "https://open.bigmodel.cn/api/anthropic" {
		t.Fatalf("unexpected zhipu anthropic target: %+v", zhipuDefault.Target)
	}
	zhipuCC, err := resolver.ResolveAccount(ctx, 16, ProtocolOpenAIChat)
	if err != nil {
		t.Fatalf("zhipu cc override failed: %v", err)
	}
	if zhipuCC.Target.BaseURL != service.DefaultZhipuPayGBaseURL {
		t.Fatalf("expected zhipu CC fallback URL %q, got %q", service.DefaultZhipuPayGBaseURL, zhipuCC.Target.BaseURL)
	}

	// DeepSeek responses & MiniMax chat_completions
	dsRes, err := resolver.ResolveAccount(ctx, 17, "")
	if err != nil {
		t.Fatalf("deepseek failed: %v", err)
	}
	if dsRes.Target.Protocol != ProtocolOpenAIResponses || dsRes.Target.BaseURL != service.DefaultDeepseekBaseURL+"/responses" {
		t.Fatalf("unexpected deepseek target: %+v", dsRes.Target)
	}
	dsV1Res, err := resolver.ResolveAccount(ctx, 19, "")
	if err != nil {
		t.Fatalf("deepseek versioned responses failed: %v", err)
	}
	if dsV1Res.Target.Protocol != ProtocolOpenAIResponses || dsV1Res.Target.BaseURL != "https://relay.example.com/v1" {
		t.Fatalf("expected versioned deepseek base URL unchanged, got %+v", dsV1Res.Target)
	}
	mmRes, err := resolver.ResolveAccount(ctx, 18, "")
	if err != nil {
		t.Fatalf("minimax failed: %v", err)
	}
	if mmRes.Target.Protocol != ProtocolOpenAIChat || mmRes.Target.BaseURL != service.DefaultMiniMaxBaseURL {
		t.Fatalf("unexpected minimax target: %+v", mmRes.Target)
	}
}

func TestResolveAdHocUsesProxyIDOnlyAndMasksLabel(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	past := now.Add(-1 * time.Hour)
	future := now.Add(24 * time.Hour)

	activeProxyID := int64(11)
	inactiveProxyID := int64(12)
	expiredProxyID := int64(13)
	missingProxyID := int64(999)
	badProxyID := int64(0)

	proxies := &stubProxyLookup{
		proxies: map[int64]*service.Proxy{
			11: {
				ID: 11, Name: "active-socks", Protocol: "socks5", Host: "198.51.100.10", Port: 1080,
				Username: "alice", Password: "proxy-secret-password", Status: service.StatusActive, ExpiresAt: &future,
			},
			12: {
				ID: 12, Name: "disabled", Protocol: "http", Host: "198.51.100.11", Port: 8080,
				Status: service.StatusDisabled,
			},
			13: {
				ID: 13, Name: "expired", Protocol: "http", Host: "198.51.100.12", Port: 8080,
				Status: service.StatusActive, ExpiresAt: &past,
			},
		},
	}

	resolver := newTestResolver(&stubAccountLookup{}, proxies, withResolverNowForTest(func() time.Time { return now }))

	rawKey := "sk-123456789"
	res, err := resolver.ResolveAdHoc(ctx, AdHocTargetInput{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  "https://api.example.com/v1/",
		APIKey:   rawKey,
		ProxyID:  &activeProxyID,
		ExtraHeaders: map[string]string{
			"X-Custom-Header":     "custom-val",
			"Authorization":       "Bearer hijack",
			"x-api-key":           "hijack-key",
			"Host":                "hijack.example.com",
			"Connection":          "keep-alive",
			"Proxy-Authorization": "Basic hijack",
			"X-Bad-CRLF":          "foo\r\nbar",
		},
	})
	if err != nil {
		t.Fatalf("ResolveAdHoc active proxy failed: %v", err)
	}

	if res.Target.Source != TargetSourceAdHoc {
		t.Fatalf("expected source=%q, got %q", TargetSourceAdHoc, res.Target.Source)
	}
	if res.Target.BaseURL != "https://api.example.com/v1" {
		t.Fatalf("expected trimmed BaseURL, got %q", res.Target.BaseURL)
	}
	if res.Target.ProxyID == nil || *res.Target.ProxyID != 11 {
		t.Fatalf("expected ProxyID=11, got %v", res.Target.ProxyID)
	}
	if res.Target.ProxyURL != "socks5h://alice:proxy-secret-password@198.51.100.10:1080" {
		t.Fatalf("expected socks5h upgraded ProxyURL, got %q", res.Target.ProxyURL)
	}
	if res.TargetLabel != "adhoc https://api.example.com (sk-12***89)" {
		t.Fatalf("expected TargetLabel %q, got %q", "adhoc https://api.example.com (sk-12***89)", res.TargetLabel)
	}
	if strings.Contains(res.TargetLabel, rawKey) || strings.Contains(res.TargetLabel, "proxy-secret-password") {
		t.Fatalf("TargetLabel leaked secret: %q", res.TargetLabel)
	}
	if got := res.Target.ExtraHeaders["X-Custom-Header"]; got != "custom-val" {
		t.Fatalf("expected X-Custom-Header preserved, got %q (all=%v)", got, res.Target.ExtraHeaders)
	}
	for _, blocked := range []string{"Authorization", "authorization", "x-api-key", "Host", "Connection", "Proxy-Authorization", "X-Bad-CRLF"} {
		if _, ok := res.Target.ExtraHeaders[blocked]; ok {
			t.Fatalf("blocked header %q must be stripped", blocked)
		}
	}

	// Reject inactive, expired, missing, and non-positive proxy_id.
	for _, tc := range []struct {
		name    string
		proxyID *int64
	}{
		{name: "inactive", proxyID: &inactiveProxyID},
		{name: "expired", proxyID: &expiredProxyID},
		{name: "missing", proxyID: &missingProxyID},
		{name: "non-positive", proxyID: &badProxyID},
	} {
		_, err := resolver.ResolveAdHoc(ctx, AdHocTargetInput{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://api.example.com",
			APIKey:   rawKey,
			ProxyID:  tc.proxyID,
		})
		if err == nil || infraerrors.Code(err) != 400 {
			t.Fatalf("%s proxy: expected 400 rejection, got %v", tc.name, err)
		}
		if strings.Contains(err.Error(), rawKey) || strings.Contains(err.Error(), "proxy-secret-password") {
			t.Fatalf("%s proxy error leaked secret: %v", tc.name, err)
		}
	}

	// Verify SSRF rejection when allowLoopback is false, and allowLoopback opt-in for httptest.
	for _, badURL := range []string{
		"http://127.0.0.1:8080",
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.1/v1",
		"http://localhost/v1",
		"https://user:pass@api.example.com",
		"https://api.example.com/v1?x=1",
		"ftp://api.example.com",
	} {
		if _, err := resolver.ResolveAdHoc(ctx, AdHocTargetInput{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  badURL,
			APIKey:   rawKey,
		}); !errors.Is(err, ErrSSRFBlocked) {
			t.Fatalf("expected ErrSSRFBlocked for %q, got %v", badURL, err)
		}
	}

	loopbackResolver := newTestResolver(&stubAccountLookup{}, proxies, WithResolverAllowLoopbackForTest())
	loopRes, err := loopbackResolver.ResolveAdHoc(ctx, AdHocTargetInput{
		Protocol: ProtocolAnthropic,
		BaseURL:  "http://127.0.0.1:18080",
		APIKey:   "short",
		AuthMode: "bearer",
	})
	if err != nil {
		t.Fatalf("loopback test resolver failed: %v", err)
	}
	if loopRes.Target.AuthMode != "bearer" {
		t.Fatalf("expected authMode=bearer, got %q", loopRes.Target.AuthMode)
	}
	if loopRes.TargetLabel != "adhoc http://127.0.0.1:18080 (***)" {
		t.Fatalf("expected short key fully masked as ***, got %q", loopRes.TargetLabel)
	}
	if _, err := loopbackResolver.ResolveAdHoc(ctx, AdHocTargetInput{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  "http://169.254.169.254/latest",
		APIKey:   rawKey,
	}); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("loopback test option must still block metadata IP, got %v", err)
	}

	// Verify validation errors and error propagation on ResolveAdHoc.
	for _, tc := range []struct {
		name  string
		input AdHocTargetInput
	}{
		{name: "empty api_key", input: AdHocTargetInput{Protocol: ProtocolOpenAIChat, BaseURL: "https://api.example.com", APIKey: "   "}},
		{name: "empty protocol", input: AdHocTargetInput{BaseURL: "https://api.example.com", APIKey: rawKey}},
		{name: "bad protocol", input: AdHocTargetInput{Protocol: Protocol("grpc"), BaseURL: "https://api.example.com", APIKey: rawKey}},
		{name: "bad auth_mode", input: AdHocTargetInput{Protocol: ProtocolAnthropic, BaseURL: "https://api.example.com", APIKey: rawKey, AuthMode: "basic"}},
	} {
		if _, err := resolver.ResolveAdHoc(ctx, tc.input); err == nil || infraerrors.Code(err) != 400 {
			t.Fatalf("%s: expected 400 error, got %v", tc.name, err)
		}
	}

	dbErr := errors.New("proxy db connection refused")
	errResolver := newTestResolver(&stubAccountLookup{}, &stubProxyLookup{err: dbErr})
	if _, err := errResolver.ResolveAdHoc(ctx, AdHocTargetInput{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  "https://api.example.com",
		APIKey:   rawKey,
		ProxyID:  &activeProxyID,
	}); !errors.Is(err, dbErr) {
		t.Fatalf("expected proxy lookup dbErr propagated, got %v", err)
	}
}

func TestTargetResolverEdgeCasesAndDefaultConstructor(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	inactivePID := int64(21)
	expiredPID := int64(22)

	accounts := &stubAccountLookup{
		accounts: map[int64]*service.Account{
			1: {
				ID: 1, Name: "LiteralPublicIP", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":  "sk-literal-123456789",
					"base_url": "https://93.184.216.34/v1/",
				},
			},
			2: {
				ID: 2, Name: "LoopbackBlocked", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":  "sk-loop-123456789",
					"base_url": "http://127.0.0.1:8080/v1",
				},
			},
			3: {
				ID: 3, Name: "InactiveProxyAccount", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				ProxyID:     &inactivePID,
				Credentials: map[string]any{"api_key": "sk-p1-123456789", "base_url": "https://93.184.216.34"},
			},
			4: {
				ID: 4, Name: "PreloadedExpiredProxy", Platform: service.PlatformGemini, Type: service.AccountTypeAPIKey,
				ProxyID: &expiredPID,
				Proxy: &service.Proxy{
					ID: expiredPID, Protocol: "http", Host: "198.51.100.20", Port: 8080,
					Status: service.StatusActive, ExpiresAt: &past,
				},
				Credentials: map[string]any{
					"api_key":  "AIzaTestKey123456789",
					"base_url": "https://93.184.216.34",
					"model_mapping": map[string]any{
						"gemini-3.1-pro-preview": "gemini-2.5-pro",
					},
				},
			},
			5: {
				ID: 5, Name: "OllamaAnthropic", Platform: service.PlatformAnthropic, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":  "sk-ollama-123456789",
					"base_url": "https://ollama.com",
				},
			},
		},
	}
	proxies := &stubProxyLookup{
		proxies: map[int64]*service.Proxy{
			inactivePID: {
				ID: inactivePID, Protocol: "http", Host: "198.51.100.19", Port: 8080,
				Status: service.StatusDisabled,
			},
		},
	}

	// Default 2-arg constructor enforces ValidateBaseURL without test options.
	defaultResolver := NewTargetResolver(accounts, proxies)
	res1, err := defaultResolver.ResolveAccount(ctx, 1, "")
	if err != nil {
		t.Fatalf("defaultResolver.ResolveAccount(1) failed: %v", err)
	}
	if res1.Target.BaseURL != "https://93.184.216.34/v1" {
		t.Fatalf("unexpected BaseURL %q", res1.Target.BaseURL)
	}
	if _, err := defaultResolver.ResolveAccount(ctx, 2, ""); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("defaultResolver must block loopback account base_url, got %v", err)
	}
	if _, err := defaultResolver.ResolveAccount(ctx, 3, ""); err == nil || infraerrors.Code(err) != 400 {
		t.Fatalf("expected 400 for inactive account proxy, got %v", err)
	}

	// Preloaded expired proxy should be rejected even with proxies=nil.
	preloadedOnly := NewTargetResolverWithOptions(accounts, nil, withResolverLookupNetIPForTest(testPublicLookup), withResolverNowForTest(func() time.Time { return now }))
	if _, err := preloadedOnly.ResolveAccount(ctx, 4, ""); err == nil || infraerrors.Code(err) != 400 {
		t.Fatalf("expected 400 for preloaded expired proxy, got %v", err)
	}

	// Ollama Cloud Anthropic endpoint forces bearer auth mode.
	ollamaRes, err := newTestResolver(accounts, proxies).ResolveAccount(ctx, 5, "")
	if err != nil {
		t.Fatalf("ollama ResolveAccount failed: %v", err)
	}
	if ollamaRes.Target.AuthMode != "bearer" {
		t.Fatalf("expected bearer auth_mode for ollama.com, got %q", ollamaRes.Target.AuthMode)
	}

	// Gemini customtools lookup normalization and nil safety in MapAccountModel.
	gemTarget := &ResolvedTarget{
		ModelMapping: map[string]string{"gemini-3.1-pro-preview": "gemini-2.5-pro"},
		platform:     service.PlatformGemini,
	}
	if got := defaultResolver.MapAccountModel(gemTarget, "gemini-3.1-pro-preview-customtools"); got != "gemini-2.5-pro" {
		t.Fatalf("expected gemini customtools normalized mapping, got %q", got)
	}
	if got := (*TargetResolver)(nil).MapAccountModel(nil, " gpt-4o "); got != "gpt-4o" {
		t.Fatalf("expected nil-safe passthrough, got %q", got)
	}

	// AccountLookup unexpected error should propagate directly.
	dbErr := errors.New("account store unavailable")
	errResolver := newTestResolver(&stubAccountLookup{err: dbErr}, proxies)
	if _, err := errResolver.ResolveAccount(ctx, 1, ""); !errors.Is(err, dbErr) {
		t.Fatalf("expected account dbErr propagated, got %v", err)
	}

	// Unhydrated (ID == 0) or mismatched preloaded account.Proxy must fall back to ProxyLookup.
	fallbackProxyID := int64(31)
	mismatchedProxyID := int64(32)
	fallbackProxies := &stubProxyLookup{
		proxies: map[int64]*service.Proxy{
			fallbackProxyID: {
				ID: fallbackProxyID, Protocol: "http", Host: "198.51.100.31", Port: 8080, Status: service.StatusActive,
			},
			mismatchedProxyID: {
				ID: mismatchedProxyID, Protocol: "http", Host: "198.51.100.32", Port: 8081, Status: service.StatusDisabled,
			},
		},
	}
	preloadedFallbackAccounts := &stubAccountLookup{
		accounts: map[int64]*service.Account{
			101: {
				ID: 101, Name: "ZeroIDPreload", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				ProxyID: &fallbackProxyID,
				Proxy: &service.Proxy{
					ID: 0, Protocol: "http", Host: "198.51.100.99", Port: 9999, Status: service.StatusActive,
				},
				Credentials: map[string]any{"api_key": "sk-zero-123456789", "base_url": "https://93.184.216.34"},
			},
			102: {
				ID: 102, Name: "MismatchedIDPreload", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				ProxyID: &mismatchedProxyID,
				Proxy: &service.Proxy{
					ID: 999, Protocol: "http", Host: "198.51.100.99", Port: 9999, Status: service.StatusActive,
				},
				Credentials: map[string]any{"api_key": "sk-mismatch-123456789", "base_url": "https://93.184.216.34"},
			},
		},
	}
	fallbackResolver := newTestResolver(preloadedFallbackAccounts, fallbackProxies)
	zeroRes, err := fallbackResolver.ResolveAccount(ctx, 101, "")
	if err != nil {
		t.Fatalf("zero-id preloaded proxy fallback failed: %v", err)
	}
	if zeroRes.Target.ProxyURL != "http://198.51.100.31:8080" {
		t.Fatalf("expected ProxyLookup URL http://198.51.100.31:8080, got %q", zeroRes.Target.ProxyURL)
	}
	if _, err := fallbackResolver.ResolveAccount(ctx, 102, ""); err == nil || infraerrors.Code(err) != 400 {
		t.Fatalf("mismatched preloaded proxy should fall back to ProxyLookup (disabled) and return 400, got %v", err)
	}
}
