package modelfp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/geminicli"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai_compat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"golang.org/x/net/http/httpguts"
)

const defaultAnthropicBaseURL = "https://api.anthropic.com"

// AccountLookup provides read-only account retrieval satisfied by service.AccountRepository.
type AccountLookup interface {
	GetByID(ctx context.Context, id int64) (*service.Account, error)
}

// ProxyLookup provides read-only proxy retrieval satisfied by service.ProxyRepository.
type ProxyLookup interface {
	GetByID(ctx context.Context, id int64) (*service.Proxy, error)
}

// AdHocTargetInput captures administrator-supplied temporary upstream credentials.
// Only pre-configured proxy_id values are accepted; free-form proxy_url strings are forbidden.
type AdHocTargetInput struct {
	Protocol     Protocol          `json:"protocol"`
	BaseURL      string            `json:"base_url"`
	APIKey       string            `json:"api_key"`
	AuthMode     string            `json:"auth_mode,omitempty"`
	ProxyID      *int64            `json:"proxy_id,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// ResolvedTarget holds a validated ProbeTarget along with secret-free display metadata
// and account model-mapping state.
type ResolvedTarget struct {
	Target        ProbeTarget
	TargetLabel   string
	DefaultModels []string
	ModelMapping  map[string]string
	platform      string
}

// ResolverOption configures optional behavior on TargetResolver (primarily for unit tests).
type ResolverOption func(*TargetResolver)

// WithResolverAllowLoopbackForTest allows loopback hosts/IPs solely for httptest.Server unit tests.
func WithResolverAllowLoopbackForTest() ResolverOption {
	return func(r *TargetResolver) {
		r.allowLoopback = true
	}
}

func withResolverLookupNetIPForTest(fn lookupNetIPFunc) ResolverOption {
	return func(r *TargetResolver) {
		r.lookupFn = fn
	}
}

func withResolverNowForTest(fn func() time.Time) ResolverOption {
	return func(r *TargetResolver) {
		r.now = fn
	}
}

// TargetResolver resolves ad-hoc inputs and standalone REST API-key accounts into validated ProbeTargets.
type TargetResolver struct {
	accounts      AccountLookup
	proxies       ProxyLookup
	allowLoopback bool
	lookupFn      lookupNetIPFunc
	now           func() time.Time
}

// NewTargetResolver creates a TargetResolver backed by read-only AccountLookup and ProxyLookup ports.
func NewTargetResolver(accounts AccountLookup, proxies ProxyLookup) *TargetResolver {
	return NewTargetResolverWithOptions(accounts, proxies)
}

// NewTargetResolverWithOptions creates a TargetResolver with optional test/runtime overrides.
func NewTargetResolverWithOptions(accounts AccountLookup, proxies ProxyLookup, opts ...ResolverOption) *TargetResolver {
	r := &TargetResolver{
		accounts: accounts,
		proxies:  proxies,
		now:      time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

var blockedResolverHeaders = map[string]struct{}{
	"host":                {},
	"content-length":      {},
	"content-type":        {},
	"transfer-encoding":   {},
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"upgrade":             {},
	"authorization":       {},
	"x-api-key":           {},
	"x-goog-api-key":      {},
	"cookie":              {},
	"accept-encoding":     {},
}

var allowedResolverPlatforms = map[string]struct{}{
	service.PlatformOpenAI:    {},
	service.PlatformAnthropic: {},
	service.PlatformGemini:    {},
	service.PlatformKimi:      {},
	service.PlatformZhipu:     {},
	service.PlatformDeepseek:  {},
	service.PlatformMiniMax:   {},
}

// ResolveAdHoc validates temporary upstream coordinates and optional proxy_id, producing a
// ProbeTarget and a secret-free TargetLabel.
func (r *TargetResolver) ResolveAdHoc(ctx context.Context, input AdHocTargetInput) (*ResolvedTarget, error) {
	if r == nil {
		return nil, errors.New("target resolver is nil")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	proto, err := normalizeSupportedProtocol(input.Protocol, false)
	if err != nil {
		return nil, err
	}

	apiKey := strings.TrimSpace(input.APIKey)
	if apiKey == "" {
		return nil, infraerrors.BadRequest("MODELFP_MISSING_API_KEY", "api_key is required")
	}

	authMode, err := normalizeAdHocAuthMode(input.AuthMode)
	if err != nil {
		return nil, err
	}

	parsedURL, err := validateBaseURLWithLookup(ctx, input.BaseURL, r.allowLoopback, r.lookupFn)
	if err != nil {
		return nil, err
	}

	proxyID, proxyURL, _, err := r.resolveProxy(ctx, input.ProxyID, nil)
	if err != nil {
		return nil, err
	}

	headers := sanitizeHeaderMap(input.ExtraHeaders, false)
	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	label := fmt.Sprintf("adhoc %s (%s)", origin, maskAPIKey(apiKey))

	return &ResolvedTarget{
		Target: ProbeTarget{
			Source:       TargetSourceAdHoc,
			Protocol:     proto,
			BaseURL:      parsedURL.String(),
			APIKey:       apiKey,
			AuthMode:     authMode,
			ProxyID:      proxyID,
			ProxyURL:     proxyURL,
			ExtraHeaders: headers,
		},
		TargetLabel: label,
	}, nil
}

// ResolveAccount loads an existing Sub2API account read-only, enforces standalone REST API-key
// eligibility, resolves protocol/base URL/headers/mapping/proxy, and masks any secrets in TargetLabel.
func (r *TargetResolver) ResolveAccount(ctx context.Context, accountID int64, protocolOverride Protocol) (*ResolvedTarget, error) {
	if r == nil || r.accounts == nil {
		return nil, errors.New("account lookup is not configured")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if accountID <= 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_ACCOUNT_ID", "account_id must be positive")
	}

	overrideProto, err := normalizeSupportedProtocol(protocolOverride, true)
	if err != nil {
		return nil, err
	}

	account, err := r.accounts.GetByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, service.ErrAccountNotFound) || infraerrors.Code(err) == http.StatusNotFound {
			return nil, ErrNotFound.WithCause(err)
		}
		return nil, err
	}
	if account == nil {
		return nil, ErrNotFound
	}

	if err := validateAccountEligible(account); err != nil {
		return nil, err
	}

	proto := resolveAccountProtocol(account, overrideProto)
	apiKey := extractAccountAPIKey(account)
	if apiKey == "" {
		return nil, infraerrors.BadRequest("MODELFP_MISSING_API_KEY", fmt.Sprintf("account #%d has no api_key configured", account.ID))
	}

	rawBaseURL := extractAccountBaseURL(account, proto)
	parsedURL, err := validateBaseURLWithLookup(ctx, rawBaseURL, r.allowLoopback, r.lookupFn)
	if err != nil {
		return nil, err
	}

	proxyID, proxyURL, proxyPassword, err := r.resolveProxy(ctx, account.ProxyID, account.Proxy)
	if err != nil {
		return nil, err
	}

	authMode := resolveAccountAuthMode(account, proto, parsedURL)
	headers := sanitizeHeaderMap(account.GetHeaderOverrides(), true)
	modelMapping := cloneStringMap(account.GetModelMapping())
	platform := strings.ToLower(strings.TrimSpace(account.Platform))
	defaultModels := resolveAccountDefaultModels(platform, modelMapping)

	accIDCopy := account.ID
	label := formatAccountLabel(account.ID, account.Name, apiKey, proxyPassword)

	return &ResolvedTarget{
		Target: ProbeTarget{
			Source:       TargetSourceAccount,
			AccountID:    &accIDCopy,
			Protocol:     proto,
			BaseURL:      parsedURL.String(),
			APIKey:       apiKey,
			AuthMode:     authMode,
			ProxyID:      proxyID,
			ProxyURL:     proxyURL,
			ExtraHeaders: headers,
		},
		TargetLabel:   label,
		DefaultModels: defaultModels,
		ModelMapping:  modelMapping,
		platform:      platform,
	}, nil
}

// MapAccountModel translates claimedModel to the effective upstream model configured on resolved
// (exact match first, then longest-prefix wildcard match) while callers retain claimedModel separately.
func (r *TargetResolver) MapAccountModel(resolved *ResolvedTarget, claimedModel string) string {
	trimmed := strings.TrimSpace(claimedModel)
	if trimmed == "" || resolved == nil || len(resolved.ModelMapping) == 0 {
		return trimmed
	}
	if mapped, ok := resolveModelMappingMatch(resolved.ModelMapping, trimmed); ok {
		return mapped
	}
	if resolved.platform == service.PlatformGemini && trimmed == "gemini-3.1-pro-preview-customtools" {
		if mapped, ok := resolveModelMappingMatch(resolved.ModelMapping, "gemini-3.1-pro-preview"); ok {
			return mapped
		}
	}
	return trimmed
}

func (r *TargetResolver) currentTime() time.Time {
	if r != nil && r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *TargetResolver) resolveProxy(
	ctx context.Context,
	proxyID *int64,
	preloaded *service.Proxy,
) (*int64, string, string, error) {
	if proxyID == nil {
		return nil, "", "", nil
	}
	if *proxyID <= 0 {
		return nil, "", "", infraerrors.BadRequest("MODELFP_INVALID_PROXY", "proxy_id must be positive")
	}

	var proxy *service.Proxy
	if preloaded != nil && preloaded.ID == *proxyID {
		proxy = preloaded
	} else {
		if r.proxies == nil {
			return nil, "", "", errors.New("proxy lookup is not configured")
		}
		loaded, err := r.proxies.GetByID(ctx, *proxyID)
		if err != nil {
			if errors.Is(err, service.ErrProxyNotFound) || infraerrors.Code(err) == http.StatusNotFound {
				return nil, "", "", infraerrors.BadRequest("MODELFP_INVALID_PROXY", fmt.Sprintf("proxy #%d not found", *proxyID))
			}
			return nil, "", "", err
		}
		if loaded == nil {
			return nil, "", "", infraerrors.BadRequest("MODELFP_INVALID_PROXY", fmt.Sprintf("proxy #%d not found", *proxyID))
		}
		proxy = loaded
	}

	if !proxy.IsActive() {
		return nil, "", "", infraerrors.BadRequest("MODELFP_PROXY_UNAVAILABLE", fmt.Sprintf("proxy #%d is not active", *proxyID))
	}
	if proxy.IsExpired(r.currentTime()) {
		return nil, "", "", infraerrors.BadRequest("MODELFP_PROXY_UNAVAILABLE", fmt.Sprintf("proxy #%d has expired", *proxyID))
	}

	rawProxyURL := strings.TrimSpace(proxy.URL())
	normalizedURL, parsedProxy, err := proxyurl.Parse(rawProxyURL)
	if err != nil || parsedProxy == nil {
		return nil, "", "", infraerrors.BadRequest("MODELFP_PROXY_UNAVAILABLE", fmt.Sprintf("proxy #%d has invalid URL configuration", *proxyID))
	}

	idCopy := *proxyID
	proxyPassword := proxy.Password
	if proxyPassword == "" && parsedProxy.User != nil {
		if pw, ok := parsedProxy.User.Password(); ok {
			proxyPassword = pw
		}
	}
	return &idCopy, normalizedURL, proxyPassword, nil
}

func validateAccountEligible(account *service.Account) error {
	if account.ParentAccountID != nil {
		return infraerrors.BadRequest(
			ErrUnsupportedAccountType.Reason,
			"shadow accounts are not supported; select the standalone parent API key account",
		)
	}

	accountType := strings.ToLower(strings.TrimSpace(account.Type))
	if accountType != service.AccountTypeAPIKey && accountType != service.AccountTypeUpstream {
		return infraerrors.BadRequest(
			ErrUnsupportedAccountType.Reason,
			fmt.Sprintf("account type %q is not supported; only standalone API key accounts are supported", account.Type),
		)
	}

	platform := strings.ToLower(strings.TrimSpace(account.Platform))
	if _, ok := allowedResolverPlatforms[platform]; !ok {
		return infraerrors.BadRequest(
			ErrUnsupportedAccountType.Reason,
			fmt.Sprintf("platform %q is not supported for model fingerprint verification", account.Platform),
		)
	}
	return nil
}

func normalizeSupportedProtocol(raw Protocol, allowEmpty bool) (Protocol, error) {
	trimmed := strings.ToLower(strings.TrimSpace(string(raw)))
	if trimmed == "" {
		if allowEmpty {
			return "", nil
		}
		return "", infraerrors.BadRequest("MODELFP_INVALID_PROTOCOL", "protocol is required")
	}
	proto := Protocol(trimmed)
	switch proto {
	case ProtocolOpenAIChat, ProtocolOpenAIResponses, ProtocolAnthropic, ProtocolGemini:
		return proto, nil
	default:
		return "", infraerrors.BadRequest("MODELFP_INVALID_PROTOCOL", fmt.Sprintf("unsupported protocol %q", raw))
	}
}

func normalizeAdHocAuthMode(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "":
		return "", nil
	case "bearer", "authorization_bearer":
		return "bearer", nil
	case "x-api-key", "x_api_key", "x-goog-api-key", "apikey", "api_key":
		return "x-api-key", nil
	default:
		return "", infraerrors.BadRequest("MODELFP_INVALID_AUTH_MODE", fmt.Sprintf("unsupported auth_mode %q", raw))
	}
}

func resolveAccountProtocol(account *service.Account, override Protocol) Protocol {
	if override != "" {
		return override
	}
	switch strings.ToLower(strings.TrimSpace(account.Platform)) {
	case service.PlatformOpenAI:
		if openai_compat.ShouldUseResponsesAPI(account.Extra) {
			return ProtocolOpenAIResponses
		}
		return ProtocolOpenAIChat
	case service.PlatformAnthropic:
		return ProtocolAnthropic
	case service.PlatformGemini:
		return ProtocolGemini
	default:
		switch account.GetAPIProtocol() {
		case service.APIProtocolAnthropic:
			return ProtocolAnthropic
		case service.APIProtocolResponses:
			return ProtocolOpenAIResponses
		default:
			return ProtocolOpenAIChat
		}
	}
}

func extractAccountAPIKey(account *service.Account) string {
	if account == nil {
		return ""
	}
	if account.IsMultiProtocolAPIKey() {
		if key := strings.TrimSpace(account.GetCNAPIKey()); key != "" {
			return key
		}
	}
	return strings.TrimSpace(account.GetCredential("api_key"))
}

func extractAccountBaseURL(account *service.Account, proto Protocol) string {
	switch strings.ToLower(strings.TrimSpace(account.Platform)) {
	case service.PlatformOpenAI:
		if proto == ProtocolOpenAIChat || proto == ProtocolOpenAIResponses {
			return strings.TrimSpace(account.GetOpenAIBaseURL())
		}
		if base := strings.TrimSpace(account.GetCredential("base_url")); base != "" {
			return base
		}
		return strings.TrimSpace(account.GetOpenAIBaseURL())

	case service.PlatformAnthropic:
		if base := strings.TrimSpace(account.GetBaseURL()); base != "" {
			return base
		}
		if base := strings.TrimSpace(account.GetCredential("base_url")); base != "" {
			return base
		}
		return defaultAnthropicBaseURL

	case service.PlatformGemini:
		return strings.TrimSpace(account.GetGeminiBaseURL(geminicli.AIStudioBaseURL))

	default:
		switch proto {
		case ProtocolAnthropic:
			if base := strings.TrimSpace(account.GetAnthropicProtocolBaseURL()); base != "" {
				return base
			}
			if base := strings.TrimSpace(account.GetCNProtocolBaseURL(service.APIProtocolAnthropic)); base != "" {
				return base
			}
			return strings.TrimSpace(account.GetCredential("base_url"))
		case ProtocolOpenAIResponses:
			var base string
			if account.IsAdaptiveAPIProtocol() {
				base = strings.TrimSpace(account.GetCNProtocolBaseURL(service.APIProtocolResponses))
			}
			if base == "" {
				if account.IsAnthropicProtocol() {
					base = strings.TrimSpace(account.GetOpenAIFormatBaseURL())
				} else {
					base = strings.TrimSpace(account.GetOpenAIBaseURL())
				}
			}
			return applyProviderResponsesPath(account.Platform, base)
		default:
			if account.IsAnthropicProtocol() {
				return strings.TrimSpace(account.GetOpenAIFormatBaseURL())
			}
			return strings.TrimSpace(account.GetOpenAIBaseURL())
		}
	}
}

func applyProviderResponsesPath(platform, base string) string {
	trimmed := strings.TrimSpace(base)
	if trimmed == "" {
		return ""
	}
	profile := service.LookupProviderProfile(strings.ToLower(strings.TrimSpace(platform)))
	if profile == nil || profile.ResponsesPath != "/responses" {
		return trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	path := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(path, "/responses") || hasAPIVersionSuffix(path) {
		return trimmed
	}
	parsed.Path = path + "/responses"
	parsed.RawPath = ""
	return parsed.String()
}

func resolveAccountAuthMode(account *service.Account, proto Protocol, parsedURL *url.URL) string {
	if proto != ProtocolAnthropic || account == nil {
		return ""
	}
	if account.GetAnthropicAPIKeyAuthScheme() == service.AnthropicAPIKeyAuthSchemeAuthorizationBearer {
		return "bearer"
	}
	if strings.EqualFold(strings.TrimSpace(account.GetExtraString("anthropic_apikey_auth_scheme")), service.AnthropicAPIKeyAuthSchemeAuthorizationBearer) {
		return "bearer"
	}
	if account.Type == service.AccountTypeAPIKey && isOllamaCloudAnthropicURL(parsedURL) {
		return "bearer"
	}
	return "x-api-key"
}

func isOllamaCloudAnthropicURL(parsedURL *url.URL) bool {
	if parsedURL == nil || !strings.EqualFold(parsedURL.Scheme, "https") {
		return false
	}
	host := strings.ToLower(parsedURL.Hostname())
	if host != "ollama.com" && host != "www.ollama.com" {
		return false
	}
	path := strings.TrimRight(parsedURL.Path, "/")
	return path == "" || path == "/v1"
}

func sanitizeHeaderMap(raw map[string]string, lowercaseKeys bool) map[string]string {
	if len(raw) == 0 {
		return nil
	}

	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]string, len(raw))
	seenLower := make(map[string]struct{}, len(raw))
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		val := strings.TrimSpace(raw[rawKey])
		if key == "" || val == "" {
			continue
		}
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(val, "\r\n") {
			continue
		}
		if !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(val) {
			continue
		}
		lower := strings.ToLower(key)
		if isBlockedResolverHeader(lower) {
			continue
		}
		if _, dup := seenLower[lower]; dup {
			continue
		}
		seenLower[lower] = struct{}{}
		if lowercaseKeys {
			out[lower] = val
		} else {
			out[key] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isBlockedResolverHeader(lowerName string) bool {
	if _, blocked := blockedResolverHeaders[lowerName]; blocked {
		return true
	}
	return strings.HasPrefix(lowerName, "sec-websocket-")
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func resolveAccountDefaultModels(platform string, mapping map[string]string) []string {
	if len(mapping) > 0 {
		models := make([]string, 0, len(mapping))
		for k, v := range mapping {
			trimmed := strings.TrimSpace(k)
			if trimmed == "" || strings.Contains(trimmed, "*") || strings.TrimSpace(v) == "" {
				continue
			}
			models = append(models, trimmed)
		}
		if len(models) > 0 {
			sort.Strings(models)
			return models
		}
	}

	switch platform {
	case service.PlatformOpenAI:
		return openai.DefaultModelIDs()
	case service.PlatformAnthropic:
		return claude.DefaultModelIDs()
	case service.PlatformGemini:
		ids := make([]string, 0, len(geminicli.DefaultModels))
		for _, m := range geminicli.DefaultModels {
			ids = append(ids, m.ID)
		}
		return ids
	case service.PlatformDeepseek:
		return []string{"deepseek-chat", "deepseek-reasoner", "deepseek-flash", "deepseek-v4-pro"}
	case service.PlatformKimi:
		return []string{"kimi-k2", "kimi-k2.5"}
	case service.PlatformZhipu:
		return []string{"glm-4.7", "glm-4.6", "glm-4.5"}
	case service.PlatformMiniMax:
		return []string{"MiniMax-M2", "MiniMax-M1"}
	default:
		return nil
	}
}

func resolveModelMappingMatch(mapping map[string]string, model string) (string, bool) {
	if mapped, exists := mapping[model]; exists {
		if trimmed := strings.TrimSpace(mapped); trimmed != "" {
			return trimmed, true
		}
		return model, false
	}

	type patternMatch struct {
		pattern string
		target  string
	}
	var matches []patternMatch
	for pattern, target := range mapping {
		if strings.HasSuffix(pattern, "*") {
			prefix := pattern[:len(pattern)-1]
			if strings.HasPrefix(model, prefix) {
				if trimmed := strings.TrimSpace(target); trimmed != "" {
					matches = append(matches, patternMatch{pattern: pattern, target: trimmed})
				}
			}
		}
	}
	if len(matches) == 0 {
		return "", false
	}

	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i].pattern) != len(matches[j].pattern) {
			return len(matches[i].pattern) > len(matches[j].pattern)
		}
		return matches[i].pattern < matches[j].pattern
	})
	return matches[0].target, true
}

func formatAccountLabel(accountID int64, rawName, apiKey, proxyPassword string) string {
	clean := sanitizeLabelText(rawName, apiKey, proxyPassword)
	if clean == "" {
		return fmt.Sprintf("account #%d", accountID)
	}
	return fmt.Sprintf("account #%d (%s)", accountID, clean)
}

func sanitizeLabelText(raw, apiKey, proxyPassword string) string {
	s := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(raw)
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, secret := range []string{strings.TrimSpace(apiKey), strings.TrimSpace(proxyPassword)} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, redactedSecretPlaceholder)
		}
	}
	s = bearerTokenPattern.ReplaceAllString(s, "Bearer "+redactedSecretPlaceholder)
	s = apiKeyTokenPattern.ReplaceAllString(s, redactedSecretPlaceholder)
	return strings.TrimSpace(s)
}

func maskAPIKey(raw string) string {
	runes := []rune(strings.TrimSpace(raw))
	n := len(runes)
	switch {
	case n <= 6:
		return "***"
	case n <= 9:
		return string(runes[:2]) + "***" + string(runes[n-2:])
	default:
		return string(runes[:5]) + "***" + string(runes[n-2:])
	}
}
