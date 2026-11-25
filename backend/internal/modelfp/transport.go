package modelfp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	defaultProbeTimeout       = 30 * time.Second
	responsesProbeTimeout     = 60 * time.Second
	maxResponseBodyBytes      = 256 << 10 // 256 KiB per response cap
	maxDiscoverModelPages     = 10
	maxErrorMessageChars      = 512
	defaultAnthropicVersion   = "2023-06-01"
	defaultTopLogprobs        = 20
	defaultLogprobsSeed       = 42
	defaultLogprobsMaxTokens  = 1
	defaultBehaviorMaxTokens  = 64
	errorCodeModelNotFound    = "model_not_found"
	errorCodeAuthError        = "auth_error"
	errorCodeRateLimited      = "rate_limited"
	errorCodeUpstreamError    = "upstream_error"
	errorCodeTimeout          = "timeout"
	errorCodeSSRFBlocked      = "ssrf_blocked"
	redactedSecretPlaceholder = "[REDACTED]"
)

var (
	bearerTokenPattern = regexp.MustCompile(`(?i)\bBearer\s+([^\s"',;]+)`)
	apiKeyTokenPattern = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{16,})`)
)

var blockedExtraHeaders = map[string]struct{}{
	"host":              {},
	"content-length":    {},
	"connection":        {},
	"transfer-encoding": {},
}

// ProbeCallResult captures the normalized outcome of a single upstream probe execution.
type ProbeCallResult struct {
	Text               string
	ResponseModel      string
	SystemFingerprint  string
	HasReasoningField  bool
	Logprobs           []TokenProb
	LogprobsSupported  bool
	PromptTokens       int
	CachedPromptTokens int
	OutputTokens       int
	LatencyMS          int
	HTTPStatus         int
	ErrorCode          string
	ErrorMessage       string
}

// ProbeClient executes single-model probes and discovers supported models across protocols.
type ProbeClient interface {
	ExecuteProbe(ctx context.Context, target ProbeTarget, model string, probe ProbeDefinition, requestLogprobs bool) ProbeCallResult
	DiscoverModels(ctx context.Context, target ProbeTarget) ([]string, error)
}

// TransportOption configures an HTTPProbeClient.
type TransportOption func(*HTTPProbeClient)

// WithAllowLoopbackForTest allows loopback hosts/IPs solely for httptest.Server unit tests.
func WithAllowLoopbackForTest() TransportOption {
	return func(c *HTTPProbeClient) {
		c.allowLoopback = true
	}
}

func withLookupNetIPForTest(fn lookupNetIPFunc) TransportOption {
	return func(c *HTTPProbeClient) {
		c.lookupFn = fn
	}
}

// HTTPProbeClient implements ProbeClient over SSRF-hardened HTTP transports.
type HTTPProbeClient struct {
	allowLoopback bool
	lookupFn      lookupNetIPFunc
	mu            sync.Mutex
	transports    map[string]http.RoundTripper
}

// NewHTTPProbeClient creates a 4-protocol SSRF-safe HTTP ProbeClient.
func NewHTTPProbeClient(opts ...TransportOption) *HTTPProbeClient {
	c := &HTTPProbeClient{
		transports: make(map[string]http.RoundTripper),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// NormalizeProtocolEndpoint constructs the target request or discovery URL without
// duplicating version path segments (/v1, /v1beta) or stripping custom prefixes.
func NormalizeProtocolEndpoint(baseURL string, protocol Protocol, model string, forDiscovery bool) (string, error) {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return "", errors.New("base URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("invalid base URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", scheme)
	}
	parsed.Scheme = scheme

	cleanModel := strings.TrimSpace(model)
	if protocol == ProtocolGemini {
		cleanModel = strings.TrimPrefix(cleanModel, "models/")
		cleanModel = strings.TrimPrefix(cleanModel, "/")
	}
	if !forDiscovery && cleanModel == "" {
		return "", errors.New("model is required")
	}

	unescapedBase := strings.TrimRight(parsed.Path, "/")
	escapedBase := strings.TrimRight(parsed.EscapedPath(), "/")

	var unescapedPath, rawPath string
	switch protocol {
	case ProtocolOpenAIChat:
		unescapedPath, rawPath = normalizeOpenAIStylePath(unescapedBase, escapedBase, "/chat/completions", forDiscovery)
	case ProtocolOpenAIResponses:
		unescapedPath, rawPath = normalizeOpenAIStylePath(unescapedBase, escapedBase, "/responses", forDiscovery)
	case ProtocolAnthropic:
		unescapedPath, rawPath = normalizeOpenAIStylePath(unescapedBase, escapedBase, "/messages", forDiscovery)
	case ProtocolGemini:
		unescapedPath, rawPath = normalizeGeminiPath(unescapedBase, escapedBase, cleanModel, forDiscovery)
	default:
		return "", fmt.Errorf("unsupported protocol %q", protocol)
	}

	parsed.Path = unescapedPath
	if rawPath != unescapedPath {
		parsed.RawPath = rawPath
	} else {
		parsed.RawPath = ""
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeOpenAIStylePath(unescapedBase, escapedBase, endpointSuffix string, forDiscovery bool) (string, string) {
	if forDiscovery {
		for _, known := range []string{"/chat/completions", "/responses", "/messages"} {
			unescapedBase = strings.TrimSuffix(unescapedBase, known)
			escapedBase = strings.TrimSuffix(escapedBase, known)
		}
		if strings.HasSuffix(unescapedBase, "/models") {
			return unescapedBase, escapedBase
		}
		if hasAPIVersionSuffix(unescapedBase) {
			return unescapedBase + "/models", escapedBase + "/models"
		}
		return unescapedBase + "/v1/models", escapedBase + "/v1/models"
	}

	if strings.HasSuffix(unescapedBase, endpointSuffix) {
		return unescapedBase, escapedBase
	}
	if hasAPIVersionSuffix(unescapedBase) {
		return unescapedBase + endpointSuffix, escapedBase + endpointSuffix
	}
	return unescapedBase + "/v1" + endpointSuffix, escapedBase + "/v1" + endpointSuffix
}

func normalizeGeminiPath(unescapedBase, escapedBase, model string, forDiscovery bool) (string, string) {
	escapedModel := url.PathEscape(model)
	if forDiscovery {
		if idx := strings.Index(unescapedBase, "/models/"); idx >= 0 {
			unescapedBase = unescapedBase[:idx] + "/models"
		}
		if idx := strings.Index(escapedBase, "/models/"); idx >= 0 {
			escapedBase = escapedBase[:idx] + "/models"
		}
		if strings.HasSuffix(unescapedBase, "/models") {
			return unescapedBase, escapedBase
		}
		if hasAPIVersionSuffix(unescapedBase) {
			return unescapedBase + "/models", escapedBase + "/models"
		}
		return unescapedBase + "/v1beta/models", escapedBase + "/v1beta/models"
	}

	if strings.HasSuffix(unescapedBase, ":generateContent") {
		return unescapedBase, escapedBase
	}
	if strings.HasSuffix(unescapedBase, "/models") {
		return unescapedBase + "/" + model + ":generateContent", escapedBase + "/" + escapedModel + ":generateContent"
	}
	if hasAPIVersionSuffix(unescapedBase) {
		return unescapedBase + "/models/" + model + ":generateContent", escapedBase + "/models/" + escapedModel + ":generateContent"
	}
	return unescapedBase + "/v1beta/models/" + model + ":generateContent", escapedBase + "/v1beta/models/" + escapedModel + ":generateContent"
}

func hasAPIVersionSuffix(path string) bool {
	trimmed := strings.TrimRight(strings.TrimSpace(path), "/")
	if trimmed == "" {
		return false
	}
	segment := trimmed
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		segment = trimmed[idx+1:]
	}
	s := strings.ToLower(strings.TrimSpace(segment))
	if len(s) < 2 || s[0] != 'v' || !isASCIIDigitByte(s[1]) {
		return false
	}
	i := 1
	for i < len(s) && isASCIIDigitByte(s[i]) {
		i++
	}
	if i == len(s) {
		return true
	}
	if s[i] == '.' {
		i++
		if i == len(s) || !isASCIIDigitByte(s[i]) {
			return false
		}
		for i < len(s) && isASCIIDigitByte(s[i]) {
			i++
		}
		return i == len(s)
	}
	rest := s[i:]
	return strings.HasPrefix(rest, "alpha") || strings.HasPrefix(rest, "beta") || strings.HasPrefix(rest, "preview")
}

func isASCIIDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

// ExecuteProbe runs one probe request against target for the specified model.
func (c *HTTPProbeClient) ExecuteProbe(
	ctx context.Context,
	target ProbeTarget,
	model string,
	probe ProbeDefinition,
	requestLogprobs bool,
) ProbeCallResult {
	start := time.Now()
	finish := func(res ProbeCallResult) ProbeCallResult {
		res.LatencyMS = int(time.Since(start).Milliseconds())
		if res.ErrorMessage != "" {
			res.ErrorMessage = redactSecretsWithStatus(res.ErrorMessage, res.HTTPStatus, target)
		}
		return res
	}

	if _, err := validateBaseURLWithLookup(ctx, target.BaseURL, c.allowLoopback, c.lookupFn); err != nil {
		return finish(ProbeCallResult{
			ErrorCode:    classifyTransportError(err),
			ErrorMessage: err.Error(),
		})
	}

	endpoint, err := NormalizeProtocolEndpoint(target.BaseURL, target.Protocol, model, false)
	if err != nil {
		return finish(ProbeCallResult{
			ErrorCode:    errorCodeUpstreamError,
			ErrorMessage: err.Error(),
		})
	}

	timeout := defaultProbeTimeout
	if target.Protocol == ProtocolOpenAIResponses {
		timeout = responsesProbeTimeout
	}
	httpClient, err := c.clientForTarget(target, timeout)
	if err != nil {
		return finish(ProbeCallResult{
			ErrorCode:    classifyTransportError(err),
			ErrorMessage: err.Error(),
		})
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	payload, hasLogprobsOrSeed, err := buildProbePayload(target.Protocol, model, probe, requestLogprobs)
	if err != nil {
		return finish(ProbeCallResult{
			ErrorCode:    errorCodeUpstreamError,
			ErrorMessage: err.Error(),
		})
	}

	status, body, exceeded, reqErr := c.doJSONRequest(reqCtx, httpClient, http.MethodPost, endpoint, payload, target)
	if reqErr != nil {
		return finish(ProbeCallResult{
			HTTPStatus:   status,
			ErrorCode:    classifyTransportError(reqErr),
			ErrorMessage: formatTransportError(reqErr),
		})
	}
	if exceeded {
		return finish(ProbeCallResult{
			HTTPStatus:   status,
			ErrorCode:    errorCodeUpstreamError,
			ErrorMessage: "response body exceeds 256 KiB limit",
		})
	}

	// Retry once on HTTP 400 after stripping logprobs/top_logprobs/seed/responseLogprobs.
	retriedWithoutLogprobs := false
	if status == http.StatusBadRequest && hasLogprobsOrSeed {
		retriedWithoutLogprobs = true
		fallbackPayload, _, fbErr := buildProbePayload(target.Protocol, model, probeWithoutSeed(probe), false)
		if fbErr != nil {
			return finish(ProbeCallResult{
				HTTPStatus:   status,
				ErrorCode:    errorCodeUpstreamError,
				ErrorMessage: fbErr.Error(),
			})
		}
		status, body, exceeded, reqErr = c.doJSONRequest(reqCtx, httpClient, http.MethodPost, endpoint, fallbackPayload, target)
		if reqErr != nil {
			return finish(ProbeCallResult{
				HTTPStatus:   status,
				ErrorCode:    classifyTransportError(reqErr),
				ErrorMessage: formatTransportError(reqErr),
			})
		}
		if exceeded {
			return finish(ProbeCallResult{
				HTTPStatus:   status,
				ErrorCode:    errorCodeUpstreamError,
				ErrorMessage: "response body exceeds 256 KiB limit",
			})
		}
	}

	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return finish(ProbeCallResult{
			HTTPStatus:   status,
			ErrorCode:    classifyHTTPStatus(status),
			ErrorMessage: extractErrorMessage(status, body),
		})
	}

	parsed, parseErr := parseProbeResponse(target.Protocol, body)
	if parseErr != nil {
		return finish(ProbeCallResult{
			HTTPStatus:   status,
			ErrorCode:    errorCodeUpstreamError,
			ErrorMessage: parseErr.Error(),
		})
	}
	parsed.HTTPStatus = status
	if retriedWithoutLogprobs {
		parsed.Logprobs = nil
		parsed.LogprobsSupported = false
	}
	return finish(parsed)
}

// DiscoverModels queries the protocol's model listing endpoint (following pagination cursors
// up to maxDiscoverModelPages) and returns deduplicated model IDs.
func (c *HTTPProbeClient) DiscoverModels(ctx context.Context, target ProbeTarget) ([]string, error) {
	if _, err := validateBaseURLWithLookup(ctx, target.BaseURL, c.allowLoopback, c.lookupFn); err != nil {
		return nil, redactError(err, target)
	}

	baseEndpoint, err := NormalizeProtocolEndpoint(target.BaseURL, target.Protocol, "", true)
	if err != nil {
		return nil, redactError(err, target)
	}

	httpClient, err := c.clientForTarget(target, defaultProbeTimeout)
	if err != nil {
		return nil, redactError(err, target)
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
	defer cancel()

	seenModels := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	var allModels []string
	nextURL := baseEndpoint

	for page := 0; page < maxDiscoverModelPages; page++ {
		status, body, exceeded, reqErr := c.doJSONRequest(reqCtx, httpClient, http.MethodGet, nextURL, nil, target)
		if reqErr != nil {
			return nil, redactError(reqErr, target)
		}
		if exceeded {
			return nil, errors.New("response body exceeds 256 KiB limit")
		}
		if status < http.StatusOK || status >= http.StatusMultipleChoices {
			msg := redactSecretsWithStatus(extractErrorMessage(status, body), status, target)
			return nil, fmt.Errorf("%s: %s", classifyHTTPStatus(status), msg)
		}

		pageModels, cursorParam, cursorVal, parseErr := parseDiscoverModelsPage(target.Protocol, body)
		if parseErr != nil {
			return nil, redactError(parseErr, target)
		}
		for _, id := range pageModels {
			if _, exists := seenModels[id]; exists {
				continue
			}
			seenModels[id] = struct{}{}
			allModels = append(allModels, id)
		}

		if cursorParam == "" || cursorVal == "" {
			break
		}
		cursorKey := cursorParam + "=" + cursorVal
		if _, repeated := seenCursors[cursorKey]; repeated {
			break
		}
		seenCursors[cursorKey] = struct{}{}

		pagedURL, err := withQueryParam(baseEndpoint, cursorParam, cursorVal)
		if err != nil {
			return nil, redactError(err, target)
		}
		nextURL = pagedURL
	}

	return allModels, nil
}

func withQueryParam(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *HTTPProbeClient) clientForTarget(target ProbeTarget, timeout time.Duration) (*http.Client, error) {
	key := fmt.Sprintf("%t|%s", c.allowLoopback, strings.TrimSpace(target.ProxyURL))
	c.mu.Lock()
	rt, ok := c.transports[key]
	if !ok {
		var err error
		rt, err = newSSRFSafeTransportWithLookup(target.ProxyURL, c.allowLoopback, c.lookupFn)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.transports[key] = rt
	}
	c.mu.Unlock()

	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Reject all redirects unconditionally so credentials and custom headers
			// can never follow redirects across origins or trailing-dot host boundaries.
			return fmt.Errorf("%w: HTTP redirects are not permitted", ErrSSRFBlocked)
		},
	}, nil
}

func (c *HTTPProbeClient) doJSONRequest(
	ctx context.Context,
	client *http.Client,
	method string,
	endpoint string,
	payload []byte,
	target ProbeTarget,
) (status int, body []byte, exceeded bool, err error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return 0, nil, false, err
	}
	applyProtocolHeaders(req, target, payload != nil)

	resp, err := client.Do(req) //nolint:gosec // G704: URL validated by validateBaseURLWithLookup; transport enforces SSRF DialContext/RoundTrip & CheckRedirect disables redirects
	if err != nil {
		return 0, nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if readErr != nil {
		return resp.StatusCode, nil, false, readErr
	}
	if int64(len(raw)) > maxResponseBodyBytes {
		return resp.StatusCode, raw[:maxResponseBodyBytes], true, nil
	}
	return resp.StatusCode, raw, false, nil
}

func applyProtocolHeaders(req *http.Request, target ProbeTarget, hasBody bool) {
	req.Header.Set("Accept", "application/json")
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}

	apiKey := strings.TrimSpace(target.APIKey)
	authMode := strings.ToLower(strings.TrimSpace(target.AuthMode))

	switch target.Protocol {
	case ProtocolOpenAIChat, ProtocolOpenAIResponses:
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	case ProtocolAnthropic:
		req.Header.Set("anthropic-version", defaultAnthropicVersion)
		if apiKey != "" {
			if authMode == "bearer" {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			} else {
				req.Header.Set("x-api-key", apiKey)
			}
		}
	case ProtocolGemini:
		if apiKey != "" {
			if authMode == "bearer" {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			} else {
				req.Header.Set("x-goog-api-key", apiKey)
			}
		}
	}

	for k, v := range target.ExtraHeaders {
		key := strings.TrimSpace(k)
		if key == "" || strings.ContainsAny(key, "\r\n") || strings.ContainsAny(v, "\r\n") {
			continue
		}
		if _, blocked := blockedExtraHeaders[strings.ToLower(key)]; blocked {
			continue
		}
		req.Header.Set(key, v)
	}
}

func probeWithoutSeed(probe ProbeDefinition) ProbeDefinition {
	out := probe
	out.Seed = nil
	out.TopLogprobs = 0
	return out
}

func buildProbePayload(protocol Protocol, model string, probe ProbeDefinition, requestLogprobs bool) ([]byte, bool, error) {
	maxTokens := probe.MaxTokens
	if maxTokens <= 0 {
		if probe.Kind == DetectorLogprobs {
			maxTokens = defaultLogprobsMaxTokens
		} else {
			maxTokens = defaultBehaviorMaxTokens
		}
	}

	switch protocol {
	case ProtocolOpenAIChat:
		type chatMsg struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		msgs := make([]chatMsg, 0, 2)
		if strings.TrimSpace(probe.SystemPrompt) != "" {
			msgs = append(msgs, chatMsg{Role: "system", Content: probe.SystemPrompt})
		}
		msgs = append(msgs, chatMsg{Role: "user", Content: probe.Prompt})

		body := map[string]any{
			"model":       model,
			"messages":    msgs,
			"max_tokens":  maxTokens,
			"temperature": probe.Temperature,
			"stream":      false,
		}
		hasOptional := false
		if requestLogprobs {
			topLP := probe.TopLogprobs
			if topLP <= 0 {
				topLP = defaultTopLogprobs
			}
			body["logprobs"] = true
			body["top_logprobs"] = topLP
			hasOptional = true
		}
		if probe.Seed != nil {
			body["seed"] = *probe.Seed
			hasOptional = true
		} else if requestLogprobs {
			body["seed"] = defaultLogprobsSeed
			hasOptional = true
		}
		raw, err := json.Marshal(body)
		return raw, hasOptional, err

	case ProtocolOpenAIResponses:
		body := map[string]any{
			"model":             model,
			"input":             probe.Prompt,
			"max_output_tokens": maxTokens,
			"temperature":       probe.Temperature,
			"stream":            false,
		}
		if strings.TrimSpace(probe.SystemPrompt) != "" {
			body["instructions"] = probe.SystemPrompt
		}
		raw, err := json.Marshal(body)
		return raw, false, err

	case ProtocolAnthropic:
		type anthropicMsg struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		body := map[string]any{
			"model":       model,
			"messages":    []anthropicMsg{{Role: "user", Content: probe.Prompt}},
			"max_tokens":  maxTokens,
			"temperature": probe.Temperature,
			"stream":      false,
		}
		if strings.TrimSpace(probe.SystemPrompt) != "" {
			body["system"] = probe.SystemPrompt
		}
		raw, err := json.Marshal(body)
		return raw, false, err

	case ProtocolGemini:
		type geminiPart struct {
			Text string `json:"text"`
		}
		type geminiContent struct {
			Role  string       `json:"role,omitempty"`
			Parts []geminiPart `json:"parts"`
		}
		genConfig := map[string]any{
			"temperature":     probe.Temperature,
			"maxOutputTokens": maxTokens,
		}
		hasOptional := false
		if requestLogprobs {
			topLP := probe.TopLogprobs
			if topLP <= 0 {
				topLP = defaultTopLogprobs
			}
			genConfig["responseLogprobs"] = true
			genConfig["logprobs"] = topLP
			hasOptional = true
		}
		body := map[string]any{
			"contents":         []geminiContent{{Role: "user", Parts: []geminiPart{{Text: probe.Prompt}}}},
			"generationConfig": genConfig,
		}
		if strings.TrimSpace(probe.SystemPrompt) != "" {
			body["systemInstruction"] = geminiContent{Parts: []geminiPart{{Text: probe.SystemPrompt}}}
		}
		raw, err := json.Marshal(body)
		return raw, hasOptional, err

	default:
		return nil, false, fmt.Errorf("unsupported protocol %q", protocol)
	}
}

func parseProbeResponse(protocol Protocol, body []byte) (ProbeCallResult, error) {
	switch protocol {
	case ProtocolOpenAIChat:
		return parseOpenAIChatResponse(body)
	case ProtocolOpenAIResponses:
		return parseOpenAIResponsesResponse(body)
	case ProtocolAnthropic:
		return parseAnthropicResponse(body)
	case ProtocolGemini:
		return parseGeminiResponse(body)
	default:
		return ProbeCallResult{}, fmt.Errorf("unsupported protocol %q", protocol)
	}
}

func parseOpenAIChatResponse(body []byte) (ProbeCallResult, error) {
	var resp struct {
		Model             string `json:"model"`
		SystemFingerprint string `json:"system_fingerprint"`
		Choices           []struct {
			Text    string `json:"text"`
			Message struct {
				Content          json.RawMessage `json:"content"`
				ReasoningContent string          `json:"reasoning_content"`
				Reasoning        string          `json:"reasoning"`
			} `json:"message"`
			Logprobs *struct {
				Content []struct {
					Token       string  `json:"token"`
					Logprob     float64 `json:"logprob"`
					TopLogprobs []struct {
						Token   string  `json:"token"`
						Logprob float64 `json:"logprob"`
					} `json:"top_logprobs"`
				} `json:"content"`
			} `json:"logprobs"`
		} `json:"choices"`
		Usage struct {
			PromptTokens         int `json:"prompt_tokens"`
			InputTokens          int `json:"input_tokens"`
			CompletionTokens     int `json:"completion_tokens"`
			OutputTokens         int `json:"output_tokens"`
			CachedTokens         int `json:"cached_tokens"`
			PromptCacheHitTokens int `json:"prompt_cache_hit_tokens"`
			PromptTokensDetails  *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			CompletionTokensDetails *struct {
				ReasoningTokens int `json:"reasoning_tokens"`
			} `json:"completion_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ProbeCallResult{}, fmt.Errorf("decode openai_chat response: %w", err)
	}

	promptTokens := resp.Usage.PromptTokens
	if promptTokens == 0 && resp.Usage.InputTokens > 0 {
		promptTokens = resp.Usage.InputTokens
	}
	outputTokens := resp.Usage.CompletionTokens
	if outputTokens == 0 && resp.Usage.OutputTokens > 0 {
		outputTokens = resp.Usage.OutputTokens
	}
	cachedTokens := maxInt(resp.Usage.CachedTokens, resp.Usage.PromptCacheHitTokens)
	if resp.Usage.PromptTokensDetails != nil {
		cachedTokens = maxInt(cachedTokens, resp.Usage.PromptTokensDetails.CachedTokens)
	}

	res := ProbeCallResult{
		ResponseModel:      resp.Model,
		SystemFingerprint:  resp.SystemFingerprint,
		PromptTokens:       promptTokens,
		CachedPromptTokens: cachedTokens,
		OutputTokens:       outputTokens,
	}
	if resp.Usage.CompletionTokensDetails != nil && resp.Usage.CompletionTokensDetails.ReasoningTokens > 0 {
		res.HasReasoningField = true
	}

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		res.Text = extractChatContentText(choice.Message.Content)
		if res.Text == "" && choice.Text != "" {
			res.Text = choice.Text
		}
		if strings.TrimSpace(choice.Message.ReasoningContent) != "" || strings.TrimSpace(choice.Message.Reasoning) != "" {
			res.HasReasoningField = true
		}
		if choice.Logprobs != nil && len(choice.Logprobs.Content) > 0 {
			first := choice.Logprobs.Content[0]
			if len(first.TopLogprobs) > 0 {
				res.Logprobs = make([]TokenProb, 0, len(first.TopLogprobs))
				for _, tp := range first.TopLogprobs {
					res.Logprobs = append(res.Logprobs, TokenProb{
						Token:   tp.Token,
						Logprob: tp.Logprob,
						Prob:    logprobToProb(tp.Logprob),
					})
				}
			} else if first.Token != "" {
				res.Logprobs = []TokenProb{{
					Token:   first.Token,
					Logprob: first.Logprob,
					Prob:    logprobToProb(first.Logprob),
				}}
			}
			res.LogprobsSupported = len(res.Logprobs) > 0
		}
	}
	return res, nil
}

func extractChatContentText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(trimmed, &parts); err == nil {
		var sb strings.Builder
		for _, p := range parts {
			if p.Text != "" {
				sb.WriteString(p.Text)
			}
		}
		return sb.String()
	}
	return ""
}

func parseOpenAIResponsesResponse(body []byte) (ProbeCallResult, error) {
	var resp struct {
		Model      string          `json:"model"`
		OutputText string          `json:"output_text"`
		Reasoning  json.RawMessage `json:"reasoning"`
		Output     []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage struct {
			InputTokens        int `json:"input_tokens"`
			OutputTokens       int `json:"output_tokens"`
			PromptTokens       int `json:"prompt_tokens"`
			CompletionTokens   int `json:"completion_tokens"`
			InputTokensDetails *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
			OutputTokensDetails *struct {
				ReasoningTokens int `json:"reasoning_tokens"`
			} `json:"output_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ProbeCallResult{}, fmt.Errorf("decode openai_responses response: %w", err)
	}

	var sb strings.Builder
	hasReasoning := hasNonEmptyJSONObject(resp.Reasoning)
	for _, item := range resp.Output {
		if item.Type == "reasoning" {
			hasReasoning = true
		}
		for _, part := range item.Content {
			if part.Type == "output_text" || part.Type == "text" || part.Type == "" {
				sb.WriteString(part.Text)
			}
		}
	}
	text := sb.String()
	if text == "" {
		text = resp.OutputText
	}

	promptTokens := resp.Usage.InputTokens
	if promptTokens == 0 && resp.Usage.PromptTokens > 0 {
		promptTokens = resp.Usage.PromptTokens
	}
	outputTokens := resp.Usage.OutputTokens
	if outputTokens == 0 && resp.Usage.CompletionTokens > 0 {
		outputTokens = resp.Usage.CompletionTokens
	}
	var cachedTokens int
	if resp.Usage.InputTokensDetails != nil {
		cachedTokens = resp.Usage.InputTokensDetails.CachedTokens
	}
	if resp.Usage.OutputTokensDetails != nil && resp.Usage.OutputTokensDetails.ReasoningTokens > 0 {
		hasReasoning = true
	}

	return ProbeCallResult{
		Text:               text,
		ResponseModel:      resp.Model,
		HasReasoningField:  hasReasoning,
		PromptTokens:       promptTokens,
		CachedPromptTokens: cachedTokens,
		OutputTokens:       outputTokens,
	}, nil
}

func hasNonEmptyJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("{}"))
}

func parseAnthropicResponse(body []byte) (ProbeCallResult, error) {
	var resp struct {
		Model   string `json:"model"`
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content"`
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CachedTokens             int `json:"cached_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ProbeCallResult{}, fmt.Errorf("decode anthropic response: %w", err)
	}

	var sb strings.Builder
	hasReasoning := false
	for _, block := range resp.Content {
		switch block.Type {
		case "thinking", "redacted_thinking":
			hasReasoning = true
		case "text", "":
			sb.WriteString(block.Text)
		}
	}

	cachedTokens := maxInt(resp.Usage.CacheReadInputTokens, resp.Usage.CachedTokens)
	promptTokens := resp.Usage.InputTokens + resp.Usage.CacheCreationInputTokens + cachedTokens

	return ProbeCallResult{
		Text:               sb.String(),
		ResponseModel:      resp.Model,
		HasReasoningField:  hasReasoning,
		PromptTokens:       promptTokens,
		CachedPromptTokens: cachedTokens,
		OutputTokens:       resp.Usage.OutputTokens,
	}, nil
}

func parseGeminiResponse(body []byte) (ProbeCallResult, error) {
	type geminiLogprobCandidate struct {
		Token          string   `json:"token"`
		LogProbability *float64 `json:"logProbability"`
		Logprob        *float64 `json:"logprob"`
	}
	var resp struct {
		ModelVersion string `json:"modelVersion"`
		Model        string `json:"model"`
		Candidates   []struct {
			Content *struct {
				Parts []struct {
					Text    string `json:"text"`
					Thought bool   `json:"thought"`
				} `json:"parts"`
			} `json:"content"`
			LogprobsResult *struct {
				TopCandidates []struct {
					Candidates []geminiLogprobCandidate `json:"candidates"`
				} `json:"topCandidates"`
				ChosenCandidates []geminiLogprobCandidate `json:"chosenCandidates"`
			} `json:"logprobsResult"`
		} `json:"candidates"`
		UsageMetadata *struct {
			PromptTokenCount        int `json:"promptTokenCount"`
			CachedContentTokenCount int `json:"cachedContentTokenCount"`
			CandidatesTokenCount    int `json:"candidatesTokenCount"`
			ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ProbeCallResult{}, fmt.Errorf("decode gemini response: %w", err)
	}

	responseModel := resp.ModelVersion
	if responseModel == "" {
		responseModel = resp.Model
	}

	res := ProbeCallResult{
		ResponseModel: responseModel,
	}
	if resp.UsageMetadata != nil {
		res.PromptTokens = resp.UsageMetadata.PromptTokenCount
		res.CachedPromptTokens = resp.UsageMetadata.CachedContentTokenCount
		res.OutputTokens = resp.UsageMetadata.CandidatesTokenCount
		if resp.UsageMetadata.ThoughtsTokenCount > 0 {
			res.HasReasoningField = true
		}
	}

	if len(resp.Candidates) > 0 {
		cand := resp.Candidates[0]
		if cand.Content != nil {
			var sb strings.Builder
			for _, part := range cand.Content.Parts {
				if part.Thought {
					res.HasReasoningField = true
					continue
				}
				sb.WriteString(part.Text)
			}
			res.Text = sb.String()
		}
		if cand.LogprobsResult != nil {
			var entries []geminiLogprobCandidate
			if len(cand.LogprobsResult.TopCandidates) > 0 {
				entries = cand.LogprobsResult.TopCandidates[0].Candidates
			} else if len(cand.LogprobsResult.ChosenCandidates) > 0 {
				entries = []geminiLogprobCandidate{cand.LogprobsResult.ChosenCandidates[0]}
			}
			if len(entries) > 0 {
				res.Logprobs = make([]TokenProb, 0, len(entries))
				for _, entry := range entries {
					lp := 0.0
					switch {
					case entry.LogProbability != nil:
						lp = *entry.LogProbability
					case entry.Logprob != nil:
						lp = *entry.Logprob
					}
					res.Logprobs = append(res.Logprobs, TokenProb{
						Token:   entry.Token,
						Logprob: lp,
						Prob:    logprobToProb(lp),
					})
				}
				res.LogprobsSupported = len(res.Logprobs) > 0
			}
		}
	}
	return res, nil
}

func parseDiscoverModelsPage(protocol Protocol, body []byte) (models []string, cursorParam string, cursorVal string, err error) {
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			ID                         string   `json:"id"`
			Name                       string   `json:"name"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
		NextPageToken string `json:"nextPageToken"`
		HasMore       bool   `json:"has_more"`
		LastID        string `json:"last_id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", "", fmt.Errorf("decode models list: %w", err)
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, len(payload.Data)+len(payload.Models))
	addModel := func(raw string) {
		id := strings.TrimSpace(raw)
		if id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}

	if protocol == ProtocolGemini {
		for _, m := range payload.Models {
			if len(m.SupportedGenerationMethods) > 0 && !containsString(m.SupportedGenerationMethods, "generateContent") {
				continue
			}
			name := strings.TrimSpace(m.Name)
			if name == "" {
				name = strings.TrimSpace(m.ID)
			}
			name = strings.TrimPrefix(name, "models/")
			addModel(name)
		}
		for _, item := range payload.Data {
			addModel(strings.TrimPrefix(strings.TrimSpace(item.ID), "models/"))
		}
		if token := strings.TrimSpace(payload.NextPageToken); token != "" {
			return out, "pageToken", token, nil
		}
		return out, "", "", nil
	}

	for _, item := range payload.Data {
		addModel(item.ID)
	}
	for _, m := range payload.Models {
		if m.ID != "" {
			addModel(m.ID)
		} else {
			addModel(m.Name)
		}
	}
	if protocol == ProtocolAnthropic && payload.HasMore {
		if lastID := strings.TrimSpace(payload.LastID); lastID != "" {
			return out, "after_id", lastID, nil
		}
	}
	return out, "", "", nil
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func logprobToProb(logprob float64) float64 {
	if math.IsNaN(logprob) || math.IsInf(logprob, -1) {
		return 0
	}
	if math.IsInf(logprob, 1) {
		return 1
	}
	p := math.Exp(logprob)
	if math.IsNaN(p) || p < 0 {
		return 0
	}
	if p > 1 {
		return 1
	}
	return p
}

func maxInt(a, b int) int {
	if b > a {
		return b
	}
	return a
}

func classifyHTTPStatus(status int) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return errorCodeAuthError
	case http.StatusNotFound:
		return errorCodeModelNotFound
	case http.StatusTooManyRequests:
		return errorCodeRateLimited
	default:
		return errorCodeUpstreamError
	}
}

func classifyTransportError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrSSRFBlocked) {
		return errorCodeSSRFBlocked
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errorCodeTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errorCodeTimeout
	}
	return errorCodeUpstreamError
}

func formatTransportError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}

func extractErrorMessage(status int, body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 {
		var envelope struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		if err := json.Unmarshal(trimmed, &envelope); err == nil {
			switch {
			case envelope.Error != nil && strings.TrimSpace(envelope.Error.Message) != "":
				return envelope.Error.Message
			case strings.TrimSpace(envelope.Message) != "":
				return envelope.Message
			case strings.TrimSpace(envelope.Detail) != "":
				return envelope.Detail
			}
		}
	}
	return genericHTTPFallback(status)
}

func genericHTTPFallback(status int) string {
	if status > 0 {
		if text := http.StatusText(status); text != "" {
			return fmt.Sprintf("upstream HTTP %d %s", status, text)
		}
		return fmt.Sprintf("upstream HTTP %d", status)
	}
	return "upstream error (redacted)"
}

func redactError(err error, target ProbeTarget) error {
	if err == nil {
		return nil
	}
	msg := redactSecrets(formatTransportError(err), target)
	if errors.Is(err, ErrSSRFBlocked) {
		return fmt.Errorf("%w: %s", ErrSSRFBlocked, msg)
	}
	return errors.New(msg)
}

func redactSecrets(msg string, target ProbeTarget) string {
	return redactSecretsWithStatus(msg, 0, target)
}

func redactSecretsWithStatus(msg string, status int, target ProbeTarget) string {
	if msg == "" {
		return ""
	}

	secrets := collectSecrets(target)
	out := msg
	for _, secret := range secrets {
		out = strings.ReplaceAll(out, secret, redactedSecretPlaceholder)
	}
	out = bearerTokenPattern.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Contains(match, redactedSecretPlaceholder) {
			return match
		}
		return "Bearer " + redactedSecretPlaceholder
	})
	out = apiKeyTokenPattern.ReplaceAllString(out, redactedSecretPlaceholder)

	if strings.ContainsRune(out, '\\') {
		unescaped := unescapeJSONSequences(out)
		if containsAnySecretOrToken(unescaped, secrets) {
			return genericHTTPFallback(status)
		}
	}

	out = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(out)
	out = strings.TrimSpace(out)
	runes := []rune(out)
	if len(runes) > maxErrorMessageChars {
		return string(runes[:maxErrorMessageChars]) + "..."
	}
	return out
}

func containsAnySecretOrToken(s string, secrets []string) bool {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(s, secret) {
			return true
		}
	}
	if apiKeyTokenPattern.MatchString(s) {
		return true
	}
	for _, m := range bearerTokenPattern.FindAllString(s, -1) {
		if !strings.Contains(m, redactedSecretPlaceholder) {
			return true
		}
	}
	return false
}

// unescapeJSONSequences decodes JSON escape sequences (including \", \\, \/, \b, \f, \n, \r, \t,
// and \uXXXX / UTF-16 surrogate pairs) in a single pass across multiline strings.
func unescapeJSONSequences(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\\', '/':
				sb.WriteByte(s[i+1])
				i += 2
				continue
			case 'b':
				sb.WriteByte('\b')
				i += 2
				continue
			case 'f':
				sb.WriteByte('\f')
				i += 2
				continue
			case 'n':
				sb.WriteByte('\n')
				i += 2
				continue
			case 'r':
				sb.WriteByte('\r')
				i += 2
				continue
			case 't':
				sb.WriteByte('\t')
				i += 2
				continue
			case 'u':
				if i+6 <= len(s) {
					if r1, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
						u1 := rune(r1)
						if utf16.IsSurrogate(u1) && i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
							if r2, err2 := strconv.ParseUint(s[i+8:i+12], 16, 32); err2 == nil {
								sb.WriteRune(utf16.DecodeRune(u1, rune(r2)))
								i += 12
								continue
							}
						}
						sb.WriteRune(u1)
						i += 6
						continue
					}
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func collectSecrets(target ProbeTarget) []string {
	seen := make(map[string]struct{})
	var secrets []string
	addVariant := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		secrets = append(secrets, s)
	}
	addWithEncodings := func(s string) {
		if s == "" {
			return
		}
		addVariant(s)
		trimmed := strings.TrimSpace(s)
		addVariant(trimmed)
		if len(trimmed) >= 4 {
			addVariant(url.QueryEscape(trimmed))
		}
		if rawJSON, err := json.Marshal(trimmed); err == nil && len(rawJSON) >= 2 {
			addVariant(string(rawJSON[1 : len(rawJSON)-1]))
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(trimmed); err == nil {
			escaped := strings.TrimSpace(buf.String())
			if len(escaped) >= 2 {
				addVariant(escaped[1 : len(escaped)-1])
			}
		}
	}

	if target.APIKey != "" {
		addWithEncodings(target.APIKey)
	}
	if target.ProxyURL != "" {
		if parsed, err := url.Parse(strings.TrimSpace(target.ProxyURL)); err == nil && parsed.User != nil {
			if pw, ok := parsed.User.Password(); ok {
				addWithEncodings(pw)
			}
		}
	}
	for k, v := range target.ExtraHeaders {
		lower := strings.ToLower(strings.TrimSpace(k))
		if strings.Contains(lower, "auth") ||
			strings.Contains(lower, "key") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "cookie") ||
			strings.Contains(lower, "pass") {
			if len(strings.TrimSpace(v)) >= 4 {
				addWithEncodings(v)
			}
		}
	}

	// Sort longest first so a shorter substring never leaves part of a secret exposed.
	sort.Slice(secrets, func(i, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return secrets
}
