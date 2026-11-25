//go:build unit

package modelfp

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func setupHandlerTestRouter(t *testing.T, svc AdminService) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(string(servermiddleware.ContextKeyUser), servermiddleware.AuthSubject{UserID: 42})
		c.Set(string(servermiddleware.ContextKeyUserRole), "admin")
		c.Next()
	})
	h := NewAdminHandler(svc)
	fp := r.Group("/api/v1/admin/model-fingerprint")
	registerTestModelFingerprintGroup(fp, h)
	return r
}

func registerTestModelFingerprintGroup(fp *gin.RouterGroup, h *AdminHandler) {
	fp.POST("/discover-models", h.DiscoverModels)
	fp.POST("/runs", h.CreateRun)
	fp.GET("/runs", h.ListRuns)
	fp.GET("/runs/:id", h.GetRun)
	fp.POST("/runs/:id/cancel", h.CancelRun)
	fp.DELETE("/runs/:id", h.DeleteRun)

	fp.GET("/baselines", h.ListBaselines)
	fp.POST("/baselines/capture", h.StartCapture)
	fp.GET("/baselines/capture/:job_id", h.GetCaptureJob)
	fp.POST("/baselines/confusion-matrix", h.ConfusionMatrix)
	fp.GET("/baselines/export", h.ExportBaselines)
	fp.POST("/baselines/import", h.ImportBaselines)
	fp.PUT("/baselines/:id", h.UpdateBaseline)
	fp.DELETE("/baselines/:id", h.DeleteBaseline)

	fp.GET("/suites", h.ListSuites)
	fp.POST("/suites", h.CreateSuite)
	fp.PUT("/suites/:id/status", h.UpdateSuiteStatus)

	fp.GET("/families", h.ListFamilyMaps)
	fp.PUT("/families/:canonical_model", h.UpsertFamilyMap)
	fp.DELETE("/families/:canonical_model", h.DeleteFamilyMap)
}

func doHandlerJSONRequest(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		switch v := body.(type) {
		case string:
			payload = []byte(v)
		case []byte:
			payload = v
		default:
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			payload = raw
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelopeData[T any](t *testing.T, rec *httptest.ResponseRecorder) (response.Response, T) {
	t.Helper()
	var env struct {
		Code     int               `json:"code"`
		Message  string            `json:"message"`
		Reason   string            `json:"reason,omitempty"`
		Metadata map[string]string `json:"metadata,omitempty"`
		Data     json.RawMessage   `json:"data,omitempty"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	var out T
	if len(env.Data) > 0 && string(env.Data) != "null" {
		require.NoError(t, json.Unmarshal(env.Data, &out))
	}
	return response.Response{
		Code:     env.Code,
		Message:  env.Message,
		Reason:   env.Reason,
		Metadata: env.Metadata,
	}, out
}

func TestAdminHandlerAll20EndpointsHappyPathAndEnvelopes(t *testing.T) {
	ctx := context.Background()
	const adhocSecret = "sk-handler-secret-canary-999"

	var blockMu sync.Mutex
	blockRunCh := make(chan struct{})
	blockEnabled := false

	probeClient := &discoverMockProbeClient{
		mockProbeClient: &mockProbeClient{
			handler: func(pCtx context.Context, _ ProbeTarget, model string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				blockMu.Lock()
				shouldBlock := blockEnabled
				ch := blockRunCh
				blockMu.Unlock()

				if shouldBlock && model == "slow-model" {
					select {
					case <-ch:
					case <-pCtx.Done():
						return ProbeCallResult{ErrorCode: errorCodeContextCanceled, ErrorMessage: pCtx.Err().Error()}
					}
				}

				switch model {
				case "gpt-4o":
					if probe.Kind == DetectorLogprobs {
						if probe.ID == "lp-1" {
							return ProbeCallResult{
								Logprobs:          []TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.25}},
								LogprobsSupported: true,
								PromptTokens:      16,
								HTTPStatus:        200,
							}
						}
						return ProbeCallResult{
							Logprobs:          []TokenProb{{Token: "ok", Prob: 0.85}, {Token: "ready", Prob: 0.10}},
							LogprobsSupported: true,
							PromptTokens:      16,
							HTTPStatus:        200,
						}
					}
					return ProbeCallResult{Text: "alpha-response", ResponseModel: "gpt-4o", HTTPStatus: 200}
				case "gpt-4o-mini":
					if probe.Kind == DetectorLogprobs {
						return ProbeCallResult{
							Logprobs:          []TokenProb{{Token: " mini", Prob: 0.88}, {Token: " fast", Prob: 0.10}},
							LogprobsSupported: true,
							PromptTokens:      14,
							HTTPStatus:        200,
						}
					}
					return ProbeCallResult{Text: "mini-response", ResponseModel: "gpt-4o-mini", HTTPStatus: 200}
				default:
					return ProbeCallResult{Text: "generic-ok", ResponseModel: model, HTTPStatus: 200}
				}
			},
		},
		discoverFn: func(_ context.Context, target ProbeTarget) ([]string, error) {
			require.Equal(t, adhocSecret, target.APIKey)
			return []string{"gpt-4o", "gpt-4o-mini"}, nil
		},
	}

	svc, store := newTestVerifyEnv(t, probeClient, nil, nil)
	require.NoError(t, svc.Start(ctx))

	// Replace seed suite with minimal suite marked default for fast capture/run execution.
	minimalSuite := seedMinimalSuite(t, store)
	_, err := store.UpdateSuiteStatus(ctx, minimalSuite.ID, StatusActive, true)
	require.NoError(t, err)

	router := setupHandlerTestRouter(t, svc)

	// 1. POST /discover-models
	rec := doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/discover-models", DiscoverModelsRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       adhocSecret,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), adhocSecret)
	env, discoverResp := decodeEnvelopeData[DiscoverModelsResponse](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, "success", env.Message)
	require.Equal(t, []string{"gpt-4o", "gpt-4o-mini"}, discoverResp.Models)

	// 2. POST /baselines/capture + 3. GET /baselines/capture/:job_id
	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/baselines/capture", CaptureRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       adhocSecret,
		SuiteID:      minimalSuite.ID,
		Models:       []string{"gpt-4o", "gpt-4o-mini"},
		SampleRounds: 3,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), adhocSecret)
	env, capJob := decodeEnvelopeData[CaptureJob](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, int64(42), capJob.CreatedBy)
	require.Positive(t, capJob.ID)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/baselines/capture/"+strconv.FormatInt(capJob.ID, 10), nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		_, capJob = decodeEnvelopeData[CaptureJob](t, rec)
		if capJob.Status == RunStatusCompleted || capJob.Status == RunStatusFailed || capJob.Status == RunStatusCancelled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, RunStatusCompleted, capJob.Status)
	require.Len(t, capJob.Results, 2)

	// 4. GET /baselines
	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/baselines?protocol=openai_chat&status=active", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, baselines := decodeEnvelopeData[[]BaselineView](t, rec)
	require.Equal(t, 0, env.Code)
	require.Len(t, baselines, 4) // 2 models * (logprobs + behavior)
	require.Equal(t, FreshnessFresh, baselines[0].Freshness)

	// 5. POST /baselines/confusion-matrix
	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/baselines/confusion-matrix", ConfusionMatrixRequest{
		Protocol:     ProtocolOpenAIChat,
		SuiteID:      minimalSuite.ID,
		DetectorKind: DetectorLogprobs,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, cm := decodeEnvelopeData[ConfusionMatrixResult](t, rec)
	require.Equal(t, 0, env.Code)
	require.Len(t, cm.Models, 2)
	require.Len(t, cm.Matrix, 2)

	// 6. PUT /baselines/:id
	newMatch := 0.09
	newNotes := "calibrated via handler"
	rec = doHandlerJSONRequest(t, router, http.MethodPut, "/api/v1/admin/model-fingerprint/baselines/"+strconv.FormatInt(baselines[0].ID, 10), UpdateBaselineRequest{
		MatchThreshold: &newMatch,
		Notes:          &newNotes,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, updatedBaseline := decodeEnvelopeData[BaselineView](t, rec)
	require.Equal(t, 0, env.Code)
	require.InDelta(t, 0.09, updatedBaseline.MatchThreshold, 1e-9)
	require.Equal(t, "calibrated via handler", updatedBaseline.Notes)

	// 7. POST /suites + 8. GET /suites + 9. PUT /suites/:id/status
	const canaryPrompt = "canary-secret-prompt-alpha-919"
	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/suites", CreateSuiteRequest{
		SuiteKey:   "private-canary",
		Version:    "v1",
		Name:       "Private Canary",
		Visibility: VisibilityPrivate,
		Probes: []ProbeDefinition{{
			ID:     "priv-1",
			Kind:   DetectorBehavior,
			Prompt: canaryPrompt,
		}},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, privSuite := decodeEnvelopeData[ProbeSuite](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, int64(42), privSuite.CreatedBy)
	require.Equal(t, VisibilityPrivate, privSuite.Visibility)

	// Duplicate suite returns 409 MODELFP_SUITE_IMMUTABLE
	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/suites", CreateSuiteRequest{
		SuiteKey:   "private-canary",
		Version:    "v1",
		Name:       "Duplicate",
		Visibility: VisibilityPrivate,
		Probes: []ProbeDefinition{{
			ID:     "priv-1",
			Kind:   DetectorBehavior,
			Prompt: canaryPrompt,
		}},
	})
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "MODELFP_SUITE_IMMUTABLE")

	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/suites", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, listedSuites := decodeEnvelopeData[[]ProbeSuite](t, rec)
	require.GreaterOrEqual(t, len(listedSuites), 2)

	rec = doHandlerJSONRequest(t, router, http.MethodPut, "/api/v1/admin/model-fingerprint/suites/"+strconv.FormatInt(privSuite.ID, 10)+"/status", UpdateSuiteStatusRequest{
		Status: StatusArchived,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, archivedSuite := decodeEnvelopeData[ProbeSuite](t, rec)
	require.Equal(t, StatusArchived, archivedSuite.Status)

	// 10. GET /baselines/export (default omits private; include_private=true includes private)
	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/baselines/export", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), canaryPrompt)
	env, publicBundle := decodeEnvelopeData[Bundle](t, rec)
	require.Equal(t, 0, env.Code)
	require.False(t, publicBundle.IncludePrivate)

	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/baselines/export?include_private=true", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, fullBundle := decodeEnvelopeData[Bundle](t, rec)
	require.True(t, fullBundle.IncludePrivate)
	require.Contains(t, rec.Body.String(), canaryPrompt)

	// 11. DELETE /baselines/:id + 12. POST /baselines/import (restores deleted baseline)
	targetBaselineID := baselines[len(baselines)-1].ID
	rec = doHandlerJSONRequest(t, router, http.MethodDelete, "/api/v1/admin/model-fingerprint/baselines/"+strconv.FormatInt(targetBaselineID, 10), nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, delResp := decodeEnvelopeData[map[string]bool](t, rec)
	require.Equal(t, 0, env.Code)
	require.True(t, delResp["deleted"])

	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/baselines/import", ImportBundleRequest{
		Bundle:       publicBundle,
		ConflictMode: ImportConflictSkip,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, importRes := decodeEnvelopeData[ImportBundleResult](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, 1, importRes.BaselinesImported)

	// 13. POST /runs + 14. GET /runs + 15. GET /runs/:id
	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/runs", CreateRunRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       adhocSecret,
		SuiteID:      minimalSuite.ID,
		Models:       []string{"gpt-4o", "gpt-4o-mini"},
		Concurrency:  2,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), adhocSecret)
	env, runDetail := decodeEnvelopeData[RunDetail](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, int64(42), runDetail.CreatedBy)

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/runs/"+strconv.FormatInt(runDetail.ID, 10), nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		_, runDetail = decodeEnvelopeData[RunDetail](t, rec)
		if runDetail.Status == RunStatusCompleted || runDetail.Status == RunStatusFailed || runDetail.Status == RunStatusCancelled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, RunStatusCompleted, runDetail.Status)
	require.Equal(t, 2, runDetail.Summary.Match)
	require.Len(t, runDetail.Items, 2)

	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/runs?page=1&page_size=20", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, runPage := decodeEnvelopeData[RunPage](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, int64(1), runPage.Total)
	require.Len(t, runPage.Items, 1)

	// 16. POST /runs/:id/cancel + 17. DELETE /runs/:id
	blockMu.Lock()
	blockEnabled = true
	blockMu.Unlock()
	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/runs", CreateRunRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       adhocSecret,
		SuiteID:      minimalSuite.ID,
		Models:       []string{"slow-model"},
		Concurrency:  1,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, slowRun := decodeEnvelopeData[RunDetail](t, rec)

	rec = doHandlerJSONRequest(t, router, http.MethodPost, "/api/v1/admin/model-fingerprint/runs/"+strconv.FormatInt(slowRun.ID, 10)+"/cancel", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, cancelResp := decodeEnvelopeData[map[string]bool](t, rec)
	require.Equal(t, 0, env.Code)
	require.True(t, cancelResp["cancelled"])
	close(blockRunCh)

	rec = doHandlerJSONRequest(t, router, http.MethodDelete, "/api/v1/admin/model-fingerprint/runs/"+strconv.FormatInt(slowRun.ID, 10), nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, delRunResp := decodeEnvelopeData[map[string]bool](t, rec)
	require.Equal(t, 0, env.Code)
	require.True(t, delRunResp["deleted"])

	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/runs/"+strconv.FormatInt(slowRun.ID, 10), nil)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// 18. GET /families + 19. PUT /families/:canonical_model + 20. DELETE /families/:canonical_model
	rec = doHandlerJSONRequest(t, router, http.MethodPut, "/api/v1/admin/model-fingerprint/families/custom-family-model", FamilyMap{
		Family:         "custom-family",
		Aliases:        []string{"custom-alias"},
		ConfusionPeers: []string{"other-model"},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, savedFM := decodeEnvelopeData[FamilyMap](t, rec)
	require.Equal(t, 0, env.Code)
	require.Equal(t, "custom-family-model", savedFM.CanonicalModel)
	require.Equal(t, []string{"custom-alias"}, savedFM.Aliases)

	rec = doHandlerJSONRequest(t, router, http.MethodGet, "/api/v1/admin/model-fingerprint/families", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_, families := decodeEnvelopeData[[]FamilyMap](t, rec)
	require.NotEmpty(t, families)

	rec = doHandlerJSONRequest(t, router, http.MethodDelete, "/api/v1/admin/model-fingerprint/families/custom-family-model", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	env, delFMResp := decodeEnvelopeData[map[string]bool](t, rec)
	require.Equal(t, 0, env.Code)
	require.True(t, delFMResp["deleted"])

	rec = doHandlerJSONRequest(t, router, http.MethodDelete, "/api/v1/admin/model-fingerprint/families/custom-family-model", nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAdminHandlerValidationErrorsReturn400(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestVerifyEnv(t, nil, nil, nil)
	require.NoError(t, svc.Start(ctx))
	_ = seedMinimalSuite(t, store)
	router := setupHandlerTestRouter(t, svc)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		// Invalid JSON payloads
		{name: "discover invalid json", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/discover-models", body: "{"},
		{name: "create run invalid json", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/runs", body: "{"},
		{name: "capture invalid json", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/baselines/capture", body: "{"},
		{name: "confusion matrix invalid json", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/baselines/confusion-matrix", body: "{"},
		{name: "update baseline invalid json", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/baselines/1", body: "{"},
		{name: "import invalid json", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/baselines/import", body: "{"},
		{name: "create suite invalid json", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/suites", body: "{"},
		{name: "update suite status invalid json", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/suites/1/status", body: "{"},
		{name: "upsert family invalid json", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/families/gpt-4o", body: "{"},

		// Missing required fields
		{name: "discover missing target", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/discover-models", body: map[string]any{}},
		{name: "create run missing models", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/runs", body: map[string]any{}},
		{name: "capture missing models", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/baselines/capture", body: map[string]any{}},
		{name: "confusion matrix missing protocol", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/baselines/confusion-matrix", body: map[string]any{}},
		{name: "import missing schema", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/baselines/import", body: map[string]any{}},
		{name: "create suite missing key", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/suites", body: map[string]any{}},
		{name: "update suite status empty body", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/suites/1/status", body: map[string]any{}},
		{name: "upsert family path body mismatch", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/families/gpt-4o", body: map[string]any{"canonical_model": "gpt-4o-mini"}},

		// Bad IDs
		{name: "get run bad id alpha", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs/abc", body: nil},
		{name: "get run bad id zero", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs/0", body: nil},
		{name: "cancel run bad id", method: http.MethodPost, path: "/api/v1/admin/model-fingerprint/runs/-1/cancel", body: nil},
		{name: "delete run bad id", method: http.MethodDelete, path: "/api/v1/admin/model-fingerprint/runs/bad", body: nil},
		{name: "get capture bad id", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines/capture/bad", body: nil},
		{name: "update baseline bad id", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/baselines/0", body: map[string]any{"notes": "x"}},
		{name: "delete baseline bad id", method: http.MethodDelete, path: "/api/v1/admin/model-fingerprint/baselines/-2", body: nil},
		{name: "update suite status bad id", method: http.MethodPut, path: "/api/v1/admin/model-fingerprint/suites/bad/status", body: map[string]any{"status": "archived"}},

		// Invalid pagination
		{name: "list runs page zero", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs?page=0", body: nil},
		{name: "list runs page negative", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs?page=-1", body: nil},
		{name: "list runs page non-numeric", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs?page=abc", body: nil},
		{name: "list runs page_size zero", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs?page_size=0", body: nil},
		{name: "list runs page_size over max", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs?page_size=101", body: nil},
		{name: "list runs page overflow", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/runs?page=" + strconv.Itoa(math.MaxInt/20+1) + "&page_size=20", body: nil},

		// Invalid baseline filter & export query
		{name: "list baselines bad protocol", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines?protocol=grpc", body: nil},
		{name: "list baselines bad suite_id", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines?suite_id=abc", body: nil},
		{name: "list baselines bad detector_kind", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines?detector_kind=magic", body: nil},
		{name: "list baselines bad status", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines?status=deleted", body: nil},
		{name: "list baselines bad visibility", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines?visibility=internal", body: nil},
		{name: "export baselines bad include_private", method: http.MethodGet, path: "/api/v1/admin/model-fingerprint/baselines/export?include_private=maybe", body: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doHandlerJSONRequest(t, router, tc.method, tc.path, tc.body)
			require.Equalf(t, http.StatusBadRequest, rec.Code, "body=%s", rec.Body.String())
			var env response.Response
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
			require.Equal(t, http.StatusBadRequest, env.Code)
			require.NotEmpty(t, env.Reason)
		})
	}
}

func TestAdminHandlerDegradedAndNilServiceReturns503(t *testing.T) {
	unstartedSvc, _ := newTestVerifyEnv(t, nil, nil, nil)
	var typedNilSvc *Service

	routers := []struct {
		name       string
		router     *gin.Engine
		wantReason string
	}{
		{name: "nil service", router: setupHandlerTestRouter(t, nil), wantReason: "MODELFP_SERVICE_UNAVAILABLE"},
		{name: "typed nil service", router: setupHandlerTestRouter(t, typedNilSvc), wantReason: "MODELFP_SERVICE_UNAVAILABLE"},
		{name: "unstarted service", router: setupHandlerTestRouter(t, unstartedSvc), wantReason: "MODELFP_SERVICE_NOT_READY"},
	}

	endpoints := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/v1/admin/model-fingerprint/discover-models", DiscoverModelsRequest{TargetSource: TargetSourceAdHoc, Protocol: ProtocolOpenAIChat, BaseURL: "https://api.example.com", APIKey: "sk-123"}},
		{http.MethodPost, "/api/v1/admin/model-fingerprint/runs", CreateRunRequest{TargetSource: TargetSourceAdHoc, Protocol: ProtocolOpenAIChat, BaseURL: "https://api.example.com", APIKey: "sk-123", Models: []string{"gpt-4o"}}},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/runs", nil},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/runs/1", nil},
		{http.MethodPost, "/api/v1/admin/model-fingerprint/runs/1/cancel", nil},
		{http.MethodDelete, "/api/v1/admin/model-fingerprint/runs/1", nil},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/baselines", nil},
		{http.MethodPost, "/api/v1/admin/model-fingerprint/baselines/capture", CaptureRequest{TargetSource: TargetSourceAdHoc, Protocol: ProtocolOpenAIChat, BaseURL: "https://api.example.com", APIKey: "sk-123", Models: []string{"gpt-4o"}}},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/baselines/capture/1", nil},
		{http.MethodPost, "/api/v1/admin/model-fingerprint/baselines/confusion-matrix", ConfusionMatrixRequest{Protocol: ProtocolOpenAIChat}},
		{http.MethodPut, "/api/v1/admin/model-fingerprint/baselines/1", UpdateBaselineRequest{}},
		{http.MethodDelete, "/api/v1/admin/model-fingerprint/baselines/1", nil},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/baselines/export", nil},
		{http.MethodPost, "/api/v1/admin/model-fingerprint/baselines/import", ImportBundleRequest{Bundle: Bundle{SchemaVersion: DefaultBundleSchemaVersion}}},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/suites", nil},
		{http.MethodPost, "/api/v1/admin/model-fingerprint/suites", CreateSuiteRequest{SuiteKey: "k", Version: "v1", Probes: []ProbeDefinition{{ID: "p1", Kind: DetectorBehavior, Prompt: "hi"}}}},
		{http.MethodPut, "/api/v1/admin/model-fingerprint/suites/1/status", UpdateSuiteStatusRequest{Status: StatusArchived}},
		{http.MethodGet, "/api/v1/admin/model-fingerprint/families", nil},
		{http.MethodPut, "/api/v1/admin/model-fingerprint/families/gpt-4o", FamilyMap{Family: "gpt"}},
		{http.MethodDelete, "/api/v1/admin/model-fingerprint/families/gpt-4o", nil},
	}

	for _, rt := range routers {
		t.Run(rt.name, func(t *testing.T) {
			for _, ep := range endpoints {
				rec := doHandlerJSONRequest(t, rt.router, ep.method, ep.path, ep.body)
				require.Equalf(t, http.StatusServiceUnavailable, rec.Code, "%s %s body=%s", ep.method, ep.path, rec.Body.String())
				var env response.Response
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
				require.Equal(t, http.StatusServiceUnavailable, env.Code)
				require.Equal(t, rt.wantReason, env.Reason)
			}
		})
	}
}
