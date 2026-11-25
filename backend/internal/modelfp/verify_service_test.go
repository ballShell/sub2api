package modelfp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai_compat"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type discoverMockProbeClient struct {
	*mockProbeClient
	discoverFn func(ctx context.Context, target ProbeTarget) ([]string, error)
}

func (m *discoverMockProbeClient) DiscoverModels(ctx context.Context, target ProbeTarget) ([]string, error) {
	if m.discoverFn != nil {
		return m.discoverFn(ctx, target)
	}
	return m.mockProbeClient.DiscoverModels(ctx, target)
}

type blockingCreateRunStore struct {
	*MemoryStore
	inCreate      chan struct{}
	releaseCreate chan struct{}
	mu            sync.Mutex
	lastCreatedID int64
}

func (b *blockingCreateRunStore) CreateRun(ctx context.Context, run Run) (*Run, error) {
	created, err := b.MemoryStore.CreateRun(ctx, run)
	if err == nil && created != nil {
		b.mu.Lock()
		b.lastCreatedID = created.ID
		b.mu.Unlock()
	}
	close(b.inCreate)
	<-b.releaseCreate
	return created, err
}

func newTestVerifyEnv(
	t *testing.T,
	client ProbeClient,
	accounts AccountLookup,
	proxies ProxyLookup,
) (*Service, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	if accounts == nil {
		accounts = &stubAccountLookup{}
	}
	if proxies == nil {
		proxies = &stubProxyLookup{}
	}
	resolver := NewTargetResolverWithOptions(
		accounts,
		proxies,
		withResolverLookupNetIPForTest(func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}),
	)
	if client == nil {
		client = &mockProbeClient{}
	}
	orch := NewOrchestrator(client)
	baselines := NewBaselineService(store, resolver, orch)
	svc := NewService(nil, store, client, resolver, orch, baselines)
	t.Cleanup(func() {
		_ = svc.Stop()
	})
	return svc, store
}

func waitForRunTerminal(t *testing.T, svc *Service, runID int64) *RunDetail {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		detail, err := svc.GetRun(context.Background(), runID)
		require.NoError(t, err)
		if detail.Status == RunStatusCompleted || detail.Status == RunStatusCancelled || detail.Status == RunStatusFailed {
			return detail
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %d did not reach terminal status in time", runID)
	return nil
}

func TestVerifyServiceBatchExecutionAndSummary(t *testing.T) {
	ctx := context.Background()

	accounts := &stubAccountLookup{
		accounts: map[int64]*service.Account{
			10: {
				ID:       10,
				Name:     "Relay Account",
				Platform: service.PlatformOpenAI,
				Type:     service.AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":  "sk-acct-verify-secret-111",
					"base_url": "https://relay.example.com/v1",
					"model_mapping": map[string]any{
						"gpt-4o": "gpt-4o-2024-11-20",
					},
				},
				Extra: map[string]any{
					openai_compat.ExtraKeyResponsesSupported: false,
				},
			},
		},
	}

	var activeProbes atomic.Int32
	var maxConcurrent atomic.Int32

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, upstreamModel string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			cur := activeProbes.Add(1)
			for {
				prev := maxConcurrent.Load()
				if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
			defer activeProbes.Add(-1)

			switch upstreamModel {
			case "gpt-4o-2024-11-20":
				if probe.Kind == DetectorLogprobs {
					if probe.ID == "lp-1" {
						return ProbeCallResult{
							Logprobs:          []TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.25}},
							LogprobsSupported: true,
							PromptTokens:      20,
							HTTPStatus:        200,
						}
					}
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: "ok", Prob: 0.85}, {Token: "ready", Prob: 0.10}},
						LogprobsSupported: true,
						PromptTokens:      20,
						HTTPStatus:        200,
					}
				}
				return ProbeCallResult{Text: "ok", HTTPStatus: 200}

			case "gpt-4o-fake":
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: "completely", Prob: 0.90}, {Token: "different", Prob: 0.08}},
						LogprobsSupported: true,
						PromptTokens:      4200, // Triggers prompt_injection_suspected (>500)
						HTTPStatus:        200,
					}
				}
				return ProbeCallResult{Text: "wrong", HTTPStatus: 200}

			case "unmapped-model":
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: "other", Prob: 0.80}},
						LogprobsSupported: true,
						PromptTokens:      30,
						HTTPStatus:        200,
					}
				}
				return ProbeCallResult{Text: "ok", HTTPStatus: 200}

			case "broken-model":
				return ProbeCallResult{
					HTTPStatus:   404,
					ErrorCode:    errorCodeModelNotFound,
					ErrorMessage: "model not found",
				}

			default:
				return ProbeCallResult{HTTPStatus: 404, ErrorCode: errorCodeModelNotFound, ErrorMessage: "unknown"}
			}
		},
	}

	svc, store := newTestVerifyEnv(t, client, accounts, nil)
	require.NoError(t, svc.Start(ctx))

	suite := seedMinimalSuite(t, store)
	_, err := store.UpdateSuiteStatus(ctx, suite.ID, StatusActive, true)
	require.NoError(t, err)

	// Seed baselines for gpt-4o (used by gpt-4o-aliased via family/model mapping) and gpt-4o-fake (different sig -> mismatch).
	_, err = store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "gpt-4o",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          suite.ID,
		DetectorKind:     DetectorLogprobs,
		SourceType:       SourceOfficialDirect,
		MatchThreshold:   0.08,
		SuspectThreshold: 0.20,
		Logprobs: makeLogprobsSignatureFromProbes(
			[]TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.25}},
			[]TokenProb{{Token: "ok", Prob: 0.85}, {Token: "ready", Prob: 0.10}},
		),
	})
	require.NoError(t, err)

	_, err = store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "gpt-4o-fake",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          suite.ID,
		DetectorKind:     DetectorLogprobs,
		SourceType:       SourceOfficialDirect,
		MatchThreshold:   0.08,
		SuspectThreshold: 0.20,
		Logprobs: makeLogprobsSignatureFromProbes(
			[]TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.25}},
			[]TokenProb{{Token: "ok", Prob: 0.85}, {Token: "ready", Prob: 0.10}},
		),
	})
	require.NoError(t, err)

	accID := int64(10)
	detail, err := svc.StartRun(ctx, CreateRunRequest{
		TargetSource: TargetSourceAccount,
		AccountID:    &accID,
		Models:       []string{"gpt-4o", "gpt-4o-fake", "unmapped-model", "broken-model"},
		Concurrency:  2,
	}, 99)
	require.NoError(t, err)
	require.Equal(t, 4, detail.TotalModels)
	require.Equal(t, int64(99), detail.CreatedBy)
	require.Equal(t, suite.ID, detail.SuiteID)

	done := waitForRunTerminal(t, svc, detail.ID)
	require.Equal(t, RunStatusCompleted, done.Status)
	require.Equal(t, 4, done.CompletedModels)
	require.NotNil(t, done.StartedAt)
	require.NotNil(t, done.FinishedAt)
	require.LessOrEqual(t, maxConcurrent.Load(), int32(2))
	require.Equal(t, int32(2), maxConcurrent.Load(), "expected concurrency 2 to run 2 models concurrently")

	require.Equal(t, RunSummary{
		Match:              1,
		Mismatch:           1,
		Unverified:         1,
		Error:              1,
		InjectionSuspected: 1,
	}, done.Summary)
	require.Len(t, done.Items, 4)

	byClaimed := make(map[string]RunItem, len(done.Items))
	for _, it := range done.Items {
		byClaimed[it.ClaimedModel] = it
	}

	mapped := byClaimed["gpt-4o"]
	require.Equal(t, "gpt-4o", mapped.ClaimedModel)
	require.Equal(t, "gpt-4o-2024-11-20", mapped.UpstreamModel)
	require.Equal(t, VerdictMatch, mapped.Verdict)

	fake := byClaimed["gpt-4o-fake"]
	require.Equal(t, VerdictMismatch, fake.Verdict)
	require.True(t, fake.PromptInjectionSuspected)
	require.Equal(t, 4200, fake.ObservedPromptTokens)

	require.Equal(t, VerdictUnverified, byClaimed["unmapped-model"].Verdict)
	require.Equal(t, VerdictError, byClaimed["broken-model"].Verdict)

	page, err := svc.ListRuns(ctx, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)
	require.Equal(t, done.Summary, page.Items[0].Summary)
	require.Equal(t, 4, page.Items[0].CompletedModels)
}

func TestVerifyServiceCancelAndModelNormalization(t *testing.T) {
	ctx := context.Background()

	t.Run("normalizes_trims_drops_blanks_dedups_before_50_cap", func(t *testing.T) {
		svc, store := newTestVerifyEnv(t, nil, nil, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		// 60 entries containing blanks and duplicates, collapsing to exactly 50 unique models.
		models := make([]string, 0, 60)
		models = append(models, "", "   ", "\t\n")
		for i := 1; i <= 50; i++ {
			models = append(models, fmt.Sprintf("  model-%02d ", i))
		}
		models = append(models, "model-01", " model-02", "model-50  ", "", "   ", "model-03", "model-04")

		detail, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-ant-norm-cap-50-key",
			SuiteID:      suite.ID,
			Models:       models,
			Concurrency:  99, // clamped to 5
		}, 1)
		require.NoError(t, err)
		require.Equal(t, 50, detail.TotalModels)

		done := waitForRunTerminal(t, svc, detail.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		require.Len(t, done.Items, 50)
		// Preserve order of first appearance.
		seen := make(map[string]struct{}, 50)
		for _, it := range done.Items {
			seen[it.ClaimedModel] = struct{}{}
		}
		require.Len(t, seen, 50)
		_, hasFirst := seen["model-01"]
		_, hasLast := seen["model-50"]
		require.True(t, hasFirst)
		require.True(t, hasLast)

		// 51 unique models must return 400 before creating a DB row.
		over := append([]string(nil), models...)
		over = append(over, "model-51")
		_, err = svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-ant-norm-cap-51-key",
			SuiteID:      suite.ID,
			Models:       over,
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))
		require.Equal(t, "MODELFP_TOO_MANY_MODELS", infraerrors.Reason(err))

		// Only the 1 successful run exists in store.
		page, err := svc.ListRuns(ctx, 1, 20)
		require.NoError(t, err)
		require.Equal(t, int64(1), page.Total)
	})

	t.Run("rejects_invalid_targets_and_credentials_before_creating_run", func(t *testing.T) {
		accounts := &stubAccountLookup{
			accounts: map[int64]*service.Account{
				1: {ID: 1, Name: "oauth", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth},
			},
		}
		svc, store := newTestVerifyEnv(t, nil, accounts, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		// SSRF loopback blocked -> 400.
		_, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "http://127.0.0.1:8080",
			APIKey:       "sk-ssrf-test-1234",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))

		// OAuth account unsupported -> 400.
		oauthID := int64(1)
		_, err = svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAccount,
			AccountID:    &oauthID,
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))

		// Bad proxy_id -> 400.
		badProxy := int64(999)
		_, err = svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-proxy-test-1234",
			ProxyID:      &badProxy,
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))

		// Credential embedded in model name -> 400.
		secretKey := "sk-embedded-in-model-999"
		_, err = svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       secretKey,
			SuiteID:      suite.ID,
			Models:       []string{"claude-" + secretKey},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))

		page, err := svc.ListRuns(ctx, 1, 20)
		require.NoError(t, err)
		require.Equal(t, int64(0), page.Total)
	})

	t.Run("cancel_run_stops_queued_models_and_sets_cancelled", func(t *testing.T) {
		m1Done := make(chan struct{})
		m2Started := make(chan struct{})
		var m2Once sync.Once
		var m1Once sync.Once

		var mu sync.Mutex
		probedModels := make([]string, 0)

		client := &mockProbeClient{
			handler: func(probeCtx context.Context, _ ProbeTarget, model string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
				mu.Lock()
				probedModels = append(probedModels, model)
				mu.Unlock()

				if model == "model-1" {
					m1Once.Do(func() { close(m1Done) })
					return ProbeCallResult{Text: "ok", HTTPStatus: 200}
				}
				if model == "model-2" {
					m2Once.Do(func() { close(m2Started) })
					<-probeCtx.Done()
					return ProbeCallResult{
						ErrorCode:    errorCodeContextCanceled,
						ErrorMessage: probeCtx.Err().Error(),
					}
				}
				return ProbeCallResult{Text: "ok", HTTPStatus: 200}
			},
		}

		svc, store := newTestVerifyEnv(t, client, nil, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		run, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-ant-cancel-test-1234",
			SuiteID:      suite.ID,
			Models:       []string{"model-1", "model-2", "model-3", "model-4", "model-5"},
			Concurrency:  1,
		}, 1)
		require.NoError(t, err)

		<-m1Done
		<-m2Started

		require.NoError(t, svc.CancelRun(ctx, run.ID))

		detail, err := svc.GetRun(ctx, run.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCancelled, detail.Status)
		require.NotNil(t, detail.FinishedAt)

		// Idempotent re-cancel stays nil; terminal check prevents queued models 3..5 from running.
		require.NoError(t, svc.CancelRun(ctx, run.ID))

		mu.Lock()
		executed := append([]string(nil), probedModels...)
		mu.Unlock()
		for _, m := range executed {
			require.NotEqual(t, "model-3", m)
			require.NotEqual(t, "model-4", m)
			require.NotEqual(t, "model-5", m)
		}
		require.LessOrEqual(t, len(detail.Items), 1)
	})

	t.Run("start_marks_stale_jobs_failed_and_degraded_startup_returns_503", func(t *testing.T) {
		store := NewMemoryStore()
		suite := seedMinimalSuite(t, store)

		staleQueued, err := store.CreateRun(ctx, Run{
			TargetSource: TargetSourceAdHoc,
			TargetLabel:  "stale-q",
			Protocol:     ProtocolOpenAIChat,
			SuiteID:      suite.ID,
			Status:       RunStatusQueued,
			TotalModels:  2,
		})
		require.NoError(t, err)
		staleRunning, err := store.CreateRun(ctx, Run{
			TargetSource: TargetSourceAdHoc,
			TargetLabel:  "stale-r",
			Protocol:     ProtocolOpenAIChat,
			SuiteID:      suite.ID,
			Status:       RunStatusRunning,
			TotalModels:  2,
		})
		require.NoError(t, err)
		staleCap, err := store.CreateCaptureJob(ctx, CaptureJob{
			Status:      RunStatusRunning,
			Protocol:    ProtocolOpenAIChat,
			SuiteID:     suite.ID,
			TotalModels: 1,
		})
		require.NoError(t, err)
		freshActiveRun, err := store.CreateRun(ctx, Run{
			TargetSource: TargetSourceAdHoc,
			TargetLabel:  "fresh-bluegreen-run",
			Protocol:     ProtocolOpenAIChat,
			SuiteID:      suite.ID,
			Status:       RunStatusRunning,
			TotalModels:  2,
		})
		require.NoError(t, err)
		freshActiveJob, err := store.CreateCaptureJob(ctx, CaptureJob{
			Status:      RunStatusRunning,
			Protocol:    ProtocolOpenAIChat,
			SuiteID:     suite.ID,
			TotalModels: 1,
		})
		require.NoError(t, err)

		staleTimestamp := time.Now().UTC().Add(-defaultStaleJobGracePeriod - time.Minute)
		store.mu.Lock()
		for _, id := range []int64{staleQueued.ID, staleRunning.ID} {
			r := store.runs[id]
			r.UpdatedAt = staleTimestamp
			store.runs[id] = r
		}
		cj := store.jobs[staleCap.ID]
		cj.UpdatedAt = staleTimestamp
		store.jobs[staleCap.ID] = cj
		store.mu.Unlock()

		resolver := NewTargetResolverWithOptions(
			&stubAccountLookup{},
			&stubProxyLookup{},
			withResolverLookupNetIPForTest(func(_ context.Context, _, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}),
		)
		client := &mockProbeClient{}
		orch := NewOrchestrator(client)
		baselines := NewBaselineService(store, resolver, orch)

		// Healthy Start with sqlmock DB verifying EnsureSchema executes once + seeds + stale cleanup.
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		for range SchemaStatements() {
			mock.ExpectExec(`.+`).WillReturnResult(sqlmock.NewResult(0, 0))
		}

		svc := NewService(db, store, client, resolver, orch, baselines)
		t.Cleanup(func() { _ = svc.Stop() })

		require.False(t, svc.IsReady())
		_, err = svc.ListRuns(ctx, 1, 20)
		require.Error(t, err)
		require.Equal(t, 503, infraerrors.Code(err))

		require.NoError(t, svc.Start(ctx))
		// Second Start is idempotent and does not re-execute DDL.
		require.NoError(t, svc.Start(ctx))
		require.True(t, svc.IsReady())
		require.NoError(t, mock.ExpectationsWereMet())

		gotQ, err := store.GetRun(ctx, staleQueued.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusFailed, gotQ.Status)
		require.Equal(t, "server restarted", gotQ.ErrorMessage)

		gotR, err := store.GetRun(ctx, staleRunning.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusFailed, gotR.Status)
		require.Equal(t, "server restarted", gotR.ErrorMessage)

		gotCap, err := store.GetCaptureJob(ctx, staleCap.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusFailed, gotCap.Status)
		require.Equal(t, "server restarted", gotCap.ErrorMessage)

		// Active jobs updated within grace period (blue-green draining instance) stay running.
		gotFreshRun, err := store.GetRun(ctx, freshActiveRun.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusRunning, gotFreshRun.Status)
		gotFreshJob, err := store.GetCaptureJob(ctx, freshActiveJob.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusRunning, gotFreshJob.Status)

		// Degraded startup when EnsureSchema fails -> 503 on operations.
		badDB, badMock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = badDB.Close() }()
		badMock.ExpectExec(`.+`).WillReturnError(errors.New("schema permission denied"))

		degradedSvc := NewService(badDB, store, client, resolver, orch, baselines)
		t.Cleanup(func() { _ = degradedSvc.Stop() })

		err = degradedSvc.Start(ctx)
		require.Error(t, err)
		require.False(t, degradedSvc.IsReady())
		require.NoError(t, badMock.ExpectationsWereMet())

		_, err = degradedSvc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-degraded-12345",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 503, infraerrors.Code(err))

		_, err = degradedSvc.ListBaselines(ctx, BaselineFilter{})
		require.Error(t, err)
		require.Equal(t, 503, infraerrors.Code(err))
	})
}

func TestVerifyServiceNeverPersistsAdHocAPIKey(t *testing.T) {
	ctx := context.Background()
	apiKey := "sk-adhoc-secret-never-persist-7788"

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, model string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if model == "echo-error-model" {
				return ProbeCallResult{
					HTTPStatus:   502,
					ErrorCode:    errorCodeUpstreamError,
					ErrorMessage: "upstream echoed key=" + apiKey,
				}
			}
			if probe.Kind == DetectorLogprobs {
				return ProbeCallResult{
					Logprobs: []TokenProb{
						{Token: "tok-" + apiKey, Prob: 0.70},
						{Token: "safe", Prob: 0.25},
					},
					LogprobsSupported: true,
					ResponseModel:     "gpt-4o-" + apiKey,
					SystemFingerprint: "fp-" + apiKey,
					HTTPStatus:        200,
				}
			}
			return ProbeCallResult{
				Text:              "text-" + apiKey,
				ResponseModel:     "gpt-4o-" + apiKey,
				SystemFingerprint: "fp-" + apiKey,
				HTTPStatus:        200,
			}
		},
	}

	svc, store := newTestVerifyEnv(t, client, nil, nil)
	require.NoError(t, svc.Start(ctx))
	suite := seedMinimalSuite(t, store)

	// Baseline exists for gpt-4o so logprobs enrichment & candidate scoring execute.
	_, err := store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "gpt-4o",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          suite.ID,
		DetectorKind:     DetectorLogprobs,
		SourceType:       SourceOfficialDirect,
		MatchThreshold:   0.08,
		SuspectThreshold: 0.20,
		Logprobs: makeLogprobsSignatureFromProbes(
			[]TokenProb{{Token: "safe", Prob: 0.90}},
			[]TokenProb{{Token: "ok", Prob: 0.90}},
		),
	})
	require.NoError(t, err)

	run, err := svc.StartRun(ctx, CreateRunRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       apiKey,
		SuiteID:      suite.ID,
		Models:       []string{"gpt-4o", "echo-error-model"},
		Concurrency:  2,
	}, 1)
	require.NoError(t, err)
	require.NotContains(t, run.TargetLabel, apiKey)

	done := waitForRunTerminal(t, svc, run.ID)
	require.Equal(t, RunStatusCompleted, done.Status)
	require.Len(t, done.Items, 2)

	rawRun, err := json.Marshal(done)
	require.NoError(t, err)
	require.NotContains(t, string(rawRun), apiKey)

	items, err := store.ListRunItems(ctx, run.ID)
	require.NoError(t, err)
	rawItems, err := json.Marshal(items)
	require.NoError(t, err)
	require.NotContains(t, string(rawItems), apiKey)
	require.Contains(t, string(rawItems), redactedSecretPlaceholder)
}

func TestVerifyServiceDiscoverModelsDeleteAndShutdownTimeout(t *testing.T) {
	ctx := context.Background()

	t.Run("discover_models_adhoc_and_account_with_defaults", func(t *testing.T) {
		accounts := &stubAccountLookup{
			accounts: map[int64]*service.Account{
				7: {
					ID:       7,
					Name:     "OpenAI Key",
					Platform: service.PlatformOpenAI,
					Type:     service.AccountTypeAPIKey,
					Credentials: map[string]any{
						"api_key":  "sk-discover-acct-999",
						"base_url": "https://api.example.com/v1",
					},
					Extra: map[string]any{
						openai_compat.ExtraKeyResponsesSupported: false,
					},
				},
			},
		}
		client := &discoverMockProbeClient{
			mockProbeClient: &mockProbeClient{},
			discoverFn: func(_ context.Context, target ProbeTarget) ([]string, error) {
				if strings.Contains(target.BaseURL, "fail.example.com") {
					return nil, fmt.Errorf("upstream failed with %s", target.APIKey)
				}
				if strings.Contains(target.BaseURL, "timeout.example.com") {
					return nil, context.DeadlineExceeded
				}
				return []string{"gpt-4o", "gpt-4.1"}, nil
			},
		}

		svc, store := newTestVerifyEnv(t, client, accounts, nil)
		require.NoError(t, svc.Start(ctx))

		acctID := int64(7)
		res, err := svc.DiscoverModels(ctx, DiscoverModelsRequest{
			TargetSource: TargetSourceAccount,
			AccountID:    &acctID,
		})
		require.NoError(t, err)
		require.Equal(t, TargetSourceAccount, res.TargetSource)
		require.Equal(t, ProtocolOpenAIChat, res.Protocol)
		require.Equal(t, []string{"gpt-4o", "gpt-4.1"}, res.Models)
		require.NotEmpty(t, res.DefaultModels)
		require.NotContains(t, res.TargetLabel, "sk-discover-acct-999")

		// Verify explicit protocol override on account discovery and baseline delegation.
		resOverride, err := svc.DiscoverModels(ctx, DiscoverModelsRequest{
			TargetSource: TargetSourceAccount,
			AccountID:    &acctID,
			Protocol:     ProtocolOpenAIResponses,
		})
		require.NoError(t, err)
		require.Equal(t, ProtocolOpenAIResponses, resOverride.Protocol)

		suites, err := svc.ListSuites(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, suites)
		require.NotNil(t, svc.Baselines())

		// Discovery failure redacts ad-hoc secret; timeout maps to 504; SSRF maps to 400.
		secret := "sk-discover-secret-fail-123"
		_, err = svc.DiscoverModels(ctx, DiscoverModelsRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://fail.example.com/v1",
			APIKey:       secret,
		})
		require.Error(t, err)
		require.Equal(t, 502, infraerrors.Code(err))
		require.NotContains(t, err.Error(), secret)

		_, err = svc.DiscoverModels(ctx, DiscoverModelsRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://timeout.example.com/v1",
			APIKey:       "sk-discover-timeout-123",
		})
		require.Error(t, err)
		require.Equal(t, 504, infraerrors.Code(err))

		_, err = svc.DiscoverModels(ctx, DiscoverModelsRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "http://169.254.169.254",
			APIKey:       "sk-discover-ssrf-123",
		})
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))
		require.ErrorIs(t, err, ErrSSRFBlocked)

		// Invalid run ID / not found / cancelling finished run edge cases.
		_, err = svc.GetRun(ctx, 0)
		require.Equal(t, 400, infraerrors.Code(err))
		_, err = svc.GetRun(ctx, 99999)
		require.ErrorIs(t, err, ErrNotFound)
		require.Equal(t, 400, infraerrors.Code(svc.CancelRun(ctx, 0)))
		require.ErrorIs(t, svc.CancelRun(ctx, 99999), ErrNotFound)
		require.Equal(t, 400, infraerrors.Code(svc.DeleteRun(ctx, 0)))

		suite := seedMinimalSuite(t, store)
		completedRun, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-finished-cancel-1234",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.NoError(t, err)
		done := waitForRunTerminal(t, svc, completedRun.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		require.Equal(t, 409, infraerrors.Code(svc.CancelRun(ctx, completedRun.ID)))
	})

	t.Run("delete_run_cancels_active_run_and_removes_items", func(t *testing.T) {
		started := make(chan struct{})
		var once sync.Once
		client := &mockProbeClient{
			handler: func(probeCtx context.Context, _ ProbeTarget, _ string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
				once.Do(func() { close(started) })
				<-probeCtx.Done()
				return ProbeCallResult{ErrorCode: errorCodeContextCanceled, ErrorMessage: probeCtx.Err().Error()}
			},
		}
		svc, store := newTestVerifyEnv(t, client, nil, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		run, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-delete-active-1234",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.NoError(t, err)
		<-started

		require.NoError(t, svc.DeleteRun(ctx, run.ID))
		_, err = svc.GetRun(ctx, run.ID)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("stop_waits_for_inflight_create_and_bounds_shutdown_timeout", func(t *testing.T) {
		baseStore := NewMemoryStore()
		suite := seedMinimalSuite(t, baseStore)

		inCreate := make(chan struct{})
		releaseCreate := make(chan struct{})
		blockingStore := &blockingCreateRunStore{
			MemoryStore:   baseStore,
			inCreate:      inCreate,
			releaseCreate: releaseCreate,
		}
		resolver := NewTargetResolverWithOptions(
			&stubAccountLookup{},
			&stubProxyLookup{},
			withResolverLookupNetIPForTest(func(_ context.Context, _, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}),
		)
		orch := NewOrchestrator(&mockProbeClient{})
		baselines := NewBaselineService(blockingStore, resolver, orch)
		svc := NewService(nil, blockingStore, &mockProbeClient{}, resolver, orch, baselines)
		require.NoError(t, svc.Start(ctx))

		var startErr error
		startDone := make(chan struct{})
		go func() {
			defer close(startDone)
			_, startErr = svc.StartRun(ctx, CreateRunRequest{
				TargetSource: TargetSourceAdHoc,
				Protocol:     ProtocolAnthropic,
				BaseURL:      "https://api.anthropic.com",
				APIKey:       "sk-stop-create-race-1234",
				SuiteID:      suite.ID,
				Models:       []string{"claude-sonnet-4-6"},
			}, 1)
		}()

		<-inCreate
		stopDone := make(chan error, 1)
		go func() {
			stopDone <- svc.Stop()
		}()

		select {
		case <-stopDone:
			t.Fatalf("Stop returned while CreateRun was still in flight")
		case <-time.After(50 * time.Millisecond):
		}

		close(releaseCreate)
		<-startDone
		require.NoError(t, <-stopDone)
		require.Error(t, startErr)
		require.Equal(t, 503, infraerrors.Code(startErr))

		persisted, err := baseStore.GetRun(ctx, blockingStore.lastCreatedID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCancelled, persisted.Status)

		// Verify bounded shutdown timeout if a worker ignores ctx.Done().
		stuckEntered := make(chan struct{})
		releaseStuck := make(chan struct{})
		defer close(releaseStuck)

		stuckClient := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
				close(stuckEntered)
				<-releaseStuck
				return ProbeCallResult{Text: "ok", HTTPStatus: 200}
			},
		}
		stuckStore := NewMemoryStore()
		stuckSuite := seedMinimalSuite(t, stuckStore)
		stuckOrch := NewOrchestrator(stuckClient)
		stuckSvc := NewService(nil, stuckStore, stuckClient, resolver, stuckOrch, NewBaselineService(stuckStore, resolver, stuckOrch))
		stuckSvc.shutdownTimeout = 50 * time.Millisecond
		require.NoError(t, stuckSvc.Start(ctx))

		_, err = stuckSvc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-stuck-worker-1234",
			SuiteID:      stuckSuite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.NoError(t, err)
		<-stuckEntered

		stopErr := stuckSvc.Stop()
		require.Error(t, stopErr)
		require.ErrorIs(t, stopErr, context.DeadlineExceeded)
	})
}

func TestVerifyServiceCustomHeadersPrivateSuiteAndLimits(t *testing.T) {
	ctx := context.Background()

	t.Run("redacts_custom_extra_headers_in_discovery_and_run_evidence", func(t *testing.T) {
		customPass := "my-custom-pass-99"
		client := &discoverMockProbeClient{
			mockProbeClient: &mockProbeClient{
				handler: func(_ context.Context, target ProbeTarget, model string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
					passed := target.ExtraHeaders["X-Relay-Pass"]
					if model == "fail-model" {
						return ProbeCallResult{
							HTTPStatus:   502,
							ErrorCode:    errorCodeUpstreamError,
							ErrorMessage: "upstream echoed pass=" + passed,
						}
					}
					return ProbeCallResult{
						Text:              "text-" + passed,
						ResponseModel:     "gpt-4o-" + passed,
						SystemFingerprint: "fp-" + passed,
						HTTPStatus:        200,
					}
				},
			},
			discoverFn: func(_ context.Context, target ProbeTarget) ([]string, error) {
				return nil, fmt.Errorf("upstream bad header %s", target.ExtraHeaders["X-Relay-Pass"])
			},
		}

		svc, store := newTestVerifyEnv(t, client, nil, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		_, discErr := svc.DiscoverModels(ctx, DiscoverModelsRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-custom-hdr-key-1234",
			ExtraHeaders: map[string]string{"X-Relay-Pass": customPass},
		})
		require.Error(t, discErr)
		require.NotContains(t, discErr.Error(), customPass)
		require.Contains(t, discErr.Error(), redactedSecretPlaceholder)

		run, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-custom-hdr-key-1234",
			ExtraHeaders: map[string]string{"X-Relay-Pass": customPass},
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6", "fail-model"},
		}, 1)
		require.NoError(t, err)

		done := waitForRunTerminal(t, svc, run.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		raw, err := json.Marshal(done)
		require.NoError(t, err)
		require.NotContains(t, string(raw), customPass)
		require.Contains(t, string(raw), redactedSecretPlaceholder)
	})

	t.Run("private_suite_strips_observed_and_baseline_text_and_keeps_telemetry", func(t *testing.T) {
		canaryPrompt := "CANARY_SECRET_PROMPT_XYZ"
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				return ProbeCallResult{
					Text:               "Answer: " + canaryPrompt,
					PromptTokens:       42,
					CachedPromptTokens: 12,
					OutputTokens:       9,
					LatencyMS:          88,
					HTTPStatus:         200,
				}
			},
		}
		svc, store := newTestVerifyEnv(t, client, nil, nil)
		require.NoError(t, svc.Start(ctx))

		privSuite, err := store.CreateSuite(ctx, ProbeSuite{
			SuiteKey:   "priv-canary",
			Version:    "v1",
			Name:       "Private Canary",
			Visibility: VisibilityPrivate,
			Status:     StatusActive,
			Probes: []ProbeDefinition{
				{ID: "bh-priv-1", Kind: DetectorBehavior, Prompt: canaryPrompt, MaxTokens: 32, Weight: 1.0, ExpectedMaxPromptTokens: 500},
			},
		})
		require.NoError(t, err)

		_, err = store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel:   "claude-sonnet-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          privSuite.ID,
			DetectorKind:     DetectorBehavior,
			SourceType:       SourceOfficialDirect,
			MatchThreshold:   0.35,
			SuspectThreshold: 0.55,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-priv-1": {ProbeID: "bh-priv-1", Samples: []string{"Answer: " + canaryPrompt}},
				},
			},
		})
		require.NoError(t, err)

		run, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-priv-suite-key-1234",
			SuiteID:      privSuite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.NoError(t, err)

		done := waitForRunTerminal(t, svc, run.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		require.Len(t, done.Items, 1)
		item := done.Items[0]
		require.Equal(t, VerdictMatch, item.Verdict)
		require.Greater(t, item.Confidence, 0.0)
		require.Len(t, item.Evidence, 1)
		ev := item.Evidence[0]
		require.Equal(t, "bh-priv-1", ev.ProbeID)
		require.Equal(t, DetectorBehavior, ev.DetectorKind)
		require.Equal(t, 42, ev.PromptTokens)
		require.Equal(t, 12, ev.CachedPromptTokens)
		require.Equal(t, 88, ev.LatencyMS)
		require.Empty(t, ev.ObservedText)
		require.Empty(t, ev.BaselineSampleText)

		persisted, err := store.ListRunItems(ctx, run.ID)
		require.NoError(t, err)
		rawItems, err := json.Marshal(persisted)
		require.NoError(t, err)
		require.NotContains(t, string(rawItems), canaryPrompt)
	})

	t.Run("cancel_run_terminal_conflict_in_handle_and_fallback_paths", func(t *testing.T) {
		svc, store := newTestVerifyEnv(t, nil, nil, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		// Handle present + finished == true with Completed status -> 409 MODELFP_RUN_ALREADY_FINISHED.
		finishedRun, err := store.CreateRun(ctx, Run{
			TargetSource: TargetSourceAdHoc,
			TargetLabel:  "finished-in-handle",
			Protocol:     ProtocolAnthropic,
			SuiteID:      suite.ID,
			Status:       RunStatusCompleted,
			TotalModels:  1,
		})
		require.NoError(t, err)
		svc.verify.mu.Lock()
		svc.verify.activeRuns[finishedRun.ID] = &activeRunHandle{
			cancel:   func() {},
			done:     make(chan struct{}),
			finished: true,
			run:      *finishedRun,
		}
		svc.verify.mu.Unlock()
		err = svc.CancelRun(ctx, finishedRun.ID)
		require.Error(t, err)
		require.Equal(t, 409, infraerrors.Code(err))
		require.Equal(t, "MODELFP_RUN_ALREADY_FINISHED", infraerrors.Reason(err))
		svc.verify.removeActiveRun(finishedRun.ID)

		// Fallback path (handle == nil) when DB row concurrently completes before UpdateRunProgress -> 409.
		raceBase := NewMemoryStore()
		raceSuite := seedMinimalSuite(t, raceBase)
		raceRun, err := raceBase.CreateRun(ctx, Run{
			TargetSource: TargetSourceAdHoc,
			TargetLabel:  "race-run",
			Protocol:     ProtocolAnthropic,
			SuiteID:      raceSuite.ID,
			Status:       RunStatusRunning,
			TotalModels:  1,
		})
		require.NoError(t, err)

		racyStore := &completeOnRunUpdateStore{MemoryStore: raceBase}
		resolver := NewTargetResolverWithOptions(&stubAccountLookup{}, &stubProxyLookup{})
		orch := NewOrchestrator(&mockProbeClient{})
		raceSvc := NewService(nil, racyStore, &mockProbeClient{}, resolver, orch, NewBaselineService(racyStore, resolver, orch))
		require.NoError(t, raceSvc.Start(ctx))
		t.Cleanup(func() { _ = raceSvc.Stop() })

		// Even with an already-cancelled caller ctx? No, GetRun uses caller ctx, then bounded cleanupCtx finishes/checks conflict;
		// test normal caller ctx triggering concurrent completion inside UpdateRunProgress.
		err = raceSvc.CancelRun(ctx, raceRun.ID)
		require.Error(t, err)
		require.Equal(t, 409, infraerrors.Code(err))
		require.Equal(t, "MODELFP_RUN_ALREADY_FINISHED", infraerrors.Reason(err))
	})

	t.Run("enforces_max_active_verify_runs_limit", func(t *testing.T) {
		release := make(chan struct{})
		entered := make(chan struct{}, maxActiveVerifyRuns)
		client := &mockProbeClient{
			handler: func(probeCtx context.Context, _ ProbeTarget, _ string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
				select {
				case <-release:
					return ProbeCallResult{Text: "ok", HTTPStatus: 200}
				default:
				}
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
					return ProbeCallResult{Text: "ok", HTTPStatus: 200}
				case <-probeCtx.Done():
					return ProbeCallResult{ErrorCode: errorCodeContextCanceled, ErrorMessage: probeCtx.Err().Error()}
				}
			},
		}
		svc, store := newTestVerifyEnv(t, client, nil, nil)
		require.NoError(t, svc.Start(ctx))
		suite := seedMinimalSuite(t, store)

		runIDs := make([]int64, 0, maxActiveVerifyRuns)
		for i := 0; i < maxActiveVerifyRuns; i++ {
			run, err := svc.StartRun(ctx, CreateRunRequest{
				TargetSource: TargetSourceAdHoc,
				Protocol:     ProtocolAnthropic,
				BaseURL:      "https://api.anthropic.com",
				APIKey:       fmt.Sprintf("sk-limit-run-%d-1234", i),
				SuiteID:      suite.ID,
				Models:       []string{"claude-sonnet-4-6"},
			}, 1)
			require.NoError(t, err)
			runIDs = append(runIDs, run.ID)
		}
		for i := 0; i < maxActiveVerifyRuns; i++ {
			<-entered
		}

		_, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-limit-run-over-1234",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 429, infraerrors.Code(err))
		require.Equal(t, "MODELFP_TOO_MANY_ACTIVE_JOBS", infraerrors.Reason(err))

		page, err := svc.ListRuns(ctx, 1, 20)
		require.NoError(t, err)
		require.Equal(t, int64(maxActiveVerifyRuns), page.Total)

		close(release)
		for _, id := range runIDs {
			waitForRunTerminal(t, svc, id)
		}

		// Once active runs complete, another run is allowed.
		nextRun, err := svc.StartRun(ctx, CreateRunRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-limit-run-after-1234",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.NoError(t, err)
		done := waitForRunTerminal(t, svc, nextRun.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
	})
}

type completeOnRunUpdateStore struct {
	*MemoryStore
}

func (c *completeOnRunUpdateStore) UpdateRunProgress(ctx context.Context, run Run) error {
	now := time.Now().UTC()
	_ = c.MemoryStore.UpdateRunProgress(ctx, Run{
		ID:              run.ID,
		Status:          RunStatusCompleted,
		CompletedModels: 1,
		FinishedAt:      &now,
	})
	return c.MemoryStore.UpdateRunProgress(ctx, run)
}
