package modelfp

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func newTestBaselineServiceEnv(
	t *testing.T,
	client ProbeClient,
	accounts AccountLookup,
	proxies ProxyLookup,
	nowFn func() time.Time,
) (*BaselineService, *MemoryStore) {
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
	svc := NewBaselineService(store, resolver, orch)
	if nowFn != nil {
		svc.now = nowFn
	}
	t.Cleanup(svc.Stop)
	return svc, store
}

func waitForCaptureJobTerminal(t *testing.T, svc *BaselineService, jobID int64) *CaptureJob {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, err := svc.GetCaptureJob(context.Background(), jobID)
		require.NoError(t, err)
		if job.Status == RunStatusCompleted || job.Status == RunStatusFailed || job.Status == RunStatusCancelled {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("capture job %d did not reach terminal status in time", jobID)
	return nil
}

func seedMinimalSuite(t *testing.T, store Store) *ProbeSuite {
	t.Helper()
	suite, err := store.UpsertSeedSuite(context.Background(), makeTestSuite())
	require.NoError(t, err)
	return suite
}

func TestCaptureJobPersistsBothDetectorsOnLogprobsEndpoint(t *testing.T) {
	ctx := context.Background()

	t.Run("openai_chat_persists_logprobs_and_behavior_and_flags_overlap", func(t *testing.T) {
		var mu sync.Mutex
		lp1Round := 0

		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, model string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
				switch model {
				case "gpt-4o":
					if probe.Kind == DetectorLogprobs {
						if !requestLogprobs {
							t.Fatalf("expected requestLogprobs=true")
						}
						if probe.ID == "lp-1" {
							mu.Lock()
							r := lp1Round
							lp1Round++
							mu.Unlock()
							// Introduce realistic inter-round variation so D_self > 0.
							switch r % 3 {
							case 0:
								return ProbeCallResult{
									Logprobs:          []TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.25}},
									LogprobsSupported: true,
									PromptTokens:      20,
									HTTPStatus:        200,
								}
							case 1:
								return ProbeCallResult{
									Logprobs:          []TokenProb{{Token: " sky", Prob: 0.50}, {Token: " glow", Prob: 0.45}},
									LogprobsSupported: true,
									PromptTokens:      20,
									HTTPStatus:        200,
								}
							default:
								return ProbeCallResult{
									Logprobs:          []TokenProb{{Token: " sky", Prob: 0.85}, {Token: " mist", Prob: 0.10}},
									LogprobsSupported: true,
									PromptTokens:      20,
									HTTPStatus:        200,
								}
							}
						}
						return ProbeCallResult{
							Logprobs:          []TokenProb{{Token: "ok", Prob: 0.85}, {Token: "ready", Prob: 0.10}},
							LogprobsSupported: true,
							PromptTokens:      22,
							HTTPStatus:        200,
						}
					}
					if probe.ID == "bh-1" {
						return ProbeCallResult{
							Text:              `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`,
							ResponseModel:     "gpt-4o-2024-11-20",
							SystemFingerprint: "fp_gpt4o",
							PromptTokens:      32,
							HTTPStatus:        200,
						}
					}
					return ProbeCallResult{
						Text:              "7",
						ResponseModel:     "gpt-4o-2024-11-20",
						SystemFingerprint: "fp_gpt4o",
						PromptTokens:      25,
						HTTPStatus:        200,
					}

				case "gpt-4o-near":
					// Very close logprobs distribution to gpt-4o (< 1.5 * D_self), distinct behavior.
					if probe.Kind == DetectorLogprobs {
						if probe.ID == "lp-1" {
							return ProbeCallResult{
								Logprobs:          []TokenProb{{Token: " sky", Prob: 0.68}, {Token: " mist", Prob: 0.20}, {Token: " glow", Prob: 0.10}},
								LogprobsSupported: true,
								PromptTokens:      20,
								HTTPStatus:        200,
							}
						}
						return ProbeCallResult{
							Logprobs:          []TokenProb{{Token: "ok", Prob: 0.84}, {Token: "ready", Prob: 0.11}},
							LogprobsSupported: true,
							PromptTokens:      22,
							HTTPStatus:        200,
						}
					}
					if probe.ID == "bh-1" {
						return ProbeCallResult{
							Text:          `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`,
							ResponseModel: "gpt-4o-near",
							PromptTokens:  32,
							HTTPStatus:    200,
						}
					}
					return ProbeCallResult{
						Text:          "7",
						ResponseModel: "gpt-4o-near",
						PromptTokens:  25,
						HTTPStatus:    200,
					}
				default:
					return ProbeCallResult{HTTPStatus: 404, ErrorCode: errorCodeModelNotFound, ErrorMessage: "not found"}
				}
			},
		}

		svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
		suite := seedMinimalSuite(t, store)

		// Pre-seed a close peer baseline ("gpt-4o-near") on the same (protocol, suite, logprobs).
		_, err := store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel:    "gpt-4o-near",
			Protocol:          ProtocolOpenAIChat,
			SuiteID:           suite.ID,
			DetectorKind:      DetectorLogprobs,
			SourceType:        SourceOfficialDirect,
			SourceLabel:       "peer",
			SampleCount:       3,
			SelfDivergenceP95: 0.01,
			MatchThreshold:    0.05,
			SuspectThreshold:  0.12,
			Logprobs: makeLogprobsSignatureFromProbes(
				[]TokenProb{{Token: " sky", Prob: 0.68}, {Token: " mist", Prob: 0.20}, {Token: " glow", Prob: 0.10}},
				[]TokenProb{{Token: "ok", Prob: 0.84}, {Token: "ready", Prob: 0.11}},
			),
		})
		require.NoError(t, err)

		secretKey := "sk-capture-openai-secret-999"
		job, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			AdHoc: &AdHocTargetInput{
				Protocol: ProtocolOpenAIChat,
				BaseURL:  "https://api.example.com/v1",
				APIKey:   secretKey,
			},
			SuiteID:      suite.ID,
			Models:       []string{" gpt-4o ", "gpt-4o"},
			SampleRounds: 3,
			SourceType:   SourceOfficialDirect,
			SourceLabel:  "OpenAI Direct",
		}, 42)
		require.NoError(t, err)
		require.Equal(t, 1, job.TotalModels)
		require.Equal(t, 3, job.SampleRounds)

		done := waitForCaptureJobTerminal(t, svc, job.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		require.Equal(t, 1, done.CompletedModels)
		require.Len(t, done.Results, 1)

		res := done.Results[0]
		require.Empty(t, res.Error)
		require.Equal(t, "gpt-4o", res.CanonicalModel)
		require.NotNil(t, res.LogprobsBaselineID)
		require.NotNil(t, res.BehaviorBaselineID)
		require.NotNil(t, res.LogprobsSelfDivP95)
		require.Greater(t, *res.LogprobsSelfDivP95, 0.0)
		require.NotNil(t, res.LogprobsNearestDist)
		require.Less(t, *res.LogprobsNearestDist, 1.5*(*res.LogprobsSelfDivP95))
		require.True(t, res.OverlapWarning, "expected overlap_warning when D_near < 1.5 * D_self")
		require.NotEmpty(t, res.OverlapDetails)

		// Verify persisted rows in store have non-zero calibrated thresholds and no leaked secret.
		lpBase, err := store.GetBaseline(ctx, *res.LogprobsBaselineID)
		require.NoError(t, err)
		require.Equal(t, DetectorLogprobs, lpBase.DetectorKind)
		require.Equal(t, StatusActive, lpBase.Status)
		require.Greater(t, lpBase.MatchThreshold, 0.0)
		require.Greater(t, lpBase.SuspectThreshold, lpBase.MatchThreshold)
		require.NotNil(t, lpBase.Logprobs)

		bhBase, err := store.GetBaseline(ctx, *res.BehaviorBaselineID)
		require.NoError(t, err)
		require.Equal(t, DetectorBehavior, bhBase.DetectorKind)
		require.Equal(t, StatusActive, bhBase.Status)
		require.Greater(t, bhBase.MatchThreshold, 0.0)
		require.Greater(t, bhBase.SuspectThreshold, bhBase.MatchThreshold)
		require.NotNil(t, bhBase.Behavior)

		rawJob, err := json.Marshal(done)
		require.NoError(t, err)
		require.NotContains(t, string(rawJob), secretKey)
	})

	t.Run("anthropic_persists_only_behavior_baseline", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs || requestLogprobs {
					t.Fatalf("anthropic capture must not execute logprobs probes")
				}
				if probe.ID == "bh-1" {
					return ProbeCallResult{
						Text:          `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`,
						ResponseModel: "claude-sonnet-4-6",
						HTTPStatus:    200,
					}
				}
				return ProbeCallResult{Text: "7", ResponseModel: "claude-sonnet-4-6", HTTPStatus: 200}
			},
		}

		svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
		suite := seedMinimalSuite(t, store)

		job, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-ant-secret-12345",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 7)
		require.NoError(t, err)
		require.Equal(t, 3, job.SampleRounds)

		done := waitForCaptureJobTerminal(t, svc, job.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		require.Len(t, done.Results, 1)
		require.Nil(t, done.Results[0].LogprobsBaselineID)
		require.NotNil(t, done.Results[0].BehaviorBaselineID)

		rows, err := store.ListBaselines(ctx, BaselineFilter{CanonicalModel: "claude-sonnet-4-6", Status: StatusActive})
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, DetectorBehavior, rows[0].DetectorKind)
	})

	t.Run("openai_chat_without_logprobs_persists_only_behavior", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{Text: "sky", LogprobsSupported: false, HTTPStatus: 200}
				}
				if probe.ID == "bh-1" {
					return ProbeCallResult{Text: `{"sum":55}`, ResponseModel: "gpt-4o", HTTPStatus: 200}
				}
				return ProbeCallResult{Text: "7", ResponseModel: "gpt-4o", HTTPStatus: 200}
			},
		}
		svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
		suite := seedMinimalSuite(t, store)

		job, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://relay.example.com/v1",
			APIKey:       "sk-relay-12345",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.NoError(t, err)
		done := waitForCaptureJobTerminal(t, svc, job.ID)
		require.Equal(t, RunStatusCompleted, done.Status)
		require.Nil(t, done.Results[0].LogprobsBaselineID)
		require.NotNil(t, done.Results[0].BehaviorBaselineID)
	})

	t.Run("gemini_with_logprobs_persists_both_and_responses_persists_behavior_only", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, target ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
				if target.Protocol == ProtocolOpenAIResponses && (probe.Kind == DetectorLogprobs || requestLogprobs) {
					t.Fatalf("openai_responses must not execute logprobs probes")
				}
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: " sky", Prob: 0.9}},
						LogprobsSupported: true,
						HTTPStatus:        200,
					}
				}
				if probe.ID == "bh-1" {
					return ProbeCallResult{Text: `{"sum":55}`, ResponseModel: "model-x", HTTPStatus: 200}
				}
				return ProbeCallResult{Text: "7", ResponseModel: "model-x", HTTPStatus: 200}
			},
		}

		svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
		suite := seedMinimalSuite(t, store)

		gemJob, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolGemini,
			BaseURL:      "https://generativelanguage.googleapis.com",
			APIKey:       "AIzaTestGeminiKey1234567890",
			SuiteID:      suite.ID,
			Models:       []string{"gemini-2.5-pro"},
		}, 1)
		require.NoError(t, err)
		gemDone := waitForCaptureJobTerminal(t, svc, gemJob.ID)
		require.Equal(t, RunStatusCompleted, gemDone.Status)
		require.NotNil(t, gemDone.Results[0].LogprobsBaselineID)
		require.NotNil(t, gemDone.Results[0].BehaviorBaselineID)

		respJob, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIResponses,
			BaseURL:      "https://api.openai.com/v1",
			APIKey:       "sk-responses-test-12345",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-5"},
		}, 1)
		require.NoError(t, err)
		respDone := waitForCaptureJobTerminal(t, svc, respJob.ID)
		require.Equal(t, RunStatusCompleted, respDone.Status)
		require.Nil(t, respDone.Results[0].LogprobsBaselineID)
		require.NotNil(t, respDone.Results[0].BehaviorBaselineID)
	})
}

func TestExportBundleExcludesPrivateByDefault(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
	require.NoError(t, svc.EnsureSeeds(ctx))

	suites, err := svc.ListSuites(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, suites)
	publicSuite := suites[0]
	require.Equal(t, VisibilityPublic, publicSuite.Visibility)

	privateSuite, err := svc.CreateSuite(ctx, CreateSuiteRequest{
		SuiteKey:   "canary-internal",
		Version:    "v1",
		Name:       "Private Canary Suite",
		Visibility: VisibilityPrivate,
		Probes: []ProbeDefinition{
			{
				ID:          "canary-bh-1",
				Kind:        DetectorBehavior,
				Prompt:      "Secret canary prompt xyz",
				MaxTokens:   32,
				Temperature: 0,
				Weight:      1.0,
			},
		},
	}, 99)
	require.NoError(t, err)
	require.Equal(t, VisibilityPrivate, privateSuite.Visibility)

	_, err = store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "gpt-4o",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          publicSuite.ID,
		DetectorKind:     DetectorBehavior,
		SourceType:       SourceOfficialDirect,
		SourceLabel:      "public-source",
		SampleCount:      3,
		MatchThreshold:   0.18,
		SuspectThreshold: 0.32,
		Behavior: &BehaviorSignature{
			Probes: map[string]BehaviorProbeSignature{
				"bh-json-1": {ProbeID: "bh-json-1", Samples: []string{`{"sum":55}`}},
			},
		},
	})
	require.NoError(t, err)

	_, err = store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "claude-opus-4-6",
		Protocol:         ProtocolAnthropic,
		SuiteID:          privateSuite.ID,
		DetectorKind:     DetectorBehavior,
		SourceType:       SourceOfficialDirect,
		SourceLabel:      "private-canary-source",
		SampleCount:      3,
		MatchThreshold:   0.18,
		SuspectThreshold: 0.32,
		Behavior: &BehaviorSignature{
			Probes: map[string]BehaviorProbeSignature{
				"canary-bh-1": {ProbeID: "canary-bh-1", Samples: []string{"canary-secret-answer"}},
			},
		},
	})
	require.NoError(t, err)

	// Default export (includePrivate=false) must strip private suites and their baselines.
	publicBundle, err := svc.ExportBundle(ctx, false)
	require.NoError(t, err)
	require.False(t, publicBundle.IncludePrivate)
	require.Len(t, publicBundle.SHA256, 64)
	for _, s := range publicBundle.Suites {
		require.NotEqual(t, VisibilityPrivate, s.Visibility)
		require.NotEqual(t, "canary-internal", s.SuiteKey)
	}
	require.Len(t, publicBundle.Baselines, 1)
	require.Equal(t, "gpt-4o", publicBundle.Baselines[0].CanonicalModel)

	rawPublic, err := json.Marshal(publicBundle)
	require.NoError(t, err)
	require.NotContains(t, string(rawPublic), "Secret canary prompt xyz")
	require.NotContains(t, string(rawPublic), "canary-secret-answer")

	// Verify JSON round-trip preserves SHA-256 verification.
	var roundTrippedPublic Bundle
	require.NoError(t, json.Unmarshal(rawPublic, &roundTrippedPublic))

	// Importing publicBundle into a clean service validates sha256 cleanly and excludes private data.
	destPublicSvc, destPublicStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
	impRes, err := destPublicSvc.ImportBundle(ctx, ImportBundleRequest{
		Bundle:       roundTrippedPublic,
		ConflictMode: ImportConflictSkip,
	})
	require.NoError(t, err)
	require.Equal(t, 1, impRes.SuitesImported)
	require.Equal(t, 1, impRes.BaselinesImported)

	destSuites, err := destPublicSvc.ListSuites(ctx)
	require.NoError(t, err)
	require.Len(t, destSuites, 1)
	destBaselines, err := destPublicStore.ListBaselines(ctx, BaselineFilter{})
	require.NoError(t, err)
	require.Len(t, destBaselines, 1)

	// Full export (includePrivate=true) includes private canary suite and its baseline.
	fullBundle, err := svc.ExportBundle(ctx, true)
	require.NoError(t, err)
	require.True(t, fullBundle.IncludePrivate)
	require.Len(t, fullBundle.Suites, 2)
	require.Len(t, fullBundle.Baselines, 2)

	destFullSvc, destFullStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
	fullImpRes, err := destFullSvc.ImportBundle(ctx, ImportBundleRequest{
		Bundle:       *fullBundle,
		ConflictMode: ImportConflictSkip,
	})
	require.NoError(t, err)
	require.Equal(t, 2, fullImpRes.SuitesImported)
	require.Equal(t, 2, fullImpRes.BaselinesImported)

	fullBaselines, err := destFullStore.ListBaselines(ctx, BaselineFilter{Visibility: VisibilityPrivate})
	require.NoError(t, err)
	require.Len(t, fullBaselines, 1)
	require.Equal(t, "claude-opus-4-6", fullBaselines[0].CanonicalModel)
}

func TestImportBundleRejectsTamperedSHA256AndRespectsConflictMode(t *testing.T) {
	ctx := context.Background()
	srcSvc, srcStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
	require.NoError(t, srcSvc.EnsureSeeds(ctx))
	suites, err := srcSvc.ListSuites(ctx)
	require.NoError(t, err)
	suite := suites[0]

	_, err = srcStore.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "gpt-4o",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          suite.ID,
		DetectorKind:     DetectorLogprobs,
		SourceType:       SourceOfficialDirect,
		SourceLabel:      "imported-source",
		SampleCount:      3,
		MatchThreshold:   0.05,
		SuspectThreshold: 0.14,
		Notes:            "from-bundle",
		Logprobs:         makeLogprobsSignatureFromProbes([]TokenProb{{Token: " sky", Prob: 0.9}}, []TokenProb{{Token: "ok", Prob: 0.9}}),
	})
	require.NoError(t, err)

	bundle, err := srcSvc.ExportBundle(ctx, false)
	require.NoError(t, err)

	// Tamper a field without recomputing sha256 -> ErrInvalidBundleChecksum.
	tampered := *bundle
	tampered.Baselines = append([]Baseline(nil), bundle.Baselines...)
	tampered.Baselines[0].Notes = "tampered-notes"
	_, err = srcSvc.ImportBundle(ctx, ImportBundleRequest{Bundle: tampered})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidBundleChecksum), "expected ErrInvalidBundleChecksum, got %v", err)
	require.Equal(t, 400, infraerrors.Code(err))

	// Destination already has an active baseline for the same (model, protocol, suite, detector_kind).
	destSvc, destStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
	require.NoError(t, destSvc.EnsureSeeds(ctx))
	destSuites, err := destSvc.ListSuites(ctx)
	require.NoError(t, err)

	existing, err := destStore.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:   "gpt-4o",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          destSuites[0].ID,
		DetectorKind:     DetectorLogprobs,
		SourceType:       SourceTrustedCloud,
		SourceLabel:      "existing-source",
		SampleCount:      3,
		MatchThreshold:   0.11,
		SuspectThreshold: 0.22,
		Notes:            "existing-notes",
		Logprobs:         makeLogprobsSignatureFromProbes([]TokenProb{{Token: " blue", Prob: 0.9}}, []TokenProb{{Token: "ok", Prob: 0.9}}),
	})
	require.NoError(t, err)

	// conflict_mode="skip" preserves existing baseline.
	skipRes, err := destSvc.ImportBundle(ctx, ImportBundleRequest{
		Bundle:       *bundle,
		ConflictMode: ImportConflictSkip,
	})
	require.NoError(t, err)
	require.Equal(t, 0, skipRes.BaselinesImported)
	require.Equal(t, 1, skipRes.BaselinesSkipped)

	stillExisting, err := destStore.GetBaseline(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, StatusActive, stillExisting.Status)
	require.Equal(t, "existing-notes", stillExisting.Notes)
	require.InDelta(t, 0.11, stillExisting.MatchThreshold, 1e-9)

	// conflict_mode="overwrite" archives old active baseline and inserts bundle baseline.
	owRes, err := destSvc.ImportBundle(ctx, ImportBundleRequest{
		Bundle:       *bundle,
		ConflictMode: ImportConflictOverwrite,
	})
	require.NoError(t, err)
	require.Equal(t, 1, owRes.BaselinesImported)
	require.Equal(t, 0, owRes.BaselinesSkipped)

	activeRows, err := destStore.ListBaselines(ctx, BaselineFilter{CanonicalModel: "gpt-4o", Status: StatusActive})
	require.NoError(t, err)
	require.Len(t, activeRows, 1)
	require.Equal(t, "from-bundle", activeRows[0].Notes)
	require.InDelta(t, 0.05, activeRows[0].MatchThreshold, 1e-9)

	oldRow, err := destStore.GetBaseline(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, StatusArchived, oldRow.Status)
}

func TestBaselineFreshnessMarksStale(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	svc, store := newTestBaselineServiceEnv(t, nil, nil, nil, func() time.Time { return fixedNow })
	suite := seedMinimalSuite(t, store)

	// Collected 65 days ago with 60-day TTL -> stale.
	staleCollected := fixedNow.Add(-65 * 24 * time.Hour)
	_, err := store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel: "stale-model",
		Protocol:       ProtocolOpenAIChat,
		SuiteID:        suite.ID,
		DetectorKind:   DetectorBehavior,
		TTLDays:        60,
		CollectedAt:    staleCollected,
		Behavior: &BehaviorSignature{
			Probes: map[string]BehaviorProbeSignature{
				"bh-1": {ProbeID: "bh-1", Samples: []string{"ok"}},
			},
		},
	})
	require.NoError(t, err)

	// Collected 15 days ago with 60-day TTL -> fresh.
	freshCollected := fixedNow.Add(-15 * 24 * time.Hour)
	_, err = store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel: "fresh-model",
		Protocol:       ProtocolOpenAIChat,
		SuiteID:        suite.ID,
		DetectorKind:   DetectorBehavior,
		TTLDays:        60,
		CollectedAt:    freshCollected,
		Behavior: &BehaviorSignature{
			Probes: map[string]BehaviorProbeSignature{
				"bh-1": {ProbeID: "bh-1", Samples: []string{"ok"}},
			},
		},
	})
	require.NoError(t, err)

	views, err := svc.ListBaselines(ctx, BaselineFilter{})
	require.NoError(t, err)
	require.Len(t, views, 2)

	byModel := make(map[string]BaselineView, 2)
	for _, v := range views {
		byModel[v.CanonicalModel] = v
	}

	require.Equal(t, FreshnessStale, byModel["stale-model"].Freshness)
	require.True(t, byModel["stale-model"].ExpiresAt.Equal(staleCollected.Add(60*24*time.Hour)))

	require.Equal(t, FreshnessFresh, byModel["fresh-model"].Freshness)
	require.True(t, byModel["fresh-model"].ExpiresAt.Equal(freshCollected.Add(60*24*time.Hour)))
}

func TestCaptureValidationMappingConfusionAndSuites(t *testing.T) {
	ctx := context.Background()

	t.Run("validation_rejects_bad_rounds_models_ssrf_and_oauth", func(t *testing.T) {
		accounts := &stubAccountLookup{
			accounts: map[int64]*service.Account{
				1: {
					ID:          1,
					Name:        "oauth-acc",
					Platform:    service.PlatformOpenAI,
					Type:        service.AccountTypeOAuth,
					Credentials: map[string]any{"access_token": "tok"},
				},
			},
		}
		svc, store := newTestBaselineServiceEnv(t, nil, accounts, nil, nil)
		suite := seedMinimalSuite(t, store)

		// Bad sample rounds (2 and 6)
		_, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-12345678",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
			SampleRounds: 2,
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))

		_, err = svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-12345678",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
			SampleRounds: 6,
		}, 1)
		require.Error(t, err)

		// Empty / blank-only models or >20 unique models
		_, err = svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-12345678",
			SuiteID:      suite.ID,
			Models:       []string{"  ", ""},
		}, 1)
		require.Error(t, err)

		tooMany := make([]string, 21)
		for i := range tooMany {
			tooMany[i] = "model-" + string(rune('a'+i))
		}
		_, err = svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-12345678",
			SuiteID:      suite.ID,
			Models:       tooMany,
		}, 1)
		require.Error(t, err)

		// SSRF target fails fast before job creation
		_, err = svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "http://127.0.0.1:8080/v1",
			APIKey:       "sk-12345678",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.Error(t, err)

		// Unsupported OAuth account fails fast
		accID := int64(1)
		_, err = svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAccount,
			AccountID:    &accID,
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.ErrorIs(t, err, ErrUnsupportedAccountType)
	})

	t.Run("account_mapping_applied_and_stop_cancels_inflight", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var seenModel string
		client := &mockProbeClient{
			handler: func(pCtx context.Context, _ ProbeTarget, model string, probe ProbeDefinition, _ bool, idx int) ProbeCallResult {
				if idx == 0 {
					seenModel = model
					close(started)
					select {
					case <-release:
					case <-pCtx.Done():
						return ProbeCallResult{ErrorCode: errorCodeContextCanceled, ErrorMessage: pCtx.Err().Error()}
					}
				}
				return ProbeCallResult{Text: "7", HTTPStatus: 200}
			},
		}
		accounts := &stubAccountLookup{
			accounts: map[int64]*service.Account{
				10: {
					ID:       10,
					Name:     "Anthropic-Key",
					Platform: service.PlatformAnthropic,
					Type:     service.AccountTypeAPIKey,
					Credentials: map[string]any{
						"api_key": "sk-ant-real-secret",
						"model_mapping": map[string]any{
							"claude-opus-4-6-custom": "claude-opus-4-6-20260201",
						},
					},
				},
			},
		}

		svc, store := newTestBaselineServiceEnv(t, client, accounts, nil, nil)
		suite := seedMinimalSuite(t, store)
		accID := int64(10)

		job, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAccount,
			AccountID:    &accID,
			SuiteID:      suite.ID,
			Models:       []string{"claude-opus-4-6-custom"},
		}, 1)
		require.NoError(t, err)

		<-started
		svc.Stop()
		close(release)

		stoppedJob, err := svc.GetCaptureJob(ctx, job.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCancelled, stoppedJob.Status)
		require.Equal(t, "claude-opus-4-6-20260201", seenModel)
	})

	t.Run("confusion_matrix_update_delete_suites_and_families", func(t *testing.T) {
		svc, store := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		require.NoError(t, svc.EnsureSeeds(ctx))
		// Calling EnsureSeeds twice is idempotent.
		require.NoError(t, svc.EnsureSeeds(ctx))

		suites, err := svc.ListSuites(ctx)
		require.NoError(t, err)
		require.Len(t, suites, 1)
		defSuite := suites[0]

		// Duplicate (suite_key, version) returns ErrSuiteImmutable.
		_, err = svc.CreateSuite(ctx, CreateSuiteRequest{
			SuiteKey: defSuite.SuiteKey,
			Version:  defSuite.Version,
			Name:     "Duplicate",
			Probes:   defSuite.Probes,
		}, 1)
		require.ErrorIs(t, err, ErrSuiteImmutable)

		// Create new version and promote it to default, then archive it.
		v2, err := svc.CreateSuite(ctx, CreateSuiteRequest{
			SuiteKey:   "builtin-public",
			Version:    "v2",
			Name:       "Public v2",
			Visibility: VisibilityPublic,
			IsDefault:  true,
			Probes:     defSuite.Probes,
		}, 1)
		require.NoError(t, err)
		require.True(t, v2.IsDefault)

		archivedV2, err := svc.UpdateSuiteStatus(ctx, v2.ID, UpdateSuiteStatusRequest{Status: StatusArchived})
		require.NoError(t, err)
		require.Equal(t, StatusArchived, archivedV2.Status)
		require.False(t, archivedV2.IsDefault)

		setDefault := true
		restoredDef, err := svc.UpdateSuiteStatus(ctx, defSuite.ID, UpdateSuiteStatusRequest{Status: StatusActive, IsDefault: &setDefault})
		require.NoError(t, err)
		require.True(t, restoredDef.IsDefault)

		// ConfusionMatrix across two logprobs baselines.
		b1, err := store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel:    "model-a",
			Protocol:          ProtocolOpenAIChat,
			SuiteID:           defSuite.ID,
			DetectorKind:      DetectorLogprobs,
			SelfDivergenceP95: 0.08,
			MatchThreshold:    0.10,
			SuspectThreshold:  0.22,
			Logprobs:          makeLogprobsSignatureFromProbes([]TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.20}}, []TokenProb{{Token: "ok", Prob: 0.80}}),
		})
		require.NoError(t, err)
		_, err = store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel:    "model-b",
			Protocol:          ProtocolOpenAIChat,
			SuiteID:           defSuite.ID,
			DetectorKind:      DetectorLogprobs,
			SelfDivergenceP95: 0.04,
			MatchThreshold:    0.09,
			SuspectThreshold:  0.20,
			Logprobs:          makeLogprobsSignatureFromProbes([]TokenProb{{Token: " sky", Prob: 0.65}, {Token: " mist", Prob: 0.25}}, []TokenProb{{Token: "ok", Prob: 0.80}}),
		})
		require.NoError(t, err)

		cm, err := svc.ConfusionMatrix(ctx, ConfusionMatrixRequest{
			Protocol:     ProtocolOpenAIChat,
			SuiteID:      defSuite.ID,
			DetectorKind: DetectorLogprobs,
		})
		require.NoError(t, err)
		require.Equal(t, []string{"model-a", "model-b"}, cm.Models)
		require.Len(t, cm.Matrix, 2)
		require.True(t, math.Abs(cm.Matrix[0][1]-cm.Matrix[1][0]) < 1e-9)
		require.Greater(t, cm.MinOffDiagonal, 0.0)
		require.NotEmpty(t, cm.ClosePairs)

		// UpdateBaseline & DeleteBaseline
		badMatch := 0.50
		_, err = svc.UpdateBaseline(ctx, b1.ID, UpdateBaselineRequest{MatchThreshold: &badMatch})
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))

		newMatch := 0.07
		newNotes := "tuned"
		updatedView, err := svc.UpdateBaseline(ctx, b1.ID, UpdateBaselineRequest{
			MatchThreshold: &newMatch,
			Notes:          &newNotes,
		})
		require.NoError(t, err)
		require.InDelta(t, 0.07, updatedView.MatchThreshold, 1e-9)
		require.Equal(t, "tuned", updatedView.Notes)

		require.NoError(t, svc.DeleteBaseline(ctx, b1.ID))
		require.ErrorIs(t, svc.DeleteBaseline(ctx, b1.ID), ErrNotFound)

		// Empty ConfusionMatrix echoes scope cleanly.
		emptyCM, err := svc.ConfusionMatrix(ctx, ConfusionMatrixRequest{
			Protocol: ProtocolAnthropic,
			SuiteID:  defSuite.ID,
		})
		require.NoError(t, err)
		require.Equal(t, ProtocolAnthropic, emptyCM.Protocol)
		require.Equal(t, DetectorBehavior, emptyCM.DetectorKind)
		require.Empty(t, emptyCM.Models)

		// FamilyMap CRUD
		upsertedFM, err := svc.UpsertFamilyMap(ctx, FamilyMap{
			CanonicalModel: "custom-model-v1",
			Family:         "custom",
			Aliases:        []string{" custom-alias ", "custom-alias", "custom-model-v1"},
			ConfusionPeers: []string{"other-model", "custom-model-v1"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{"custom-alias"}, upsertedFM.Aliases)
		require.Equal(t, []string{"other-model"}, upsertedFM.ConfusionPeers)

		fms, err := svc.ListFamilyMaps(ctx)
		require.NoError(t, err)
		foundCustom := false
		for _, fm := range fms {
			if fm.CanonicalModel == "custom-model-v1" {
				foundCustom = true
			}
		}
		require.True(t, foundCustom)

		require.NoError(t, svc.DeleteFamilyMap(ctx, "custom-model-v1"))
		require.ErrorIs(t, svc.DeleteFamilyMap(ctx, "custom-model-v1"), ErrNotFound)
	})
}

func TestBaselineSecretSanitizationOnCaptureError(t *testing.T) {
	ctx := context.Background()
	secret := "sk-error-leak-guard-777"
	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
			return ProbeCallResult{
				HTTPStatus:   401,
				ErrorCode:    errorCodeAuthError,
				ErrorMessage: "unauthorized for key " + secret,
			}
		},
	}
	svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
	suite := seedMinimalSuite(t, store)

	job, err := svc.StartCaptureJob(ctx, CaptureRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolAnthropic,
		BaseURL:      "https://api.example.com",
		APIKey:       secret,
		SuiteID:      suite.ID,
		Models:       []string{"claude-sonnet-4-6"},
	}, 1)
	require.NoError(t, err)

	done := waitForCaptureJobTerminal(t, svc, job.ID)
	require.Equal(t, RunStatusFailed, done.Status)
	require.NotContains(t, done.ErrorMessage, secret)
	require.Len(t, done.Results, 1)
	require.NotContains(t, done.Results[0].Error, secret)
	require.True(t, strings.Contains(done.Results[0].Error, "auth_error") || strings.Contains(done.Results[0].Error, "unauthorized"))
}

func TestCaptureRejectsKeyInModelNameAndRedactsEchoedSignatures(t *testing.T) {
	ctx := context.Background()
	apiKey := "opaque-adhoc-secret-9988"

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.Kind == DetectorLogprobs {
				return ProbeCallResult{
					Logprobs: []TokenProb{
						{Token: "tok-" + apiKey, Prob: 0.70},
						{Token: " safe", Prob: 0.25},
					},
					LogprobsSupported: true,
					HTTPStatus:        200,
				}
			}
			return ProbeCallResult{
				Text:              "echo:" + apiKey + "\nline2",
				ResponseModel:     "gpt-4o-" + apiKey,
				SystemFingerprint: "fp-" + apiKey,
				HTTPStatus:        200,
			}
		},
	}

	svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
	suite := seedMinimalSuite(t, store)

	// 1. Model name containing ad-hoc API key is rejected before persisting any CaptureJob.
	_, err := svc.StartCaptureJob(ctx, CaptureRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       apiKey,
		SuiteID:      suite.ID,
		Models:       []string{"gpt-4o-" + apiKey},
	}, 1)
	require.Error(t, err)
	require.Equal(t, 400, infraerrors.Code(err))

	// 2. Echoed api_key in logprob tokens, behavior text, response_model, system_fingerprint, and snapshot
	// must never reach stored baselines, CaptureJob results_json, or exported bundles.
	job, err := svc.StartCaptureJob(ctx, CaptureRequest{
		TargetSource:     TargetSourceAdHoc,
		Protocol:         ProtocolOpenAIChat,
		BaseURL:          "https://api.example.com/v1",
		APIKey:           apiKey,
		SuiteID:          suite.ID,
		Models:           []string{"gpt-4o"},
		UpstreamSnapshot: "snap-" + apiKey,
		Notes:            "note-" + apiKey,
	}, 1)
	require.NoError(t, err)

	done := waitForCaptureJobTerminal(t, svc, job.ID)
	require.Equal(t, RunStatusCompleted, done.Status)
	require.Len(t, done.Results, 1)
	require.NotNil(t, done.Results[0].LogprobsBaselineID)
	require.NotNil(t, done.Results[0].BehaviorBaselineID)

	rawJob, err := json.Marshal(done)
	require.NoError(t, err)
	require.NotContains(t, string(rawJob), apiKey)

	lpBase, err := store.GetBaseline(ctx, *done.Results[0].LogprobsBaselineID)
	require.NoError(t, err)
	rawLP, err := json.Marshal(lpBase)
	require.NoError(t, err)
	require.NotContains(t, string(rawLP), apiKey)
	require.Contains(t, string(rawLP), redactedSecretPlaceholder)

	bhBase, err := store.GetBaseline(ctx, *done.Results[0].BehaviorBaselineID)
	require.NoError(t, err)
	rawBH, err := json.Marshal(bhBase)
	require.NoError(t, err)
	require.NotContains(t, string(rawBH), apiKey)
	require.Contains(t, string(rawBH), redactedSecretPlaceholder)

	bundle, err := svc.ExportBundle(ctx, true)
	require.NoError(t, err)
	rawBundle, err := json.Marshal(bundle)
	require.NoError(t, err)
	require.NotContains(t, string(rawBundle), apiKey)
}

func TestCaptureRequiresBehaviorProbeAndFailsOnPartialPersistence(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects_logprobs_only_suite", func(t *testing.T) {
		svc, _ := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		lpOnly, err := svc.CreateSuite(ctx, CreateSuiteRequest{
			SuiteKey: "lp-only",
			Version:  "v1",
			Name:     "Logprobs Only",
			Probes: []ProbeDefinition{
				{ID: "lp-1", Kind: DetectorLogprobs, Prompt: "Hello", MaxTokens: 1, TopLogprobs: 20},
			},
		}, 1)
		require.NoError(t, err)

		_, err = svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-test-lp-only-1234",
			SuiteID:      lpOnly.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 400, infraerrors.Code(err))
		require.Equal(t, "MODELFP_NO_APPLICABLE_PROBES", infraerrors.Reason(err))
	})

	t.Run("behavior_write_failure_after_logprobs_marks_model_and_job_failed", func(t *testing.T) {
		baseStore := NewMemoryStore()
		failingStore := &failOnBaselineWriteStore{
			MemoryStore: baseStore,
			failKind:    DetectorBehavior,
			failErr:     errors.New("simulated behavior write failure"),
		}
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: " sky", Prob: 0.9}},
						LogprobsSupported: true,
						HTTPStatus:        200,
					}
				}
				return ProbeCallResult{Text: `{"sum":55}`, HTTPStatus: 200}
			},
		}
		resolver := NewTargetResolverWithOptions(
			&stubAccountLookup{},
			&stubProxyLookup{},
			withResolverLookupNetIPForTest(func(_ context.Context, _, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}),
		)
		svc := NewBaselineService(failingStore, resolver, NewOrchestrator(client))
		t.Cleanup(svc.Stop)

		suite, err := baseStore.UpsertSeedSuite(ctx, makeTestSuite())
		require.NoError(t, err)

		priorLP, err := baseStore.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel:   "gpt-4o",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorLogprobs,
			SourceType:       SourceOfficialDirect,
			MatchThreshold:   0.08,
			SuspectThreshold: 0.18,
			Notes:            "prior-active-logprobs",
			Logprobs:         makeLogprobsSignatureFromProbes([]TokenProb{{Token: "ok", Prob: 1.0}}, []TokenProb{{Token: "ok", Prob: 1.0}}),
		})
		require.NoError(t, err)

		job, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-partial-fail-12345",
			SuiteID:      suite.ID,
			Models:       []string{"gpt-4o"},
		}, 1)
		require.NoError(t, err)

		done := waitForCaptureJobTerminal(t, svc, job.ID)
		require.Equal(t, RunStatusFailed, done.Status)
		require.Len(t, done.Results, 1)
		require.Contains(t, done.Results[0].Error, "simulated behavior write failure")
		require.Nil(t, done.Results[0].LogprobsBaselineID)
		require.Nil(t, done.Results[0].BehaviorBaselineID)

		// Atomic rollback leaves the prior active logprobs baseline untouched and writes no behavior baseline.
		activeLP, err := baseStore.ListBaselines(ctx, BaselineFilter{CanonicalModel: "gpt-4o", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, DetectorKind: DetectorLogprobs, Status: StatusActive})
		require.NoError(t, err)
		require.Len(t, activeLP, 1)
		require.Equal(t, priorLP.ID, activeLP[0].ID)
		require.Equal(t, "prior-active-logprobs", activeLP[0].Notes)

		allBH, err := baseStore.ListBaselines(ctx, BaselineFilter{CanonicalModel: "gpt-4o", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, DetectorKind: DetectorBehavior})
		require.NoError(t, err)
		require.Empty(t, allBH)
	})
}

func TestOverlapWarningUsesCandidateSelfDivStrictly(t *testing.T) {
	ctx := context.Background()
	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.Kind == DetectorLogprobs {
				return ProbeCallResult{
					// Deterministic across rounds -> candidate D_self == 0 (1.5 * D_self == 0).
					Logprobs:          []TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.25}},
					LogprobsSupported: true,
					HTTPStatus:        200,
				}
			}
			if probe.ID == "bh-1" {
				return ProbeCallResult{Text: `{"sum":55}`, ResponseModel: "gpt-4o", HTTPStatus: 200}
			}
			return ProbeCallResult{Text: "7", ResponseModel: "gpt-4o", HTTPStatus: 200}
		},
	}

	svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
	suite := seedMinimalSuite(t, store)

	// Peer has large SelfDivergenceP95 (0.50 -> 1.5*peer.D_self = 0.75) and small non-zero distance (~0.10),
	// while candidate has D_self = 0 (D_near > 1.5 * candidate.D_self). OverlapWarning must remain false.
	_, err := store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:    "gpt-4o-wide-peer",
		Protocol:          ProtocolOpenAIChat,
		SuiteID:           suite.ID,
		DetectorKind:      DetectorLogprobs,
		SourceType:        SourceOfficialDirect,
		SourceLabel:       "wide-peer",
		SampleCount:       3,
		SelfDivergenceP95: 0.50,
		MatchThreshold:    0.08,
		SuspectThreshold:  0.18,
		Logprobs: makeLogprobsSignatureFromProbes(
			[]TokenProb{{Token: " sky", Prob: 0.50}, {Token: " mist", Prob: 0.45}},
			[]TokenProb{{Token: "ok", Prob: 0.85}},
		),
	})
	require.NoError(t, err)

	job, err := svc.StartCaptureJob(ctx, CaptureRequest{
		TargetSource: TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       "sk-overlap-neg-12345",
		SuiteID:      suite.ID,
		Models:       []string{"gpt-4o"},
	}, 1)
	require.NoError(t, err)

	done := waitForCaptureJobTerminal(t, svc, job.ID)
	require.Equal(t, RunStatusCompleted, done.Status)
	require.Len(t, done.Results, 1)
	require.NotNil(t, done.Results[0].LogprobsSelfDivP95)
	require.Equal(t, 0.0, *done.Results[0].LogprobsSelfDivP95)
	require.NotNil(t, done.Results[0].LogprobsNearestDist)
	require.Greater(t, *done.Results[0].LogprobsNearestDist, 0.0)
	require.False(t, done.Results[0].OverlapWarning)
	require.Empty(t, done.Results[0].OverlapDetails)
}

func TestStopWaitsForInflightCreateCaptureJob(t *testing.T) {
	ctx := context.Background()
	baseStore := NewMemoryStore()
	suite := seedMinimalSuite(t, baseStore)

	inCreate := make(chan struct{})
	releaseCreate := make(chan struct{})
	store := &blockingCreateCaptureStore{
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
	svc := NewBaselineService(store, resolver, NewOrchestrator(&mockProbeClient{}))

	var startErr error
	startDone := make(chan struct{})
	go func() {
		defer close(startDone)
		reqCtx, reqCancel := context.WithCancel(ctx)
		defer reqCancel()
		_, startErr = svc.StartCaptureJob(reqCtx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.example.com",
			APIKey:       "sk-stop-race-12345",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
	}()

	<-inCreate
	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		svc.Stop()
	}()

	// Stop must block until CreateCaptureJob finishes and cancels the queued job.
	select {
	case <-stopDone:
		t.Fatalf("Stop returned while CreateCaptureJob was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseCreate)
	<-startDone
	<-stopDone

	require.Error(t, startErr)
	require.NotZero(t, store.lastCreatedID)
	persisted, err := baseStore.GetCaptureJob(ctx, store.lastCreatedID)
	require.NoError(t, err)
	require.Equal(t, RunStatusCancelled, persisted.Status)
}

func TestImportBundlePrevalidatesSuiteHashAndStrictSuiteResolution(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects_suite_content_hash_conflict_before_any_writes", func(t *testing.T) {
		destSvc, destStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		require.NoError(t, destSvc.EnsureSeeds(ctx))

		srcSvc, srcStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		conflictingSuite, err := srcStore.CreateSuite(ctx, ProbeSuite{
			SuiteKey:   "builtin-public",
			Version:    "v1",
			Name:       "Modified Builtin",
			Visibility: VisibilityPublic,
			Status:     StatusActive,
			Probes: []ProbeDefinition{
				{ID: "different-probe", Kind: DetectorBehavior, Prompt: "Different prompt", MaxTokens: 32, Weight: 1.0},
			},
		})
		require.NoError(t, err)
		_, err = srcStore.UpsertFamilyMap(ctx, FamilyMap{
			CanonicalModel: "should-not-be-imported",
			Family:         "test",
		})
		require.NoError(t, err)
		_, err = srcStore.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel: "gpt-4o",
			Protocol:       ProtocolOpenAIChat,
			SuiteID:        conflictingSuite.ID,
			DetectorKind:   DetectorBehavior,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"different-probe": {ProbeID: "different-probe", Samples: []string{"ok"}},
				},
			},
		})
		require.NoError(t, err)

		bundle, err := srcSvc.ExportBundle(ctx, true)
		require.NoError(t, err)

		_, err = destSvc.ImportBundle(ctx, ImportBundleRequest{
			Bundle:       *bundle,
			ConflictMode: ImportConflictOverwrite,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrSuiteImmutable)

		// Zero writes occurred: family map and baseline were not persisted.
		fms, err := destStore.ListFamilyMaps(ctx)
		require.NoError(t, err)
		for _, fm := range fms {
			require.NotEqual(t, "should-not-be-imported", fm.CanonicalModel)
		}
		bls, err := destStore.ListBaselines(ctx, BaselineFilter{})
		require.NoError(t, err)
		require.Empty(t, bls)
	})

	t.Run("rejects_baseline_referencing_destination_suite_id_not_in_bundle", func(t *testing.T) {
		destSvc, destStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		destSuite := seedMinimalSuite(t, destStore)

		bundle := Bundle{
			SchemaVersion:  DefaultBundleSchemaVersion,
			ExportedAt:     time.Now().UTC(),
			IncludePrivate: false,
			Suites:         []ProbeSuite{},
			FamilyMaps: []FamilyMap{
				{CanonicalModel: "should-not-write-family", Family: "test"},
			},
			Baselines: []Baseline{
				{
					CanonicalModel: "gpt-4o",
					Protocol:       ProtocolOpenAIChat,
					SuiteID:        destSuite.ID, // raw destination-local ID only, suite missing from Bundle.Suites
					DetectorKind:   DetectorBehavior,
					Behavior: &BehaviorSignature{
						Probes: map[string]BehaviorProbeSignature{
							"bh-1": {ProbeID: "bh-1", Samples: []string{"ok"}},
						},
					},
				},
			},
		}
		sha, err := computeBundleSHA256(bundle)
		require.NoError(t, err)
		bundle.SHA256 = sha

		_, err = destSvc.ImportBundle(ctx, ImportBundleRequest{Bundle: bundle})
		require.Error(t, err)
		require.Equal(t, "MODELFP_INVALID_BUNDLE_SUITE", infraerrors.Reason(err))

		fms, err := destStore.ListFamilyMaps(ctx)
		require.NoError(t, err)
		require.Empty(t, fms)
	})
}

type failOnBaselineWriteStore struct {
	*MemoryStore
	failKind DetectorKind
	failErr  error
}

func (f *failOnBaselineWriteStore) UpsertActiveBaseline(ctx context.Context, baseline Baseline) (*Baseline, error) {
	if baseline.DetectorKind == f.failKind {
		return nil, f.failErr
	}
	return f.MemoryStore.UpsertActiveBaseline(ctx, baseline)
}

func (f *failOnBaselineWriteStore) UpsertActiveBaselinesAtomic(ctx context.Context, baselines []Baseline) ([]Baseline, error) {
	prev := f.beforeBaselineInsert
	f.beforeBaselineInsert = func(b Baseline) error {
		if b.DetectorKind == f.failKind {
			return f.failErr
		}
		if prev != nil {
			return prev(b)
		}
		return nil
	}
	defer func() {
		f.beforeBaselineInsert = prev
	}()
	return f.MemoryStore.UpsertActiveBaselinesAtomic(ctx, baselines)
}

type blockingCreateCaptureStore struct {
	*MemoryStore
	inCreate      chan struct{}
	releaseCreate chan struct{}
	mu            sync.Mutex
	lastCreatedID int64
}

func (b *blockingCreateCaptureStore) CreateCaptureJob(ctx context.Context, job CaptureJob) (*CaptureJob, error) {
	created, err := b.MemoryStore.CreateCaptureJob(ctx, job)
	if err == nil && created != nil {
		b.mu.Lock()
		b.lastCreatedID = created.ID
		b.mu.Unlock()
	}
	close(b.inCreate)
	<-b.releaseCreate
	return created, err
}

func TestBaselineCaptureHeadersPrivatePromptsSeedsAndLimits(t *testing.T) {
	ctx := context.Background()

	t.Run("redacts_custom_extra_headers_and_private_prompts_in_signatures", func(t *testing.T) {
		customPass := "my-custom-pass-99"
		privatePrompt := "Canary Prompt Alpha 99"

		client := &mockProbeClient{
			handler: func(_ context.Context, target ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				passed := target.ExtraHeaders["X-Relay-Pass"]
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: "tok-" + passed, Prob: 0.9}},
						LogprobsSupported: true,
						ResponseModel:     "gpt-4o-" + passed,
						HTTPStatus:        200,
					}
				}
				return ProbeCallResult{
					Text:              "Reflected " + strings.ToLower(privatePrompt) + " and header=" + passed,
					ResponseModel:     "gpt-4o-" + passed,
					SystemFingerprint: "fp-" + passed,
					HTTPStatus:        200,
				}
			},
		}

		svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
		privSuite, err := store.CreateSuite(ctx, ProbeSuite{
			SuiteKey:   "priv-cap",
			Version:    "v1",
			Name:       "Private Capture",
			Visibility: VisibilityPrivate,
			Status:     StatusActive,
			Probes: []ProbeDefinition{
				{ID: "lp-1", Kind: DetectorLogprobs, Prompt: privatePrompt, MaxTokens: 1, TopLogprobs: 20, Weight: 1.0},
				{ID: "bh-1", Kind: DetectorBehavior, Prompt: privatePrompt, MaxTokens: 32, Weight: 1.0},
			},
		})
		require.NoError(t, err)

		job, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolOpenAIChat,
			BaseURL:      "https://api.example.com/v1",
			APIKey:       "sk-cap-custom-hdr-1234",
			ExtraHeaders: map[string]string{"X-Relay-Pass": customPass},
			SuiteID:      privSuite.ID,
			Models:       []string{"gpt-4o"},
			SampleRounds: 3,
		}, 1)
		require.NoError(t, err)

		done := waitForCaptureJobTerminal(t, svc, job.ID)
		require.Equal(t, RunStatusCompleted, done.Status)

		bls, err := store.ListBaselines(ctx, BaselineFilter{SuiteID: privSuite.ID, Status: StatusActive})
		require.NoError(t, err)
		require.Len(t, bls, 2)

		raw, err := json.Marshal(bls)
		require.NoError(t, err)
		require.NotContains(t, string(raw), customPass)
		require.NotContains(t, strings.ToLower(string(raw)), strings.ToLower(privatePrompt))
		require.Contains(t, string(raw), redactedSecretPlaceholder)
	})

	t.Run("ensure_seeds_preserves_admin_edited_family_maps", func(t *testing.T) {
		svc, _ := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		require.NoError(t, svc.EnsureSeeds(ctx))

		edited, err := svc.UpsertFamilyMap(ctx, FamilyMap{
			CanonicalModel: "gpt-4o",
			Family:         "gpt-4o-custom",
			Aliases:        []string{"admin-custom-alias-4o"},
			ConfusionPeers: []string{"custom-peer-mini"},
		})
		require.NoError(t, err)
		require.Equal(t, "gpt-4o-custom", edited.Family)

		// Re-running EnsureSeeds (e.g. pod restart) must NOT overwrite admin customizations.
		require.NoError(t, svc.EnsureSeeds(ctx))

		fms, err := svc.ListFamilyMaps(ctx)
		require.NoError(t, err)
		var found *FamilyMap
		for i := range fms {
			if fms[i].CanonicalModel == "gpt-4o" {
				found = &fms[i]
				break
			}
		}
		require.NotNil(t, found)
		require.Equal(t, "gpt-4o-custom", found.Family)
		require.Equal(t, []string{"admin-custom-alias-4o"}, found.Aliases)
		require.Equal(t, []string{"custom-peer-mini"}, found.ConfusionPeers)
	})

	t.Run("enforces_max_active_capture_jobs_and_caps_imported_samples", func(t *testing.T) {
		release := make(chan struct{})
		entered := make(chan struct{}, maxActiveCaptureJobs)
		client := &mockProbeClient{
			handler: func(probeCtx context.Context, _ ProbeTarget, _ string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
				entered <- struct{}{}
				select {
				case <-release:
					return ProbeCallResult{Text: "ok", HTTPStatus: 200}
				case <-probeCtx.Done():
					return ProbeCallResult{ErrorCode: errorCodeContextCanceled, ErrorMessage: probeCtx.Err().Error()}
				}
			},
		}
		svc, store := newTestBaselineServiceEnv(t, client, nil, nil, nil)
		suite := seedMinimalSuite(t, store)

		for i := 0; i < maxActiveCaptureJobs; i++ {
			_, err := svc.StartCaptureJob(ctx, CaptureRequest{
				TargetSource: TargetSourceAdHoc,
				Protocol:     ProtocolAnthropic,
				BaseURL:      "https://api.anthropic.com",
				APIKey:       "sk-cap-limit-1234",
				SuiteID:      suite.ID,
				Models:       []string{"claude-sonnet-4-6"},
			}, 1)
			require.NoError(t, err)
		}
		for i := 0; i < maxActiveCaptureJobs; i++ {
			<-entered
		}

		_, err := svc.StartCaptureJob(ctx, CaptureRequest{
			TargetSource: TargetSourceAdHoc,
			Protocol:     ProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			APIKey:       "sk-cap-over-limit-1234",
			SuiteID:      suite.ID,
			Models:       []string{"claude-sonnet-4-6"},
		}, 1)
		require.Error(t, err)
		require.Equal(t, 429, infraerrors.Code(err))
		require.Equal(t, "MODELFP_TOO_MANY_ACTIVE_JOBS", infraerrors.Reason(err))

		close(release)
		svc.Stop()

		// ImportBundle caps behavior samples to maxBehaviorSampleRunes.
		destSvc, destStore := newTestBaselineServiceEnv(t, nil, nil, nil, nil)
		longSample := strings.Repeat("z", maxBehaviorSampleRunes+600)
		bundle := Bundle{
			SchemaVersion:  DefaultBundleSchemaVersion,
			ExportedAt:     time.Now().UTC(),
			IncludePrivate: false,
			Suites: []ProbeSuite{
				{
					SuiteKey:   "cap-import",
					Version:    "v1",
					Name:       "Cap Import",
					Visibility: VisibilityPublic,
					Status:     StatusActive,
					Probes:     []ProbeDefinition{{ID: "bh-1", Kind: DetectorBehavior, Prompt: "hi", MaxTokens: 32, Weight: 1}},
				},
			},
			FamilyMaps: []FamilyMap{},
			Baselines: []Baseline{
				{
					CanonicalModel: "claude-sonnet-4-6",
					Protocol:       ProtocolAnthropic,
					SuiteKey:       "cap-import",
					SuiteVersion:   "v1",
					DetectorKind:   DetectorBehavior,
					Behavior: &BehaviorSignature{
						Probes: map[string]BehaviorProbeSignature{
							"bh-1": {ProbeID: "bh-1", Samples: []string{longSample}},
						},
					},
				},
			},
		}
		sha, err := computeBundleSHA256(bundle)
		require.NoError(t, err)
		bundle.SHA256 = sha

		impRes, err := destSvc.ImportBundle(ctx, ImportBundleRequest{Bundle: bundle})
		require.NoError(t, err)
		require.Equal(t, 1, impRes.BaselinesImported)

		stored, err := destStore.ListBaselines(ctx, BaselineFilter{Status: StatusActive})
		require.NoError(t, err)
		require.Len(t, stored, 1)
		require.Equal(t, maxBehaviorSampleRunes, len([]rune(stored[0].Behavior.Probes["bh-1"].Samples[0])))
	})
}

func TestModelContainsCredentialsSeparatesRoutingHeadersFromSecrets(t *testing.T) {
	target := ProbeTarget{
		APIKey: "sk-live-secret-12345",
		ExtraHeaders: map[string]string{
			"X-Provider":   "openai",
			"X-Auth-Token": "tok-custom-98765",
		},
	}

	if modelContainsCredentials("openai/gpt-4o", target) {
		t.Fatalf("expected non-secret routing header X-Provider=openai not to block openai/gpt-4o")
	}
	if !modelContainsCredentials("bad-tok-custom-98765", target) {
		t.Fatalf("expected auth-like header value to be blocked in model name")
	}
	if !modelContainsCredentials("bad-sk-live-secret-12345", target) {
		t.Fatalf("expected APIKey to be blocked in model name")
	}
	// Output redaction must still scrub all custom header values including X-Provider.
	if red := redactExactSecrets("reflected openai and tok-custom-98765", target); strings.Contains(red, "openai") || strings.Contains(red, "tok-custom-98765") {
		t.Fatalf("expected output redaction to scrub all custom headers, got %q", red)
	}
}
