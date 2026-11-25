package modelfp

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockProbeCall struct {
	Target          ProbeTarget
	Model           string
	Probe           ProbeDefinition
	RequestLogprobs bool
}

type mockProbeClient struct {
	mu      sync.Mutex
	calls   []mockProbeCall
	handler func(ctx context.Context, target ProbeTarget, model string, probe ProbeDefinition, requestLogprobs bool, callIndex int) ProbeCallResult
}

func (m *mockProbeClient) ExecuteProbe(
	ctx context.Context,
	target ProbeTarget,
	model string,
	probe ProbeDefinition,
	requestLogprobs bool,
) ProbeCallResult {
	m.mu.Lock()
	idx := len(m.calls)
	m.calls = append(m.calls, mockProbeCall{
		Target:          target,
		Model:           model,
		Probe:           probe,
		RequestLogprobs: requestLogprobs,
	})
	m.mu.Unlock()

	if m.handler != nil {
		return m.handler(ctx, target, model, probe, requestLogprobs, idx)
	}
	return ProbeCallResult{}
}

func (m *mockProbeClient) DiscoverModels(_ context.Context, _ ProbeTarget) ([]string, error) {
	return nil, nil
}

func (m *mockProbeClient) recordedCalls() []mockProbeCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockProbeCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func makeTestSuite() ProbeSuite {
	seed := 42
	return ProbeSuite{
		ID:       1,
		SuiteKey: "builtin-public",
		Version:  "v1",
		Name:     "Test Suite",
		Status:   StatusActive,
		Probes: []ProbeDefinition{
			{
				ID:                      "lp-1",
				Kind:                    DetectorLogprobs,
				Prompt:                  "The quiet coastal town woke up to a pale",
				MaxTokens:               1,
				Temperature:             0,
				TopLogprobs:             20,
				Seed:                    &seed,
				Weight:                  1.0,
				ExpectedMaxPromptTokens: 500,
			},
			{
				ID:                      "lp-2",
				Kind:                    DetectorLogprobs,
				Prompt:                  "{\"status\": \"",
				MaxTokens:               1,
				Temperature:             0,
				TopLogprobs:             20,
				Seed:                    &seed,
				Weight:                  2.0,
				ExpectedMaxPromptTokens: 500,
			},
			{
				ID:                      "bh-1",
				Kind:                    DetectorBehavior,
				Prompt:                  "Return JSON sum/sorted/parity for [14,3,9,22,7].",
				MaxTokens:               64,
				Temperature:             0,
				Weight:                  1.0,
				ExpectedMaxPromptTokens: 500,
				ExpectedFormat:          "json",
			},
			{
				ID:                      "bh-2",
				Kind:                    DetectorBehavior,
				Prompt:                  "Count r in strawberry-harbor-mirror.",
				MaxTokens:               64,
				Temperature:             0,
				Weight:                  1.5,
				ExpectedMaxPromptTokens: 500,
				ExpectedFormat:          "integer",
			},
		},
	}
}

func makeLogprobsSignatureFromProbes(p1, p2 []TokenProb) *LogprobsSignature {
	return &LogprobsSignature{
		Probes: map[string]LogprobsProbeSignature{
			"lp-1": {
				ProbeID:      "lp-1",
				Distribution: NormalizeTokenDistribution(p1),
				TopTokens:    p1,
				SampleCount:  3,
			},
			"lp-2": {
				ProbeID:      "lp-2",
				Distribution: NormalizeTokenDistribution(p2),
				TopTokens:    p2,
				SampleCount:  3,
			},
		},
	}
}

func TestOrchestratorLogprobsMatchAndMismatch(t *testing.T) {
	suite := makeTestSuite()
	families := []FamilyMap{
		{
			CanonicalModel: "gpt-4o",
			Family:         "gpt-4o",
			Aliases:        []string{"gpt-4o-2024-11-20"},
			ConfusionPeers: []string{"gpt-4o-mini"},
		},
		{
			CanonicalModel: "gpt-4o-mini",
			Family:         "gpt-4o",
			ConfusionPeers: []string{"gpt-4o"},
		},
	}

	gpt4oLP1 := []TokenProb{{Token: " sky", Prob: 0.70}, {Token: " glow", Prob: 0.20}}
	gpt4oLP2 := []TokenProb{{Token: "ok", Prob: 0.80}, {Token: "success", Prob: 0.15}}
	miniLP1 := []TokenProb{{Token: " morning", Prob: 0.75}, {Token: " mist", Prob: 0.15}}
	miniLP2 := []TokenProb{{Token: "ready", Prob: 0.85}, {Token: "active", Prob: 0.10}}

	baselines := []Baseline{
		{
			ID:               101,
			CanonicalModel:   "gpt-4o",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorLogprobs,
			Status:           StatusActive,
			MatchThreshold:   0.08,
			SuspectThreshold: 0.18,
			Logprobs:         makeLogprobsSignatureFromProbes(gpt4oLP1, gpt4oLP2),
		},
		{
			ID:               102,
			CanonicalModel:   "gpt-4o-mini",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorLogprobs,
			Status:           StatusActive,
			MatchThreshold:   0.08,
			SuspectThreshold: 0.18,
			Logprobs:         makeLogprobsSignatureFromProbes(miniLP1, miniLP2),
		},
	}

	target := ProbeTarget{
		Protocol: ProtocolOpenAIChat,
		BaseURL:  "https://api.example.com/v1",
		APIKey:   "sk-test-secret-key",
	}

	t.Run("match via alias", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
				if !requestLogprobs {
					t.Fatalf("expected requestLogprobs=true for %s", probe.ID)
				}
				switch probe.ID {
				case "lp-1":
					return ProbeCallResult{Logprobs: gpt4oLP1, LogprobsSupported: true, PromptTokens: 24, OutputTokens: 1, HTTPStatus: 200}
				case "lp-2":
					return ProbeCallResult{Logprobs: gpt4oLP2, LogprobsSupported: true, PromptTokens: 20, OutputTokens: 1, HTTPStatus: 200}
				default:
					t.Fatalf("did not expect behavior probe %s when logprobs matched", probe.ID)
					return ProbeCallResult{}
				}
			},
		}

		orch := NewOrchestrator(client)
		out := orch.VerifyModel(context.Background(), VerifyModelInput{
			Target:       target,
			ClaimedModel: "gpt-4o-2024-11-20",
			Suite:        suite,
			Baselines:    baselines,
			FamilyMaps:   families,
		})

		if out.Verdict != VerdictMatch {
			t.Fatalf("expected VerdictMatch, got %s (%+v)", out.Verdict, out)
		}
		if out.DetectorUsed != DetectorLogprobs {
			t.Fatalf("expected DetectorLogprobs, got %s", out.DetectorUsed)
		}
		if out.CanonicalModel != "gpt-4o" {
			t.Fatalf("expected canonical gpt-4o, got %q", out.CanonicalModel)
		}
		if out.Distance > 0.08 {
			t.Fatalf("expected distance <= 0.08, got %v", out.Distance)
		}
		if len(out.TopCandidates) == 0 || out.TopCandidates[0].CanonicalModel != "gpt-4o" || !out.TopCandidates[0].WithinMatch {
			t.Fatalf("unexpected TopCandidates: %+v", out.TopCandidates)
		}
	})

	t.Run("mismatch identifies swapped true model", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				switch probe.ID {
				case "lp-1":
					return ProbeCallResult{Logprobs: miniLP1, LogprobsSupported: true, PromptTokens: 24, OutputTokens: 1, HTTPStatus: 200}
				case "lp-2":
					return ProbeCallResult{Logprobs: miniLP2, LogprobsSupported: true, PromptTokens: 20, OutputTokens: 1, HTTPStatus: 200}
				default:
					return ProbeCallResult{}
				}
			},
		}

		orch := NewOrchestrator(client)
		out := orch.VerifyModel(context.Background(), VerifyModelInput{
			Target:       target,
			ClaimedModel: "gpt-4o",
			Suite:        suite,
			Baselines:    baselines,
			FamilyMaps:   families,
		})

		if out.Verdict != VerdictMismatch {
			t.Fatalf("expected VerdictMismatch, got %s (%+v)", out.Verdict, out)
		}
		if out.DetectorUsed != DetectorLogprobs {
			t.Fatalf("expected DetectorLogprobs, got %s", out.DetectorUsed)
		}
		if len(out.TopCandidates) == 0 || out.TopCandidates[0].CanonicalModel != "gpt-4o-mini" || !out.TopCandidates[0].WithinMatch {
			t.Fatalf("expected TopCandidates[0] to identify gpt-4o-mini within_match=true, got %+v", out.TopCandidates)
		}
	})
}

func TestOrchestratorFallbackPreservesInjectionWarning(t *testing.T) {
	// Review Focus #3: logprobs stripped (LogprobsSupported=false) + 4120 prompt tokens -> fallback to behavior preserves injection warning.
	suite := makeTestSuite()
	families := []FamilyMap{
		{CanonicalModel: "gpt-4o", Family: "gpt-4o", ConfusionPeers: []string{"gpt-4o-mini"}},
		{CanonicalModel: "gpt-4o-mini", Family: "gpt-4o", ConfusionPeers: []string{"gpt-4o"}},
	}

	baselines := []Baseline{
		{
			ID:               201,
			CanonicalModel:   "gpt-4o",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorLogprobs,
			Status:           StatusActive,
			MatchThreshold:   0.08,
			SuspectThreshold: 0.18,
			Logprobs: makeLogprobsSignatureFromProbes(
				[]TokenProb{{Token: " sky", Prob: 0.8}},
				[]TokenProb{{Token: "ok", Prob: 0.9}},
			),
		},
		{
			ID:               202,
			CanonicalModel:   "gpt-4o",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
				ResponseModels: []string{"gpt-4o"},
			},
		},
		{
			ID:               203,
			CanonicalModel:   "gpt-4o-mini",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":54,"sorted":[3,7,9,14,22],"parity":"even"}`}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"5"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
				ResponseModels: []string{"gpt-4o-mini"},
			},
		},
	}

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			switch probe.Kind {
			case DetectorLogprobs:
				return ProbeCallResult{
					Text:               "sky",
					ResponseModel:      "gpt-4o",
					LogprobsSupported:  false,
					PromptTokens:       4120,
					CachedPromptTokens: 4096,
					OutputTokens:       1,
					HTTPStatus:         200,
				}
			case DetectorBehavior:
				if probe.ID == "bh-1" {
					return ProbeCallResult{
						Text:          `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`,
						ResponseModel: "gpt-4o",
						PromptTokens:  42, // Lower on phase 2 so test verifies phase 1 warning is NOT lost!
						OutputTokens:  18,
						HTTPStatus:    200,
					}
				}
				return ProbeCallResult{
					Text:          "7",
					ResponseModel: "gpt-4o",
					PromptTokens:  30,
					OutputTokens:  1,
					HTTPStatus:    200,
				}
			default:
				return ProbeCallResult{}
			}
		},
	}

	orch := NewOrchestrator(client)
	out := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://relay.example.com/v1",
			APIKey:   "sk-relay-secret",
		},
		ClaimedModel: "gpt-4o",
		Suite:        suite,
		Baselines:    baselines,
		FamilyMaps:   families,
	})

	if out.DetectorUsed != DetectorBehavior {
		t.Fatalf("expected fallback to DetectorBehavior, got %s", out.DetectorUsed)
	}
	if out.Verdict != VerdictMatch {
		t.Fatalf("expected VerdictMatch against behavior baseline, got %s (%+v)", out.Verdict, out)
	}
	if !out.PromptInjectionSuspected {
		t.Fatalf("expected PromptInjectionSuspected=true to be preserved across fallback")
	}
	if out.ObservedPromptTokens != 4120 {
		t.Fatalf("expected ObservedPromptTokens=4120, got %d", out.ObservedPromptTokens)
	}
	if len(out.TopCandidates) == 0 || out.TopCandidates[0].CanonicalModel != "gpt-4o" {
		t.Fatalf("expected gpt-4o at TopCandidates[0], got %+v", out.TopCandidates)
	}
}

func TestOrchestratorFallbackWhenNoClaimedLogprobsBaseline(t *testing.T) {
	suite := makeTestSuite()
	baselines := []Baseline{
		{
			ID:               301,
			CanonicalModel:   "other-model",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorLogprobs,
			Status:           StatusActive,
			MatchThreshold:   0.08,
			SuspectThreshold: 0.18,
			Logprobs: makeLogprobsSignatureFromProbes(
				[]TokenProb{{Token: "x", Prob: 1.0}},
				[]TokenProb{{Token: "y", Prob: 1.0}},
			),
		},
		{
			ID:               302,
			CanonicalModel:   "deepseek-v3",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
			},
		},
	}

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.Kind == DetectorLogprobs {
				t.Fatalf("expected immediate fallback to behavior when claimed model lacks logprobs baseline but has behavior baseline")
			}
			if probe.ID == "bh-1" {
				return ProbeCallResult{Text: `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`, CachedPromptTokens: 700, HTTPStatus: 200}
			}
			return ProbeCallResult{Text: "7", PromptTokens: 35, HTTPStatus: 200}
		},
	}

	orch := NewOrchestrator(client)
	out := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://api.example.com/v1",
			APIKey:   "sk-secret",
		},
		ClaimedModel: "deepseek-v3",
		Suite:        suite,
		Baselines:    baselines,
	})

	if out.DetectorUsed != DetectorBehavior || out.Verdict != VerdictMatch {
		t.Fatalf("expected DetectorBehavior VerdictMatch, got detector=%s verdict=%s", out.DetectorUsed, out.Verdict)
	}
	if !out.PromptInjectionSuspected || out.ObservedPromptTokens != 700 {
		t.Fatalf("expected CachedPromptTokens=700 to trigger injection warning, got injected=%v tokens=%d", out.PromptInjectionSuspected, out.ObservedPromptTokens)
	}
}

func TestOrchestratorUnverifiedWhenNoClaimedBaseline(t *testing.T) {
	suite := makeTestSuite()
	baselines := []Baseline{
		{
			ID:               401,
			CanonicalModel:   "claude-opus-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
			},
		},
		{
			ID:               402,
			CanonicalModel:   "claude-sonnet-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":99,"sorted":[1,2],"parity":"odd"}`}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"4"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
			},
		},
		{
			ID:               403,
			CanonicalModel:   "claude-haiku-4-5",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{"unrelated text output"}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"three"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
			},
		},
		{
			ID:               404,
			CanonicalModel:   "extra-fourth-model",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{"totally different"}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"zero"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
			},
		},
	}

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
			if requestLogprobs {
				t.Fatalf("anthropic must not request logprobs")
			}
			if probe.ID == "bh-1" {
				return ProbeCallResult{Text: `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`, PromptTokens: 32, HTTPStatus: 200}
			}
			return ProbeCallResult{Text: "7", PromptTokens: 20, HTTPStatus: 200}
		},
	}

	orch := NewOrchestrator(client)
	out := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-secret",
		},
		ClaimedModel: "claude-unknown-future",
		Suite:        suite,
		Baselines:    baselines,
	})

	if out.Verdict != VerdictUnverified {
		t.Fatalf("expected VerdictUnverified, got %s", out.Verdict)
	}
	if out.DetectorUsed != DetectorBehavior {
		t.Fatalf("expected DetectorBehavior, got %s", out.DetectorUsed)
	}
	if len(out.TopCandidates) != 3 {
		t.Fatalf("expected Top 3 candidates, got %d (%+v)", len(out.TopCandidates), out.TopCandidates)
	}
	if out.TopCandidates[0].CanonicalModel != "claude-opus-4-6" || !out.TopCandidates[0].WithinMatch {
		t.Fatalf("expected claude-opus-4-6 at TopCandidates[0] within_match=true, got %+v", out.TopCandidates[0])
	}
}

func TestOrchestratorPeerAmbiguityMarksSuspect(t *testing.T) {
	suite := makeTestSuite()
	families := []FamilyMap{
		{
			CanonicalModel: "claude-opus-4-6",
			Family:         "claude-4",
			ConfusionPeers: []string{"claude-sonnet-4-6"},
		},
		{
			CanonicalModel: "claude-sonnet-4-6",
			Family:         "claude-4",
			ConfusionPeers: []string{"claude-opus-4-6"},
		},
	}

	// Choose strings whose BehaviorResponseDistance puts opus <= 0.18 while keeping sonnet within 0.05 of opus.
	obsText := "1: Red\n2: Green\n3: Blue prism splits white light cleanly into seven bright bands"
	opusText := "1: Red\n2: Green\n3: Blue prism splits white light cleanly into seven bright bands"
	sonnetText := "1: Red\n2: Green\n3: Blue prism splits white light cleanly into seven bright band"
	farPeerText := "Completely unrelated multi-sentence prose explanation of optical refraction phenomena"
	dOpus := BehaviorResponseDistance(obsText, opusText)
	dSonnet := BehaviorResponseDistance(obsText, sonnetText)
	if dOpus != 0 || dSonnet <= 0 || dSonnet > 0.05 {
		t.Fatalf("test fixture precondition failed: dOpus=%v dSonnet=%v", dOpus, dSonnet)
	}

	baselines := []Baseline{
		{
			ID:               501,
			CanonicalModel:   "claude-opus-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{opusText}},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}},
				},
			},
		},
		{
			ID:               502,
			CanonicalModel:   "claude-sonnet-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{sonnetText}},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}},
				},
			},
		},
	}

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.ID == "bh-1" {
				return ProbeCallResult{Text: obsText, HTTPStatus: 200}
			}
			return ProbeCallResult{Text: "7", HTTPStatus: 200}
		},
	}

	orch := NewOrchestrator(client)
	out := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-secret",
		},
		ClaimedModel: "claude-opus-4-6",
		Suite:        suite,
		Baselines:    baselines,
		FamilyMaps:   families,
	})

	if out.Verdict != VerdictSuspect {
		t.Fatalf("expected VerdictSuspect due to confusion peer within 0.05 margin, got %s (dist=%v top=%+v)", out.Verdict, out.Distance, out.TopCandidates)
	}
	if len(out.TopCandidates) < 2 || !out.TopCandidates[1].IsConfusionPeer {
		t.Fatalf("expected confusion peer flagged in TopCandidates, got %+v", out.TopCandidates)
	}

	// When the rival is NOT a confusion peer and claimed model is strictly closer, VerdictMatch holds.
	outNonPeer := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-secret",
		},
		ClaimedModel: "claude-opus-4-6",
		Suite:        suite,
		Baselines:    baselines,
		FamilyMaps:   nil, // no confusion_peers declared
	})
	if outNonPeer.Verdict != VerdictMatch {
		t.Fatalf("expected VerdictMatch when no confusion_peers declared and claimed is best, got %s", outNonPeer.Verdict)
	}

	// When the confusion_peer is outside the 0.05 margin, VerdictMatch holds.
	farBaselines := []Baseline{
		baselines[0],
		{
			ID:               503,
			CanonicalModel:   "claude-sonnet-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{farPeerText}},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"12"}},
				},
			},
		},
	}
	outFarPeer := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-secret",
		},
		ClaimedModel: "claude-opus-4-6",
		Suite:        suite,
		Baselines:    farBaselines,
		FamilyMaps:   families,
	})
	if outFarPeer.Verdict != VerdictMatch {
		t.Fatalf("expected VerdictMatch when confusion peer is outside 0.05 margin, got %s (top=%+v)", outFarPeer.Verdict, outFarPeer.TopCandidates)
	}
}

func TestOrchestratorErrorMapping(t *testing.T) {
	suite := makeTestSuite()
	secret := "sk-super-secret-do-not-leak-888"

	cases := []struct {
		name     string
		proto    Protocol
		res      ProbeCallResult
		wantCode string
	}{
		{
			name:     "404 model_not_found on openai_chat",
			proto:    ProtocolOpenAIChat,
			res:      ProbeCallResult{HTTPStatus: 404, ErrorCode: errorCodeModelNotFound, ErrorMessage: "model not found for key " + secret},
			wantCode: "model_not_found",
		},
		{
			name:     "401 auth_error on anthropic",
			proto:    ProtocolAnthropic,
			res:      ProbeCallResult{HTTPStatus: 401, ErrorCode: errorCodeAuthError, ErrorMessage: "Bearer " + secret + " rejected"},
			wantCode: "auth_error",
		},
		{
			name:     "429 rate_limited",
			proto:    ProtocolOpenAIResponses,
			res:      ProbeCallResult{HTTPStatus: 429, ErrorCode: errorCodeRateLimited, ErrorMessage: "rate limit hit with " + secret},
			wantCode: "rate_limited",
		},
		{
			name:     "ssrf_blocked",
			proto:    ProtocolGemini,
			res:      ProbeCallResult{ErrorCode: errorCodeSSRFBlocked, ErrorMessage: "blocked private IP"},
			wantCode: "ssrf_blocked",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockProbeClient{
				handler: func(_ context.Context, _ ProbeTarget, _ string, _ ProbeDefinition, _ bool, _ int) ProbeCallResult {
					return tc.res
				},
			}
			orch := NewOrchestrator(client)
			out := orch.VerifyModel(context.Background(), VerifyModelInput{
				Target: ProbeTarget{
					Protocol: tc.proto,
					BaseURL:  "https://api.example.com/v1",
					APIKey:   secret,
				},
				ClaimedModel: "gpt-4o",
				Suite:        suite,
				Baselines: []Baseline{
					{
						ID:               1,
						CanonicalModel:   "gpt-4o",
						Protocol:         tc.proto,
						SuiteID:          suite.ID,
						DetectorKind:     DetectorLogprobs,
						Status:           StatusActive,
						MatchThreshold:   0.08,
						SuspectThreshold: 0.18,
						Logprobs:         makeLogprobsSignatureFromProbes([]TokenProb{{Token: "a", Prob: 1}}, []TokenProb{{Token: "b", Prob: 1}}),
					},
				},
			})

			if out.Verdict != VerdictError {
				t.Fatalf("expected VerdictError, got %s", out.Verdict)
			}
			if out.ErrorCode != tc.wantCode {
				t.Fatalf("expected ErrorCode=%q, got %q", tc.wantCode, out.ErrorCode)
			}
			if strings.Contains(out.ErrorMessage, secret) {
				t.Fatalf("ErrorMessage leaked secret: %q", out.ErrorMessage)
			}
			for _, ev := range out.Evidence {
				if strings.Contains(ev.ErrorMessage, secret) {
					t.Fatalf("ProbeEvidence leaked secret: %q", ev.ErrorMessage)
				}
			}
		})
	}
}

func TestOrchestratorStaleBaselineFallback(t *testing.T) {
	suite := makeTestSuite()
	oldTime := time.Now().Add(-90 * 24 * time.Hour)
	baselines := []Baseline{
		{
			ID:               601,
			CanonicalModel:   "claude-sonnet-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			TTLDays:          60,
			CollectedAt:      oldTime,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":55}`}},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}},
				},
			},
		},
		{
			ID:               602,
			CanonicalModel:   "claude-sonnet-4-6",
			Protocol:         ProtocolAnthropic,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusArchived, // must be ignored
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{"wrong"}},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"999"}},
				},
			},
		},
	}

	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.ID == "bh-1" {
				return ProbeCallResult{Text: `{"sum":55}`, HTTPStatus: 200}
			}
			return ProbeCallResult{Text: "7", HTTPStatus: 200}
		},
	}

	orch := NewOrchestrator(client)
	out := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-key",
		},
		ClaimedModel: "claude-sonnet-4-6",
		Suite:        suite,
		Baselines:    baselines,
	})

	if out.Verdict != VerdictMatch {
		t.Fatalf("expected VerdictMatch using stale baseline, got %s", out.Verdict)
	}
	if !out.UsedStaleBaseline {
		t.Fatalf("expected UsedStaleBaseline=true")
	}
	if len(out.TopCandidates) != 1 || out.TopCandidates[0].Freshness != FreshnessStale {
		t.Fatalf("expected candidate marked FreshnessStale, got %+v", out.TopCandidates)
	}
}

func TestCaptureModelSignatures(t *testing.T) {
	suite := makeTestSuite()

	t.Run("openai_chat runs both logprobs and behavior across K rounds", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, idx int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs {
					if !requestLogprobs {
						t.Fatalf("expected requestLogprobs=true for logprobs probe")
					}
					if probe.ID == "lp-1" {
						return ProbeCallResult{
							Logprobs:          []TokenProb{{Token: " sky", Prob: 0.70}, {Token: " mist", Prob: 0.20}},
							LogprobsSupported: true,
							PromptTokens:      20,
							HTTPStatus:        200,
						}
					}
					return ProbeCallResult{
						Logprobs:          []TokenProb{{Token: "ok", Prob: 0.85}},
						LogprobsSupported: true,
						PromptTokens:      22,
						HTTPStatus:        200,
					}
				}
				if requestLogprobs {
					t.Fatalf("behavior probe must not request logprobs")
				}
				if probe.ID == "bh-1" {
					return ProbeCallResult{
						Text:              `{"sum":55,"sorted":[3,7,9,14,22],"parity":"odd"}`,
						ResponseModel:     "gpt-4o-2024-11-20",
						SystemFingerprint: "fp_test_1",
						PromptTokens:      35,
						HTTPStatus:        200,
					}
				}
				return ProbeCallResult{
					Text:              "7",
					ResponseModel:     "gpt-4o-2024-11-20",
					SystemFingerprint: "fp_test_1",
					PromptTokens:      25,
					HTTPStatus:        200,
				}
			},
		}

		orch := NewOrchestrator(client)
		samples, err := orch.CaptureModelSignatures(context.Background(), ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://api.openai.com/v1",
			APIKey:   "sk-openai-secret",
		}, "gpt-4o", suite, 3)
		if err != nil {
			t.Fatalf("CaptureModelSignatures failed: %v", err)
		}
		if !samples.LogprobsSupported || samples.AggregatedLogprobs == nil {
			t.Fatalf("expected logprobs samples captured, got %+v", samples)
		}
		if len(samples.LogprobsRounds) != 3 || len(samples.BehaviorRounds) != 3 {
			t.Fatalf("expected 3 logprobs and 3 behavior rounds, got lp=%d bh=%d", len(samples.LogprobsRounds), len(samples.BehaviorRounds))
		}
		if samples.AggregatedBehavior == nil || len(samples.AggregatedBehavior.ResponseModels) == 0 {
			t.Fatalf("expected aggregated behavior signature with metadata, got %+v", samples.AggregatedBehavior)
		}
		if len(client.recordedCalls()) != 3*len(suite.Probes) {
			t.Fatalf("expected %d probe calls, got %d", 3*len(suite.Probes), len(client.recordedCalls()))
		}
	})

	t.Run("anthropic runs only behavior probes", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs || requestLogprobs {
					t.Fatalf("anthropic capture must only run behavior probes")
				}
				if probe.ID == "bh-1" {
					return ProbeCallResult{Text: `{"sum":55}`, ResponseModel: "claude-sonnet-4-6", HTTPStatus: 200}
				}
				return ProbeCallResult{Text: "7", ResponseModel: "claude-sonnet-4-6", HTTPStatus: 200}
			},
		}

		orch := NewOrchestrator(client)
		samples, err := orch.CaptureModelSignatures(context.Background(), ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-secret",
		}, "claude-sonnet-4-6", suite, 3)
		if err != nil {
			t.Fatalf("CaptureModelSignatures failed: %v", err)
		}
		if samples.LogprobsSupported || samples.AggregatedLogprobs != nil {
			t.Fatalf("expected LogprobsSupported=false on anthropic")
		}
		if len(samples.BehaviorRounds) != 3 || samples.AggregatedBehavior == nil {
			t.Fatalf("expected 3 behavior rounds, got %+v", samples)
		}
		if len(client.recordedCalls()) != 3*2 {
			t.Fatalf("expected 6 behavior probe calls, got %d", len(client.recordedCalls()))
		}
	})

	t.Run("openai_chat with stripped logprobs falls back to behavior baseline only", func(t *testing.T) {
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs {
					return ProbeCallResult{Text: "sky", LogprobsSupported: false, PromptTokens: 4120, HTTPStatus: 200}
				}
				if probe.ID == "bh-1" {
					return ProbeCallResult{Text: `{"sum":55}`, ResponseModel: "gpt-4o", HTTPStatus: 200}
				}
				return ProbeCallResult{Text: "7", ResponseModel: "gpt-4o", HTTPStatus: 200}
			},
		}

		orch := NewOrchestrator(client)
		samples, err := orch.CaptureModelSignatures(context.Background(), ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://relay.example.com/v1",
			APIKey:   "sk-relay-secret",
		}, "gpt-4o", suite, 3)
		if err != nil {
			t.Fatalf("CaptureModelSignatures failed: %v", err)
		}
		if samples.LogprobsSupported || samples.AggregatedLogprobs != nil {
			t.Fatalf("expected LogprobsSupported=false when upstream strips logprobs")
		}
		if len(samples.BehaviorRounds) != 3 || samples.AggregatedBehavior == nil {
			t.Fatalf("expected 3 behavior rounds captured")
		}
		if !samples.PromptInjectionSuspected || samples.ObservedPromptTokens != 4120 {
			t.Fatalf("expected injection telemetry captured, got injected=%v tokens=%d", samples.PromptInjectionSuspected, samples.ObservedPromptTokens)
		}
	})

	t.Run("openai_responses runs only behavior probes and redacts errors", func(t *testing.T) {
		secret := "sk-responses-secret-777"
		client := &mockProbeClient{
			handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, requestLogprobs bool, _ int) ProbeCallResult {
				if probe.Kind == DetectorLogprobs || requestLogprobs {
					t.Fatalf("openai_responses capture must not run logprobs probes")
				}
				return ProbeCallResult{HTTPStatus: 401, ErrorCode: errorCodeAuthError, ErrorMessage: "bad key " + secret}
			},
		}

		orch := NewOrchestrator(client)
		_, err := orch.CaptureModelSignatures(context.Background(), ProbeTarget{
			Protocol: ProtocolOpenAIResponses,
			BaseURL:  "https://api.openai.com/v1",
			APIKey:   secret,
		}, "gpt-5", suite, 3)
		if err == nil {
			t.Fatalf("expected capture error on 401")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("capture error leaked secret: %v", err)
		}
	})
}

func TestBehaviorMetaAndSuspectBandAndSecretRedaction(t *testing.T) {
	suite := makeTestSuite()
	secret := "sk-echo-secret-12345"
	hasReasoningFalse := false

	baselines := []Baseline{
		{
			ID:               701,
			CanonicalModel:   "deepseek-v3",
			Protocol:         ProtocolOpenAIChat,
			SuiteID:          suite.ID,
			DetectorKind:     DetectorBehavior,
			Status:           StatusActive,
			MatchThreshold:   0.18,
			SuspectThreshold: 0.32,
			Behavior: &BehaviorSignature{
				Probes: map[string]BehaviorProbeSignature{
					"bh-1": {ProbeID: "bh-1", Samples: []string{`{"sum":55}`}, ExpectedFormat: "json", FormatMatchRate: 1.0},
					"bh-2": {ProbeID: "bh-2", Samples: []string{"7"}, ExpectedFormat: "integer", FormatMatchRate: 1.0},
				},
				ResponseModels:    []string{"deepseek-chat"},
				HasReasoningField: &hasReasoningFalse,
			},
		},
	}

	// Returning identical text ("55", "7") but exposing HasReasoningField=true and foreign ResponseModel
	// pushes meta penalty into suspect band (0.25 in (0.18, 0.32]).
	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.ID == "bh-1" {
				return ProbeCallResult{
					Text:              `{"sum":55}`,
					ResponseModel:     "deepseek-reasoner",
					HasReasoningField: true,
					PromptTokens:      40,
					HTTPStatus:        200,
				}
			}
			return ProbeCallResult{
				Text:              "7",
				ResponseModel:     "deepseek-reasoner",
				HasReasoningField: true,
				PromptTokens:      40,
				HTTPStatus:        200,
			}
		},
	}

	orch := NewOrchestrator(client)
	out := orch.VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://api.example.com/v1",
			APIKey:   secret,
		},
		ClaimedModel: "deepseek-v3",
		Suite:        suite,
		Baselines:    baselines,
	})

	if out.Verdict != VerdictSuspect {
		t.Fatalf("expected VerdictSuspect due to reasoning+model meta mismatch (dist=0.25), got %s (dist=%v)", out.Verdict, out.Distance)
	}

	// Verify secret echoed in upstream response text or response_model is redacted from ProbeEvidence.
	echoClient := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			return ProbeCallResult{
				Text:          "7 " + secret,
				ResponseModel: "model-" + secret,
				HTTPStatus:    200,
			}
		},
	}
	outEcho := NewOrchestrator(echoClient).VerifyModel(context.Background(), VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolOpenAIChat,
			BaseURL:  "https://api.example.com/v1",
			APIKey:   secret,
		},
		ClaimedModel: "deepseek-v3",
		Suite:        suite,
		Baselines:    baselines,
	})
	for _, ev := range outEcho.Evidence {
		if strings.Contains(ev.ObservedText, secret) || strings.Contains(ev.ResponseModel, secret) {
			t.Fatalf("evidence leaked secret: %+v", ev)
		}
	}
}

func TestOrchestratorContextCanceledReturnsError(t *testing.T) {
	suite := makeTestSuite()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := &mockProbeClient{}
	orch := NewOrchestrator(client)
	out := orch.VerifyModel(ctx, VerifyModelInput{
		Target: ProbeTarget{
			Protocol: ProtocolAnthropic,
			BaseURL:  "https://api.anthropic.com",
			APIKey:   "sk-ant-key",
		},
		ClaimedModel: "claude-sonnet-4-6",
		Suite:        suite,
	})

	if out.Verdict != VerdictError {
		t.Fatalf("expected VerdictError on canceled context, got %s", out.Verdict)
	}
	if out.ErrorCode != errorCodeContextCanceled {
		t.Fatalf("expected ErrorCode=%q, got %q", errorCodeContextCanceled, out.ErrorCode)
	}
}

func TestDetectorsWeightedDistanceAndEvidenceAndToRunItem(t *testing.T) {
	suite := makeTestSuite()
	base := Baseline{
		ID:               801,
		CanonicalModel:   "gpt-4o",
		Protocol:         ProtocolOpenAIChat,
		SuiteID:          suite.ID,
		DetectorKind:     DetectorLogprobs,
		Status:           StatusActive,
		MatchThreshold:   0.08,
		SuspectThreshold: 0.18,
		Logprobs: makeLogprobsSignatureFromProbes(
			[]TokenProb{{Token: "a", Prob: 1.0}},
			[]TokenProb{{Token: "b", Prob: 1.0}},
		),
	}

	// lp-1 (weight 1.0) matches identically (JSD=0), lp-2 (weight 2.0) is disjoint (JSD=1).
	// Weighted distance must be (1*0 + 2*1) / 3 = 2/3.
	obs := &ObservedSignature{
		Kind:       DetectorLogprobs,
		Applicable: true,
		ProbeWeights: map[string]float64{
			"lp-1": 1.0,
			"lp-2": 2.0,
		},
		Logprobs: makeLogprobsSignatureFromProbes(
			[]TokenProb{{Token: "a", Prob: 1.0}},
			[]TokenProb{{Token: "z", Prob: 1.0}},
		),
	}
	d := NewLogprobsDetector().Distance(obs, base)
	want := 2.0 / 3.0
	if d < want-1e-6 || d > want+1e-6 {
		t.Fatalf("expected weighted JSD %v, got %v", want, d)
	}

	// Verify ProbeEvidence receives TopKOverlap and BaselineTopTokens, and ToRunItem preserves fields.
	client := &mockProbeClient{
		handler: func(_ context.Context, _ ProbeTarget, _ string, probe ProbeDefinition, _ bool, _ int) ProbeCallResult {
			if probe.ID == "lp-1" {
				return ProbeCallResult{Logprobs: []TokenProb{{Token: "a", Prob: 1.0}}, LogprobsSupported: true, HTTPStatus: 200}
			}
			return ProbeCallResult{Logprobs: []TokenProb{{Token: "b", Prob: 1.0}}, LogprobsSupported: true, HTTPStatus: 200}
		},
	}
	out := NewOrchestrator(client).VerifyModel(context.Background(), VerifyModelInput{
		Target:       ProbeTarget{Protocol: ProtocolOpenAIChat, BaseURL: "https://api.example.com/v1", APIKey: "sk-key"},
		ClaimedModel: "gpt-4o",
		Suite:        suite,
		Baselines:    []Baseline{base},
	})
	if len(out.Evidence) != 2 {
		t.Fatalf("expected 2 logprobs evidence items, got %d", len(out.Evidence))
	}
	for _, ev := range out.Evidence {
		if ev.TopKOverlap < 0.99 || len(ev.BaselineTopTokens) == 0 || len(ev.ObservedTopTokens) == 0 {
			t.Fatalf("expected enriched top-k evidence, got %+v", ev)
		}
	}
	item := out.ToRunItem(99)
	if item.RunID != 99 || item.Verdict != VerdictMatch || item.ClaimedModel != "gpt-4o" {
		t.Fatalf("unexpected RunItem conversion: %+v", item)
	}
}
