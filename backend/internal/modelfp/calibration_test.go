package modelfp

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

func TestNormalizeAndJSD(t *testing.T) {
	p := NormalizeTokenDistribution([]TokenProb{{Token: " the", Prob: 0.6}, {Token: " a", Prob: 0.3}})
	if math.Abs(p["<OTHER>"]-0.1) > 1e-6 {
		t.Fatalf("expected <OTHER>=0.1, got %v", p["<OTHER>"])
	}
	if d := JensenShannonDivergence(p, p); d > 1e-9 {
		t.Fatalf("expected self JSD 0, got %v", d)
	}
	q := NormalizeTokenDistribution([]TokenProb{{Token: "xyz", Prob: 1.0}})
	if d := JensenShannonDivergence(p, q); d < 0.99 || d > 1.000001 {
		t.Fatalf("expected disjoint JSD ~1.0, got %v", d)
	}
	if math.Abs(JensenShannonDivergence(p, q)-JensenShannonDivergence(q, p)) > 1e-9 {
		t.Fatalf("expected JSD symmetry")
	}

	// Byte/whitespace sensitivity must be preserved.
	pTrimmed := NormalizeTokenDistribution([]TokenProb{{Token: "the", Prob: 1.0}})
	pSpaced := NormalizeTokenDistribution([]TokenProb{{Token: " the", Prob: 1.0}})
	if d := JensenShannonDivergence(pTrimmed, pSpaced); d < 0.99 {
		t.Fatalf("expected leading-space distinction to yield disjoint JSD ~1.0, got %v", d)
	}

	// Empty distribution collapses safely into <OTHER>=1.0 and over-sum >1 renormalizes.
	empty := NormalizeTokenDistribution(nil)
	if math.Abs(empty["<OTHER>"]-1.0) > 1e-9 {
		t.Fatalf("expected empty distribution to assign 1.0 to <OTHER>, got %+v", empty)
	}
	over := NormalizeTokenDistribution([]TokenProb{{Token: "a", Prob: 0.8}, {Token: "b", Prob: 0.8}})
	if math.Abs(over["a"]-0.5) > 1e-6 || math.Abs(over["b"]-0.5) > 1e-6 {
		t.Fatalf("expected over-unity probs to renormalize to 0.5/0.5, got %+v", over)
	}
}

func TestTopKOverlap(t *testing.T) {
	p := NormalizeTokenDistribution([]TokenProb{
		{Token: "a", Prob: 0.4},
		{Token: "b", Prob: 0.3},
		{Token: "c", Prob: 0.1},
		{Token: "d", Prob: 0.05},
		{Token: "e", Prob: 0.05},
	})
	q := NormalizeTokenDistribution([]TokenProb{
		{Token: "a", Prob: 0.45},
		{Token: "b", Prob: 0.25},
		{Token: "c", Prob: 0.1},
		{Token: "x", Prob: 0.05},
		{Token: "y", Prob: 0.05},
	})
	if ov := TopKOverlap(p, p, 5); math.Abs(ov-1.0) > 1e-9 {
		t.Fatalf("expected self top-k overlap 1.0, got %v", ov)
	}
	if ov := TopKOverlap(p, q, 5); math.Abs(ov-0.6) > 1e-9 {
		t.Fatalf("expected top-5 overlap 0.6 (3/5), got %v", ov)
	}
	r := NormalizeTokenDistribution([]TokenProb{{Token: "z", Prob: 1.0}})
	if ov := TopKOverlap(p, r, 5); ov != 0 {
		t.Fatalf("expected disjoint overlap 0, got %v", ov)
	}
	if ov := TopKOverlap(p, q, 0); ov != 0 {
		t.Fatalf("expected k=0 overlap 0, got %v", ov)
	}
}

func TestBehaviorResponseDistance(t *testing.T) {
	if d := BehaviorResponseDistance("  alpha\r\nbeta  ", "alpha\nbeta"); d > 1e-9 {
		t.Fatalf("expected whitespace/newline normalized distance 0, got %v", d)
	}
	dSame := BehaviorResponseDistance(`{"sum":55}`, `{"sum":55}`)
	if dSame != 0 {
		t.Fatalf("expected identical distance 0, got %v", dSame)
	}
	dClose := BehaviorResponseDistance(`{"sum":55,"parity":"odd"}`, `{"sum":55,"parity":"even"}`)
	dFar := BehaviorResponseDistance(`{"sum":55,"parity":"odd"}`, `完全不同的中文长文本输出内容`)
	if dClose <= 0 || dClose >= dFar || dFar > 1.0 {
		t.Fatalf("unexpected behavior distance ordering: close=%v far=%v", dClose, dFar)
	}
	if math.Abs(BehaviorResponseDistance("abc", "axc")-BehaviorResponseDistance("axc", "abc")) > 1e-9 {
		t.Fatalf("expected symmetric distance")
	}
	if d := BehaviorResponseDistance("", "nonempty"); math.Abs(d-1.0) > 1e-9 {
		t.Fatalf("expected empty vs nonempty distance 1.0, got %v", d)
	}
}

func TestComputeSelfDivergenceP95(t *testing.T) {
	if got := ComputeSelfDivergenceP95(nil); got != 0 {
		t.Fatalf("expected empty slice p95 0, got %v", got)
	}
	vals := []float64{0.02, 0.01, 0.08, 0.03, 0.05, 0.04, 0.02, 0.01, 0.03, 0.02}
	p95 := ComputeSelfDivergenceP95(vals)
	if p95 < 0.05 || p95 > 0.08 {
		t.Fatalf("unexpected p95 value: %v", p95)
	}
}

func TestDeriveThresholdsEdgeCases(t *testing.T) {
	// Review Focus #4: zero variance and no neighbors must not collapse to 0
	m, s := DeriveThresholds(DetectorLogprobs, 0.0, nil)
	if m < 0.03 || m > 0.25 || s <= m || s > 0.45 {
		t.Fatalf("unexpected logprobs bounds: match=%v suspect=%v", m, s)
	}
	bm, bs := DeriveThresholds(DetectorBehavior, 0.0, nil)
	if bm < 0.12 || bm > 0.38 || bs <= bm || bs > 0.60 {
		t.Fatalf("unexpected behavior bounds: match=%v suspect=%v", bm, bs)
	}
	near := 0.20
	m2, s2 := DeriveThresholds(DetectorLogprobs, 0.02, &near)
	if math.Abs(m2-0.05) > 1e-6 || math.Abs(s2-0.13) > 1e-6 {
		t.Fatalf("expected match=0.05 suspect=0.13, got match=%v suspect=%v", m2, s2)
	}

	// Very tight neighbor must not collapse match below epsilon_min (0.03 / 0.12).
	tight := 0.01
	mTight, sTight := DeriveThresholds(DetectorLogprobs, 0.0, &tight)
	if mTight < 0.03 || sTight <= mTight || sTight > 0.45 {
		t.Fatalf("tight neighbor violated logprobs floor: match=%v suspect=%v", mTight, sTight)
	}
	nearBh := 0.50
	bm2, bs2 := DeriveThresholds(DetectorBehavior, 0.10, &nearBh)
	if bm2 < 0.12 || bm2 > 0.38 || bs2 <= bm2 || bs2 > 0.60 {
		t.Fatalf("unexpected behavior calibrated bounds: match=%v suspect=%v", bm2, bs2)
	}
}

func TestBuildConfusionMatrix(t *testing.T) {
	empty := BuildConfusionMatrix(nil, nil)
	if len(empty.Models) != 0 || len(empty.Matrix) != 0 {
		t.Fatalf("expected empty confusion matrix, got %+v", empty)
	}

	baselines := []Baseline{
		{
			ID:                1,
			CanonicalModel:    "claude-sonnet-4-6",
			Protocol:          ProtocolAnthropic,
			SuiteID:           1,
			DetectorKind:      DetectorBehavior,
			SelfDivergenceP95: 0.08,
			MatchThreshold:    0.18,
			SuspectThreshold:  0.30,
		},
		{
			ID:                2,
			CanonicalModel:    "claude-opus-4-6",
			Protocol:          ProtocolAnthropic,
			SuiteID:           1,
			DetectorKind:      DetectorBehavior,
			SelfDivergenceP95: 0.06,
			MatchThreshold:    0.16,
			SuspectThreshold:  0.28,
		},
		{
			ID:                3,
			CanonicalModel:    "gpt-4o",
			Protocol:          ProtocolAnthropic,
			SuiteID:           1,
			DetectorKind:      DetectorBehavior,
			SelfDivergenceP95: 0.05,
			MatchThreshold:    0.15,
			SuspectThreshold:  0.26,
		},
	}

	res := BuildConfusionMatrix(baselines, func(a, b Baseline) float64 {
		if (a.CanonicalModel == "claude-opus-4-6" && b.CanonicalModel == "claude-sonnet-4-6") ||
			(a.CanonicalModel == "claude-sonnet-4-6" && b.CanonicalModel == "claude-opus-4-6") {
			return 0.10 // < 1.5 * 0.08 = 0.12 -> triggers overlap warning
		}
		return 0.72
	})

	if len(res.Models) != 3 || len(res.Matrix) != 3 {
		t.Fatalf("expected 3x3 matrix, got %+v", res)
	}
	for i := range res.Matrix {
		if res.Matrix[i][i] != 0 {
			t.Fatalf("expected diagonal 0 at %d, got %v", i, res.Matrix[i][i])
		}
		for j := range res.Matrix[i] {
			if math.Abs(res.Matrix[i][j]-res.Matrix[j][i]) > 1e-9 {
				t.Fatalf("matrix not symmetric at (%d,%d)", i, j)
			}
		}
	}
	if math.Abs(res.MinOffDiagonal-0.10) > 1e-9 {
		t.Fatalf("expected min off-diagonal 0.10, got %v", res.MinOffDiagonal)
	}
	if len(res.ClosePairs) == 0 || !res.ClosePairs[0].OverlapWarning {
		t.Fatalf("expected overlap warning on close pair, got %+v", res.ClosePairs)
	}
}

func TestComputeContentHashDeterministic(t *testing.T) {
	a := map[string]any{"b": 2, "a": []string{"<OTHER>", "x"}, "nested": map[string]int{"z": 9, "m": 1}}
	b := map[string]any{"nested": map[string]int{"m": 1, "z": 9}, "a": []string{"<OTHER>", "x"}, "b": 2}
	ha, err := ComputeContentHash(a)
	if err != nil {
		t.Fatalf("ComputeContentHash(a) failed: %v", err)
	}
	hb, err := ComputeContentHash(b)
	if err != nil {
		t.Fatalf("ComputeContentHash(b) failed: %v", err)
	}
	if len(ha) != 64 || ha != hb {
		t.Fatalf("expected matching 64-char sha256 hex digests, got %q vs %q", ha, hb)
	}
	hc, err := ComputeContentHash(map[string]any{"b": 3})
	if err != nil || hc == ha {
		t.Fatalf("expected distinct hash for modified input")
	}
}

func TestSeedsLoadValidJSON(t *testing.T) {
	suites, families, baselines, err := LoadSeedData()
	if err != nil {
		t.Fatalf("LoadSeedData failed: %v", err)
	}
	if len(suites) == 0 || suites[0].SuiteKey != "builtin-public" || suites[0].Version != "v1" {
		t.Fatalf("unexpected seed suites: %+v", suites)
	}
	suite := suites[0]
	if suite.Visibility != VisibilityPublic || !suite.IsDefault || suite.Status != StatusActive {
		t.Fatalf("unexpected default suite flags: %+v", suite)
	}
	var lpCount, bhCount int
	for _, p := range suite.Probes {
		if p.ExpectedMaxPromptTokens != 500 || p.Temperature != 0 {
			t.Fatalf("unexpected probe defaults for %s: %+v", p.ID, p)
		}
		switch p.Kind {
		case DetectorLogprobs:
			lpCount++
			if p.MaxTokens != 1 || p.TopLogprobs != 20 {
				t.Fatalf("unexpected logprobs probe config for %s: %+v", p.ID, p)
			}
		case DetectorBehavior:
			bhCount++
			if p.MaxTokens != 64 {
				t.Fatalf("unexpected behavior probe config for %s: %+v", p.ID, p)
			}
		default:
			t.Fatalf("unknown detector kind %q on probe %s", p.Kind, p.ID)
		}
	}
	if lpCount != 4 || bhCount != 5 {
		t.Fatalf("expected 4 logprobs and 5 behavior probes, got lp=%d bh=%d", lpCount, bhCount)
	}
	wantHash, err := ComputeContentHash(suite.Probes)
	if err != nil || suite.ContentHash != wantHash {
		t.Fatalf("suite ContentHash mismatch: got=%q want=%q err=%v", suite.ContentHash, wantHash, err)
	}

	if len(families) == 0 {
		t.Fatalf("expected default family maps")
	}
	hasModel := make(map[string]bool, len(families))
	seenAliases := make(map[string]string)
	for _, fm := range families {
		if fm.CanonicalModel == "" || fm.Family == "" {
			t.Fatalf("family map missing canonical_model or family: %+v", fm)
		}
		if hasModel[fm.CanonicalModel] {
			t.Fatalf("duplicate canonical_model %q in seed family maps", fm.CanonicalModel)
		}
		hasModel[fm.CanonicalModel] = true
		for _, alias := range fm.Aliases {
			if prev, exists := seenAliases[alias]; exists {
				t.Fatalf("duplicate alias %q across %q and %q", alias, prev, fm.CanonicalModel)
			}
			seenAliases[alias] = fm.CanonicalModel
		}
	}
	for _, required := range []string{"claude-opus-4-6", "claude-sonnet-4-6", "gpt-4o", "gpt-5", "gemini-2.5-pro", "deepseek-v3", "deepseek-r1"} {
		if !hasModel[required] {
			t.Fatalf("expected canonical model %q in default family maps", required)
		}
	}
	if len(baselines) != 0 {
		t.Fatalf("seed baselines must not contain fabricated distributions, got %d", len(baselines))
	}
}

func TestErrorSentinelsAndSecretRedaction(t *testing.T) {
	if got := infraerrors.Reason(ErrUnsupportedAccountType); got != "MODELFP_UNSUPPORTED_ACCOUNT_TYPE" {
		t.Fatalf("unexpected reason for ErrUnsupportedAccountType: %q", got)
	}
	if errors.Is(ErrUnsupportedAccountType, ErrNotFound) {
		t.Fatalf("error sentinels must be distinguishable via errors.Is")
	}
	if errors.Is(ErrInvalidBundleChecksum, ErrSuiteImmutable) {
		t.Fatalf("error sentinels must be distinguishable via errors.Is")
	}

	raw, err := json.Marshal(ProbeTarget{
		Source:       TargetSourceAdHoc,
		Protocol:     ProtocolOpenAIChat,
		BaseURL:      "https://api.example.com/v1",
		APIKey:       "sk-secret-do-not-marshal",
		ProxyURL:     "http://user:pass@proxy.internal:8080",
		ExtraHeaders: map[string]string{"Authorization": "Bearer topsecret"},
	})
	if err != nil {
		t.Fatalf("marshal ProbeTarget failed: %v", err)
	}
	for _, secret := range []string{"sk-secret-do-not-marshal", "user:pass", "topsecret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("ProbeTarget JSON serialization leaked secret %q: %s", secret, string(raw))
		}
	}
}
