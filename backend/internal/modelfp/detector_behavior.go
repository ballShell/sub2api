package modelfp

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

const (
	behaviorFormatPenaltyWeight = 0.20
	behaviorMetaPenaltyWeight   = 0.25
)

// BehaviorProtocolDetector verifies models via deterministic behavior probes and protocol metadata.
type BehaviorProtocolDetector struct{}

// NewBehaviorProtocolDetector constructs a BehaviorProtocolDetector instance.
func NewBehaviorProtocolDetector() *BehaviorProtocolDetector {
	return &BehaviorProtocolDetector{}
}

// Kind returns DetectorBehavior.
func (d *BehaviorProtocolDetector) Kind() DetectorKind {
	return DetectorBehavior
}

// ProbeModel executes all behavior probes in suite and captures normalized text and protocol metadata.
func (d *BehaviorProtocolDetector) ProbeModel(
	ctx context.Context,
	client ProbeClient,
	target ProbeTarget,
	model string,
	suite ProbeSuite,
) (*ObservedSignature, error) {
	sig := &BehaviorSignature{
		Probes: make(map[string]BehaviorProbeSignature),
	}
	seenModels := make(map[string]struct{})
	seenFingerprints := make(map[string]struct{})
	anyReasoning := false

	obs, successCount, err := executeDetectorProbes(
		ctx,
		client,
		target,
		model,
		suite,
		DetectorBehavior,
		false,
		func(probe ProbeDefinition, res ProbeCallResult, ev *ProbeEvidence) {
			normText := normalizeBehaviorText(redactExactSecrets(res.Text, target))
			ev.ObservedText = normText

			var matchRate float64
			if matchesExpectedFormat(normText, probe.ExpectedFormat) {
				matchRate = 1.0
			}
			sig.Probes[probe.ID] = BehaviorProbeSignature{
				ProbeID:         probe.ID,
				Samples:         []string{normText},
				ExpectedFormat:  probe.ExpectedFormat,
				FormatMatchRate: matchRate,
			}

			if ev.ResponseModel != "" {
				if _, ok := seenModels[ev.ResponseModel]; !ok {
					seenModels[ev.ResponseModel] = struct{}{}
					sig.ResponseModels = append(sig.ResponseModels, ev.ResponseModel)
				}
			}
			if ev.SystemFingerprint != "" {
				if _, ok := seenFingerprints[ev.SystemFingerprint]; !ok {
					seenFingerprints[ev.SystemFingerprint] = struct{}{}
					sig.SystemFingerprints = append(sig.SystemFingerprints, ev.SystemFingerprint)
				}
			}
			if res.HasReasoningField {
				anyReasoning = true
			}
		},
	)
	if successCount > 0 {
		reasoningFlag := anyReasoning
		sig.HasReasoningField = &reasoningFlag
	}
	if obs != nil {
		obs.Behavior = sig
		obs.Applicable = successCount > 0
	}
	return obs, err
}

// Distance computes the weighted behavioral response distance combined with format compliance
// and protocol-meta consistency signals.
func (d *BehaviorProtocolDetector) Distance(observed *ObservedSignature, baseline Baseline) float64 {
	if observed == nil || !observed.Applicable || observed.Behavior == nil || baseline.Behavior == nil {
		return 1.0
	}

	probeIDs := make([]string, 0, len(observed.Behavior.Probes))
	for pid := range observed.Behavior.Probes {
		probeIDs = append(probeIDs, pid)
	}
	sort.Strings(probeIDs)

	var weightedSum float64
	var totalWeight float64
	for _, pid := range probeIDs {
		obsProbe := observed.Behavior.Probes[pid]
		baseProbe, ok := baseline.Behavior.Probes[pid]
		if !ok || len(obsProbe.Samples) == 0 || len(baseProbe.Samples) == 0 {
			continue
		}

		_, probeDist := closestSample(obsProbe.Samples[0], baseProbe.Samples)
		expectedFmt := obsProbe.ExpectedFormat
		if expectedFmt == "" {
			expectedFmt = baseProbe.ExpectedFormat
		}
		if expectedFmt != "" && baseProbe.FormatMatchRate >= 0.8 && !matchesExpectedFormat(obsProbe.Samples[0], expectedFmt) {
			probeDist = clampFloat(probeDist+behaviorFormatPenaltyWeight, 0, 1)
		}

		w := probeWeight(observed, pid)
		weightedSum += w * probeDist
		totalWeight += w
	}

	if totalWeight <= 0 {
		return 1.0
	}

	avgProbeDist := clampFloat(weightedSum/totalWeight, 0, 1)
	metaPenalty := behaviorMetaMismatch(observed.Behavior, baseline)
	return clampFloat(avgProbeDist+behaviorMetaPenaltyWeight*metaPenalty, 0, 1)
}

func closestSample(observedText string, samples []string) (string, float64) {
	if len(samples) == 0 {
		return "", 1.0
	}
	bestText := samples[0]
	bestDist := BehaviorResponseDistance(observedText, samples[0])
	for _, s := range samples[1:] {
		dist := BehaviorResponseDistance(observedText, s)
		if dist < bestDist {
			bestDist = dist
			bestText = s
		}
	}
	return bestText, bestDist
}

func behaviorMetaMismatch(obs *BehaviorSignature, baseline Baseline) float64 {
	if obs == nil || baseline.Behavior == nil {
		return 0
	}

	var mismatchSum float64
	var weightSum float64

	if baseline.Behavior.HasReasoningField != nil && obs.HasReasoningField != nil {
		weightSum += 1.0
		if *baseline.Behavior.HasReasoningField != *obs.HasReasoningField {
			mismatchSum += 1.0
		}
	}

	if len(baseline.Behavior.ResponseModels) > 0 && len(obs.ResponseModels) > 0 {
		weightSum += 1.0
		if !anyResponseModelMatch(obs.ResponseModels, baseline.Behavior.ResponseModels, baseline.CanonicalModel) {
			mismatchSum += 1.0
		}
	}

	if len(baseline.Behavior.SystemFingerprints) > 0 && len(obs.SystemFingerprints) > 0 {
		weightSum += 0.25
		if !anyCaseInsensitiveOverlap(obs.SystemFingerprints, baseline.Behavior.SystemFingerprints) {
			mismatchSum += 0.25
		}
	}

	if weightSum <= 0 {
		return 0
	}
	return clampFloat(mismatchSum/weightSum, 0, 1)
}

func anyResponseModelMatch(observedModels, baselineModels []string, canonicalModel string) bool {
	for _, obsM := range observedModels {
		trimmedObs := strings.TrimSpace(obsM)
		if trimmedObs == "" {
			continue
		}
		if canonicalModel != "" && strings.EqualFold(trimmedObs, canonicalModel) {
			return true
		}
		for _, baseM := range baselineModels {
			if strings.EqualFold(trimmedObs, strings.TrimSpace(baseM)) {
				return true
			}
		}
	}
	return false
}

func anyCaseInsensitiveOverlap(a, b []string) bool {
	for _, va := range a {
		ta := strings.TrimSpace(va)
		if ta == "" {
			continue
		}
		for _, vb := range b {
			if strings.EqualFold(ta, strings.TrimSpace(vb)) {
				return true
			}
		}
	}
	return false
}

func matchesExpectedFormat(text, expectedFormat string) bool {
	format := strings.ToLower(strings.TrimSpace(expectedFormat))
	trimmed := strings.TrimSpace(text)
	if format == "" {
		return true
	}
	if trimmed == "" {
		return false
	}

	switch format {
	case "json":
		return json.Valid([]byte(trimmed))
	case "integer":
		_, err := strconv.Atoi(trimmed)
		return err == nil
	case "csv":
		return !strings.Contains(trimmed, "\n") && strings.Contains(trimmed, ",")
	case "numbered_lines":
		lines := strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n")
		if len(lines) != 3 {
			return false
		}
		return strings.HasPrefix(strings.TrimSpace(lines[0]), "1:") &&
			strings.HasPrefix(strings.TrimSpace(lines[1]), "2:") &&
			strings.HasPrefix(strings.TrimSpace(lines[2]), "3:")
	case "code":
		return strings.Contains(trimmed, "def ") || strings.Contains(trimmed, "func ") || strings.Contains(trimmed, "return ")
	default:
		return true
	}
}

func aggregateBehaviorRounds(rounds []*ObservedSignature) *BehaviorSignature {
	type accum struct {
		samples      []string
		seenSamples  map[string]struct{}
		expectedFmt  string
		formatHits   int
		totalSamples int
	}

	byProbe := make(map[string]*accum)
	seenModels := make(map[string]struct{})
	seenFingerprints := make(map[string]struct{})
	var responseModels []string
	var systemFingerprints []string
	hasReasoning := false
	sawReasoningFlag := false

	for _, r := range rounds {
		if r == nil || r.Behavior == nil {
			continue
		}
		if r.Behavior.HasReasoningField != nil {
			sawReasoningFlag = true
			if *r.Behavior.HasReasoningField {
				hasReasoning = true
			}
		}
		for _, rm := range r.Behavior.ResponseModels {
			if _, ok := seenModels[rm]; !ok {
				seenModels[rm] = struct{}{}
				responseModels = append(responseModels, rm)
			}
		}
		for _, fp := range r.Behavior.SystemFingerprints {
			if _, ok := seenFingerprints[fp]; !ok {
				seenFingerprints[fp] = struct{}{}
				systemFingerprints = append(systemFingerprints, fp)
			}
		}
		for pid, p := range r.Behavior.Probes {
			acc, ok := byProbe[pid]
			if !ok {
				acc = &accum{
					seenSamples: make(map[string]struct{}),
					expectedFmt: p.ExpectedFormat,
				}
				byProbe[pid] = acc
			}
			for _, s := range p.Samples {
				acc.totalSamples++
				if matchesExpectedFormat(s, acc.expectedFmt) {
					acc.formatHits++
				}
				if _, exists := acc.seenSamples[s]; !exists {
					acc.seenSamples[s] = struct{}{}
					acc.samples = append(acc.samples, s)
				}
			}
		}
	}

	out := &BehaviorSignature{
		Probes:             make(map[string]BehaviorProbeSignature, len(byProbe)),
		ResponseModels:     responseModels,
		SystemFingerprints: systemFingerprints,
	}
	if sawReasoningFlag {
		flag := hasReasoning
		out.HasReasoningField = &flag
	}
	for pid, acc := range byProbe {
		var matchRate float64
		if acc.totalSamples > 0 {
			matchRate = float64(acc.formatHits) / float64(acc.totalSamples)
		}
		out.Probes[pid] = BehaviorProbeSignature{
			ProbeID:         pid,
			Samples:         acc.samples,
			ExpectedFormat:  acc.expectedFmt,
			FormatMatchRate: matchRate,
		}
	}
	return out
}
