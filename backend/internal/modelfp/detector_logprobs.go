package modelfp

import (
	"context"
	"math"
	"sort"
)

// LogprobsDetector verifies models via first-token probability distributions (JSD + Top-K overlap).
type LogprobsDetector struct{}

// NewLogprobsDetector constructs a LogprobsDetector instance.
func NewLogprobsDetector() *LogprobsDetector {
	return &LogprobsDetector{}
}

// Kind returns DetectorLogprobs.
func (d *LogprobsDetector) Kind() DetectorKind {
	return DetectorLogprobs
}

// ProbeModel executes all logprobs probes in suite with requestLogprobs=true and builds a normalized LogprobsSignature.
// Marks Applicable=false when zero probes return usable logprobs.
func (d *LogprobsDetector) ProbeModel(
	ctx context.Context,
	client ProbeClient,
	target ProbeTarget,
	model string,
	suite ProbeSuite,
) (*ObservedSignature, error) {
	sig := &LogprobsSignature{
		Probes: make(map[string]LogprobsProbeSignature),
	}
	supportedCount := 0

	obs, _, err := executeDetectorProbes(
		ctx,
		client,
		target,
		model,
		suite,
		DetectorLogprobs,
		true,
		func(probe ProbeDefinition, res ProbeCallResult, ev *ProbeEvidence) {
			if !res.LogprobsSupported || len(res.Logprobs) == 0 {
				return
			}
			normalizedProbs := normalizeTokenProbInputs(res.Logprobs)
			dist := NormalizeTokenDistribution(normalizedProbs)
			if !hasRealTokenMass(dist) {
				return
			}
			top := sortedTopTokensFromDist(dist, 20)
			sig.Probes[probe.ID] = LogprobsProbeSignature{
				ProbeID:      probe.ID,
				Distribution: dist,
				TopTokens:    top,
				SampleCount:  1,
			}
			ev.ObservedTopTokens = sliceTopTokens(top, 10)
			supportedCount++
		},
	)
	if obs != nil {
		obs.Logprobs = sig
		obs.Applicable = supportedCount > 0
	}
	return obs, err
}

// Distance computes the weighted average base-2 Jensen-Shannon divergence between observed and baseline.
func (d *LogprobsDetector) Distance(observed *ObservedSignature, baseline Baseline) float64 {
	if observed == nil || !observed.Applicable || observed.Logprobs == nil || baseline.Logprobs == nil {
		return 1.0
	}

	probeIDs := make([]string, 0, len(observed.Logprobs.Probes))
	for pid := range observed.Logprobs.Probes {
		probeIDs = append(probeIDs, pid)
	}
	sort.Strings(probeIDs)

	var weightedSum float64
	var totalWeight float64
	for _, pid := range probeIDs {
		obsProbe := observed.Logprobs.Probes[pid]
		baseProbe, ok := baseline.Logprobs.Probes[pid]
		if !ok || len(obsProbe.Distribution) == 0 || len(baseProbe.Distribution) == 0 {
			continue
		}
		jsd := JensenShannonDivergence(obsProbe.Distribution, baseProbe.Distribution)
		w := probeWeight(observed, pid)
		weightedSum += w * jsd
		totalWeight += w
	}

	if totalWeight <= 0 {
		return 1.0
	}
	return clampFloat(weightedSum/totalWeight, 0, 1)
}

func aggregateLogprobsRounds(rounds []*ObservedSignature) *LogprobsSignature {
	type accum struct {
		sums  map[string]float64
		count int
	}
	byProbe := make(map[string]*accum)
	for _, r := range rounds {
		if r == nil || r.Logprobs == nil {
			continue
		}
		for pid, p := range r.Logprobs.Probes {
			if len(p.Distribution) == 0 {
				continue
			}
			acc, ok := byProbe[pid]
			if !ok {
				acc = &accum{sums: make(map[string]float64)}
				byProbe[pid] = acc
			}
			for tok, prob := range p.Distribution {
				if math.IsNaN(prob) || math.IsInf(prob, 0) || prob <= 0 {
					continue
				}
				acc.sums[tok] += prob
			}
			acc.count++
		}
	}

	out := &LogprobsSignature{
		Probes: make(map[string]LogprobsProbeSignature, len(byProbe)),
	}
	for pid, acc := range byProbe {
		if acc.count == 0 {
			continue
		}
		avg := make(map[string]float64, len(acc.sums))
		for tok, total := range acc.sums {
			avg[tok] = total / float64(acc.count)
		}
		norm, _ := normalizeProbMap(avg)
		if len(norm) == 0 {
			continue
		}
		out.Probes[pid] = LogprobsProbeSignature{
			ProbeID:      pid,
			Distribution: norm,
			TopTokens:    sortedTopTokensFromDist(norm, 20),
			SampleCount:  acc.count,
		}
	}
	return out
}

func normalizeTokenProbInputs(probs []TokenProb) []TokenProb {
	out := make([]TokenProb, len(probs))
	for i, tp := range probs {
		if tp.Prob == 0 && tp.Logprob < 0 {
			tp.Prob = logprobToProb(tp.Logprob)
		}
		out[i] = tp
	}
	return out
}

func hasRealTokenMass(dist map[string]float64) bool {
	for tok, prob := range dist {
		if tok != DefaultOtherToken && prob > 0 {
			return true
		}
	}
	return false
}

func sortedTopTokensFromDist(dist map[string]float64, limit int) []TokenProb {
	entries := make([]TokenProb, 0, len(dist))
	for tok, prob := range dist {
		if tok == DefaultOtherToken || math.IsNaN(prob) || math.IsInf(prob, 0) || prob <= 0 {
			continue
		}
		entries = append(entries, TokenProb{Token: tok, Prob: prob})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Prob != entries[j].Prob {
			return entries[i].Prob > entries[j].Prob
		}
		return entries[i].Token < entries[j].Token
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}

func sliceTopTokens(tokens []TokenProb, limit int) []TokenProb {
	if len(tokens) == 0 {
		return nil
	}
	n := len(tokens)
	if limit > 0 && n > limit {
		n = limit
	}
	out := make([]TokenProb, n)
	copy(out, tokens[:n])
	return out
}
