package modelfp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	logprobsEpsMin     = 0.03
	logprobsEpsMax     = 0.25
	logprobsSuspectCap = 0.45
	logprobsDefMatch   = 0.08
	logprobsDefSuspect = 0.18

	behaviorEpsMin         = 0.12
	behaviorEpsMax         = 0.38
	behaviorSuspectCap     = 0.60
	behaviorDefMatch       = 0.18
	behaviorDefSuspect     = 0.32
	maxBehaviorSampleRunes = 2048
)

// NormalizeTokenDistribution normalizes top-k token probabilities into a probability map
// summing to 1.0, assigning residual probability mass below 1.0 to DefaultOtherToken ("<OTHER>").
// Byte and whitespace differences in Token keys are intentionally preserved.
func NormalizeTokenDistribution(probs []TokenProb) map[string]float64 {
	dist := make(map[string]float64, len(probs)+1)
	var total float64
	for _, tp := range probs {
		if math.IsNaN(tp.Prob) || math.IsInf(tp.Prob, 0) || tp.Prob <= 0 {
			continue
		}
		dist[tp.Token] += tp.Prob
		total += tp.Prob
	}

	if total <= 0 {
		return map[string]float64{DefaultOtherToken: 1.0}
	}

	if total < 1.0-1e-12 {
		dist[DefaultOtherToken] += 1.0 - total
		return dist
	}

	if math.Abs(total-1.0) > 1e-12 {
		for k, v := range dist {
			dist[k] = v / total
		}
	}
	return dist
}

// JensenShannonDivergence computes the base-2 Jensen-Shannon divergence between p and q in [0, 1].
func JensenShannonDivergence(p, q map[string]float64) float64 {
	pn, pSum := normalizeProbMap(p)
	qn, qSum := normalizeProbMap(q)

	if pSum == 0 && qSum == 0 {
		return 0
	}
	if pSum == 0 || qSum == 0 {
		return 1.0
	}

	keys := make([]string, 0, len(pn)+len(qn))
	seen := make(map[string]struct{}, len(pn)+len(qn))
	for k := range pn {
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range qn {
		if _, ok := seen[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var jsd float64
	for _, k := range keys {
		pi := pn[k]
		qi := qn[k]
		mi := 0.5 * (pi + qi)
		if mi <= 0 {
			continue
		}
		var t1, t2 float64
		if pi > 0 {
			t1 = 0.5 * pi * math.Log2(pi/mi)
		}
		if qi > 0 {
			t2 = 0.5 * qi * math.Log2(qi/mi)
		}
		// Add smaller term first regardless of argument order to keep exact float symmetry.
		if t1 < t2 {
			jsd += t1 + t2
		} else {
			jsd += t2 + t1
		}
	}

	return clampFloat(jsd, 0, 1)
}

func normalizeProbMap(m map[string]float64) (map[string]float64, float64) {
	if len(m) == 0 {
		return nil, 0
	}
	out := make(map[string]float64, len(m))
	var sum float64
	for k, v := range m {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			continue
		}
		out[k] = v
		sum += v
	}
	if sum <= 0 {
		return nil, 0
	}
	if math.Abs(sum-1.0) > 1e-12 {
		for k, v := range out {
			out[k] = v / sum
		}
	}
	return out, sum
}

// TopKOverlap computes the overlap ratio in [0, 1] of the top k real tokens between p and q.
func TopKOverlap(p, q map[string]float64, k int) float64 {
	if k <= 0 {
		return 0
	}
	topP := topTokens(p, k)
	topQ := topTokens(q, k)
	if len(topP) == 0 || len(topQ) == 0 {
		return 0
	}

	qSet := make(map[string]struct{}, len(topQ))
	for _, tok := range topQ {
		qSet[tok] = struct{}{}
	}
	shared := 0
	for _, tok := range topP {
		if _, ok := qSet[tok]; ok {
			shared++
		}
	}

	denom := len(topP)
	if len(topQ) > denom {
		denom = len(topQ)
	}
	return float64(shared) / float64(denom)
}

func topTokens(dist map[string]float64, k int) []string {
	type tokenEntry struct {
		token string
		prob  float64
	}
	entries := make([]tokenEntry, 0, len(dist))
	for tok, prob := range dist {
		if tok == DefaultOtherToken || math.IsNaN(prob) || math.IsInf(prob, 0) || prob <= 0 {
			continue
		}
		entries = append(entries, tokenEntry{token: tok, prob: prob})
	}
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].prob != entries[j].prob {
			return entries[i].prob > entries[j].prob
		}
		return entries[i].token < entries[j].token
	})
	if len(entries) > k {
		entries = entries[:k]
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.token
	}
	return out
}

// BehaviorResponseDistance computes a weighted distance in [0, 1] combining
// normalized rune Levenshtein distance and character-bigram Jaccard distance.
func BehaviorResponseDistance(a, b string) float64 {
	na := normalizeBehaviorText(a)
	nb := normalizeBehaviorText(b)
	if na == nb {
		return 0
	}
	if na == "" || nb == "" {
		return 1
	}

	ra := []rune(na)
	rb := []rune(nb)
	maxRunes := len(ra)
	if len(rb) > maxRunes {
		maxRunes = len(rb)
	}
	normLev := float64(runeLevenshtein(ra, rb)) / float64(maxRunes)
	bigramDist := bigramJaccardDistance(ra, rb)

	return clampFloat(0.5*normLev+0.5*bigramDist, 0, 1)
}

func normalizeBehaviorText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSpace(s)
	return strings.TrimSpace(truncateRunes(s, maxBehaviorSampleRunes))
}

func runeLevenshtein(a, b []rune) int {
	if len(a) < len(b) {
		a, b = b, a
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			best := del
			if ins < best {
				best = ins
			}
			if sub < best {
				best = sub
			}
			curr[j] = best
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func bigramJaccardDistance(a, b []rune) float64 {
	if len(a) < 2 || len(b) < 2 {
		if string(a) == string(b) {
			return 0
		}
		return 1
	}
	type bigram struct {
		r1, r2 rune
	}
	setA := make(map[bigram]struct{}, len(a)-1)
	for i := 0; i < len(a)-1; i++ {
		setA[bigram{a[i], a[i+1]}] = struct{}{}
	}
	setB := make(map[bigram]struct{}, len(b)-1)
	for i := 0; i < len(b)-1; i++ {
		setB[bigram{b[i], b[i+1]}] = struct{}{}
	}

	intersection := 0
	for bg := range setA {
		if _, ok := setB[bg]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return 1.0 - float64(intersection)/float64(union)
}

// ComputeSelfDivergenceP95 computes the conservative 95th percentile (nearest-rank)
// of intra-model pairwise distances.
func ComputeSelfDivergenceP95(distances []float64) float64 {
	if len(distances) == 0 {
		return 0
	}
	clean := make([]float64, 0, len(distances))
	for _, d := range distances {
		if math.IsNaN(d) || math.IsInf(d, 0) {
			continue
		}
		if d < 0 {
			d = 0
		}
		clean = append(clean, d)
	}
	if len(clean) == 0 {
		return 0
	}
	sort.Float64s(clean)
	idx := int(math.Ceil(0.95*float64(len(clean)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(clean) {
		idx = len(clean) - 1
	}
	return clean[idx]
}

// DeriveThresholds calculates match and suspect decision thresholds using spec Section 7.3
// calibration bounds for the specified detector engine.
func DeriveThresholds(kind DetectorKind, selfDivP95 float64, nearestDist *float64) (matchThreshold, suspectThreshold float64) {
	if math.IsNaN(selfDivP95) || math.IsInf(selfDivP95, 0) || selfDivP95 < 0 {
		selfDivP95 = 0
	}

	epsMin, epsMax, suspectCap, defMatch, defSuspect := detectorBounds(kind)

	if nearestDist == nil || math.IsNaN(*nearestDist) || math.IsInf(*nearestDist, 0) || *nearestDist < 0 {
		return defMatch, defSuspect
	}

	near := *nearestDist
	upper := math.Min(0.45*near, epsMax)
	if upper < epsMin {
		upper = epsMin
	}
	raw := math.Max(2.5*selfDivP95, epsMin)
	match := clampFloat(raw, epsMin, upper)
	suspect := math.Min(math.Max(2.0*match, 0.65*near), suspectCap)
	return match, suspect
}

func detectorBounds(kind DetectorKind) (epsMin, epsMax, suspectCap, defMatch, defSuspect float64) {
	switch kind {
	case DetectorLogprobs:
		return logprobsEpsMin, logprobsEpsMax, logprobsSuspectCap, logprobsDefMatch, logprobsDefSuspect
	default:
		return behaviorEpsMin, behaviorEpsMax, behaviorSuspectCap, behaviorDefMatch, behaviorDefSuspect
	}
}

// BuildConfusionMatrix computes a symmetric pairwise distance matrix and flags close/overlapping baseline pairs.
func BuildConfusionMatrix(baselines []Baseline, distFn func(a, b Baseline) float64) ConfusionMatrixResult {
	n := len(baselines)
	if n == 0 {
		return ConfusionMatrixResult{
			Models:     []string{},
			Matrix:     [][]float64{},
			ClosePairs: []ConfusionPair{},
		}
	}

	sorted := append([]Baseline(nil), baselines...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CanonicalModel != sorted[j].CanonicalModel {
			return sorted[i].CanonicalModel < sorted[j].CanonicalModel
		}
		return sorted[i].ID < sorted[j].ID
	})

	models := make([]string, n)
	matrix := make([][]float64, n)
	for i := range sorted {
		models[i] = sorted[i].CanonicalModel
		matrix[i] = make([]float64, n)
	}

	res := ConfusionMatrixResult{
		Protocol:     sorted[0].Protocol,
		SuiteID:      sorted[0].SuiteID,
		DetectorKind: sorted[0].DetectorKind,
		Models:       models,
		Matrix:       matrix,
		ClosePairs:   []ConfusionPair{},
	}

	if n < 2 {
		return res
	}

	minOffDiag := math.Inf(1)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			var d float64
			if distFn != nil {
				d = distFn(sorted[i], sorted[j])
			}
			if math.IsNaN(d) || math.IsInf(d, 0) || d < 0 {
				d = 0
			}
			matrix[i][j] = d
			matrix[j][i] = d
			if d < minOffDiag {
				minOffDiag = d
			}

			maxSelf := math.Max(sorted[i].SelfDivergenceP95, sorted[j].SelfDivergenceP95)
			overlapWarning := maxSelf > 0 && d < 1.5*maxSelf
			suspectCeiling := math.Max(sorted[i].SuspectThreshold, sorted[j].SuspectThreshold)
			if overlapWarning || (suspectCeiling > 0 && d <= suspectCeiling) {
				res.ClosePairs = append(res.ClosePairs, ConfusionPair{
					ModelA:         sorted[i].CanonicalModel,
					ModelB:         sorted[j].CanonicalModel,
					Distance:       d,
					OverlapWarning: overlapWarning,
				})
			}
		}
	}

	if !math.IsInf(minOffDiag, 1) {
		res.MinOffDiagonal = minOffDiag
	}
	sort.Slice(res.ClosePairs, func(i, j int) bool {
		if res.ClosePairs[i].Distance != res.ClosePairs[j].Distance {
			return res.ClosePairs[i].Distance < res.ClosePairs[j].Distance
		}
		if res.ClosePairs[i].ModelA != res.ClosePairs[j].ModelA {
			return res.ClosePairs[i].ModelA < res.ClosePairs[j].ModelA
		}
		return res.ClosePairs[i].ModelB < res.ClosePairs[j].ModelB
	})

	return res
}

// ComputeContentHash returns the SHA-256 hex digest of v serialized as canonical JSON.
func ComputeContentHash(v any) (string, error) {
	var rawBuf bytes.Buffer
	enc := json.NewEncoder(&rawBuf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("marshal for content hash: %w", err)
	}

	dec := json.NewDecoder(&rawBuf)
	dec.UseNumber()
	var canonical any
	if err := dec.Decode(&canonical); err != nil {
		return "", fmt.Errorf("decode canonical form for content hash: %w", err)
	}

	var outBuf bytes.Buffer
	outEnc := json.NewEncoder(&outBuf)
	outEnc.SetEscapeHTML(false)
	if err := outEnc.Encode(canonical); err != nil {
		return "", fmt.Errorf("encode canonical form for content hash: %w", err)
	}

	sum := sha256.Sum256(bytes.TrimSpace(outBuf.Bytes()))
	return hex.EncodeToString(sum[:]), nil
}

func clampFloat(v, minVal, maxVal float64) float64 {
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}
