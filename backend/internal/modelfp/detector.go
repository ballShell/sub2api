package modelfp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	peerAmbiguityMargin      = 0.05
	defaultMaxTopCandidates  = 3
	defaultCaptureRounds     = 3
	errorCodeInvalidInput    = "invalid_input"
	errorCodeContextCanceled = "cancelled"
)

// Detector defines a single fingerprint detection engine capable of probing an upstream model
// and scoring the observed signature against a stored baseline.
type Detector interface {
	Kind() DetectorKind
	ProbeModel(ctx context.Context, client ProbeClient, target ProbeTarget, model string, suite ProbeSuite) (*ObservedSignature, error)
	Distance(observed *ObservedSignature, baseline Baseline) float64
}

// ObservedSignature holds the normalized probe output and usage telemetry captured by one detector run.
type ObservedSignature struct {
	Kind                     DetectorKind
	Applicable               bool
	Logprobs                 *LogprobsSignature
	Behavior                 *BehaviorSignature
	ProbeWeights             map[string]float64
	PromptInjectionSuspected bool
	ObservedPromptTokens     int
	Evidence                 []ProbeEvidence
	LatencyMS                int
}

// ProbeError represents a fatal or all-probes-failed upstream execution error from a detector run.
type ProbeError struct {
	Code       string
	Message    string
	HTTPStatus int
	Cause      error
}

// Unwrap returns the underlying error cause if present.
func (e *ProbeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Error implements the error interface without exposing raw target credentials.
func (e *ProbeError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// VerifyModelInput configures a single-model verification run on Orchestrator.
type VerifyModelInput struct {
	Target         ProbeTarget
	ClaimedModel   string
	UpstreamModel  string
	CanonicalModel string
	Suite          ProbeSuite
	Baselines      []Baseline
	FamilyMaps     []FamilyMap
	ConfusionPeers []string
	Now            time.Time
}

// VerifyModelOutput captures the verdict, confidence, candidates, and telemetry for one model verification.
type VerifyModelOutput struct {
	ClaimedModel             string           `json:"claimed_model"`
	UpstreamModel            string           `json:"upstream_model"`
	CanonicalModel           string           `json:"canonical_model"`
	Verdict                  Verdict          `json:"verdict"`
	DetectorUsed             DetectorKind     `json:"detector_used,omitempty"`
	Confidence               float64          `json:"confidence"`
	Distance                 float64          `json:"distance"`
	PromptInjectionSuspected bool             `json:"prompt_injection_suspected"`
	ObservedPromptTokens     int              `json:"observed_prompt_tokens"`
	UsedStaleBaseline        bool             `json:"used_stale_baseline,omitempty"`
	TopCandidates            []CandidateScore `json:"top_candidates"`
	Evidence                 []ProbeEvidence  `json:"evidence"`
	LatencyMS                int              `json:"latency_ms"`
	ErrorCode                string           `json:"error_code,omitempty"`
	ErrorMessage             string           `json:"error_message,omitempty"`
	CheckedAt                time.Time        `json:"checked_at"`
}

// ToRunItem converts a VerifyModelOutput into a RunItem ready for persistence under runID.
func (o VerifyModelOutput) ToRunItem(runID int64) RunItem {
	return RunItem{
		RunID:                    runID,
		ClaimedModel:             o.ClaimedModel,
		UpstreamModel:            o.UpstreamModel,
		CanonicalModel:           o.CanonicalModel,
		Verdict:                  o.Verdict,
		DetectorUsed:             o.DetectorUsed,
		Confidence:               o.Confidence,
		Distance:                 o.Distance,
		PromptInjectionSuspected: o.PromptInjectionSuspected,
		ObservedPromptTokens:     o.ObservedPromptTokens,
		UsedStaleBaseline:        o.UsedStaleBaseline,
		TopCandidates:            o.TopCandidates,
		Evidence:                 o.Evidence,
		LatencyMS:                o.LatencyMS,
		ErrorCode:                o.ErrorCode,
		ErrorMessage:             o.ErrorMessage,
		CheckedAt:                o.CheckedAt,
	}
}

// CapturedModelSamples holds multi-round dual-engine capture output for baseline calibration.
type CapturedModelSamples struct {
	Model                     string
	Protocol                  Protocol
	SuiteID                   int64
	Rounds                    int
	LogprobsSupported         bool
	LogprobsRounds            []*ObservedSignature
	BehaviorRounds            []*ObservedSignature
	AggregatedLogprobs        *LogprobsSignature
	AggregatedBehavior        *BehaviorSignature
	LogprobsSelfDivergenceP95 float64
	BehaviorSelfDivergenceP95 float64
	PromptInjectionSuspected  bool
	ObservedPromptTokens      int
	Evidence                  []ProbeEvidence
}

// Orchestrator coordinates sequential dual-engine verification and multi-round baseline capture.
type Orchestrator struct {
	client   ProbeClient
	logprobs *LogprobsDetector
	behavior *BehaviorProtocolDetector
}

// NewOrchestrator constructs an Orchestrator wired with LogprobsDetector and BehaviorProtocolDetector.
func NewOrchestrator(client ProbeClient) *Orchestrator {
	return &Orchestrator{
		client:   client,
		logprobs: NewLogprobsDetector(),
		behavior: NewBehaviorProtocolDetector(),
	}
}

// VerifyModel executes sequential dual-engine detection (LogprobsDetector -> BehaviorProtocolDetector)
// with hoisted prompt-injection inspection across both phases and 5-verdict adjudication.
func (o *Orchestrator) VerifyModel(ctx context.Context, req VerifyModelInput) VerifyModelOutput {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	claimedModel := strings.TrimSpace(req.ClaimedModel)
	upstreamModel := strings.TrimSpace(req.UpstreamModel)
	if upstreamModel == "" {
		upstreamModel = claimedModel
	}
	canonicalModel, peerSet := resolveCanonicalAndPeers(claimedModel, req.CanonicalModel, req.FamilyMaps, req.ConfusionPeers)

	out := VerifyModelOutput{
		ClaimedModel:   claimedModel,
		UpstreamModel:  upstreamModel,
		CanonicalModel: canonicalModel,
		Verdict:        VerdictUnverified,
		TopCandidates:  []CandidateScore{},
		Evidence:       []ProbeEvidence{},
		CheckedAt:      now,
	}

	if o == nil || o.client == nil {
		return failVerifyOutput(out, errorCodeUpstreamError, "probe client is not configured", req.Target)
	}
	if claimedModel == "" {
		return failVerifyOutput(out, errorCodeInvalidInput, "claimed model is required", req.Target)
	}
	if len(req.Suite.Probes) == 0 {
		return failVerifyOutput(out, errorCodeInvalidInput, "probe suite contains no probes", req.Target)
	}

	lpPool := selectBaselinePool(req.Baselines, req.Target.Protocol, req.Suite, DetectorLogprobs, now)
	bhPool := selectBaselinePool(req.Baselines, req.Target.Protocol, req.Suite, DetectorBehavior, now)

	_, hasClaimedLP := findClaimedBaseline(lpPool, canonicalModel)
	_, hasClaimedBH := findClaimedBaseline(bhPool, canonicalModel)

	var activeDetector Detector
	var activeObs *ObservedSignature
	var activePool []baselineEntry

	// Try Phase 1 (LogprobsDetector) only when protocol supports logprobs, suite has logprobs probes,
	// usable logprobs baselines exist, and we don't have a behavior-only claimed model without logprobs baseline.
	canTryLogprobs := protocolSupportsLogprobs(req.Target.Protocol) &&
		hasProbesOfKind(req.Suite, DetectorLogprobs) &&
		len(lpPool) > 0 &&
		(hasClaimedLP || !hasClaimedBH)

	if canTryLogprobs {
		lpObs, lpErr := o.logprobs.ProbeModel(ctx, o.client, req.Target, upstreamModel, req.Suite)
		mergeObservedTelemetry(&out, lpObs)
		if lpErr != nil {
			var pErr *ProbeError
			if errors.As(lpErr, &pErr) {
				out.DetectorUsed = DetectorLogprobs
				return failVerifyOutput(out, pErr.Code, pErr.Message, req.Target)
			}
			out.DetectorUsed = DetectorLogprobs
			return failVerifyOutput(out, errorCodeUpstreamError, lpErr.Error(), req.Target)
		}
		if lpObs != nil && lpObs.Applicable {
			activeDetector = o.logprobs
			activeObs = lpObs
			activePool = lpPool
		}
	}

	// Sequential fallback to BehaviorProtocolDetector.
	if activeDetector == nil && hasProbesOfKind(req.Suite, DetectorBehavior) {
		bhObs, bhErr := o.behavior.ProbeModel(ctx, o.client, req.Target, upstreamModel, req.Suite)
		mergeObservedTelemetry(&out, bhObs)
		if bhErr != nil {
			var pErr *ProbeError
			if errors.As(bhErr, &pErr) {
				out.DetectorUsed = DetectorBehavior
				return failVerifyOutput(out, pErr.Code, pErr.Message, req.Target)
			}
			out.DetectorUsed = DetectorBehavior
			return failVerifyOutput(out, errorCodeUpstreamError, bhErr.Error(), req.Target)
		}
		if bhObs != nil && bhObs.Applicable {
			activeDetector = o.behavior
			activeObs = bhObs
			activePool = bhPool
		}
	}

	if activeDetector == nil || activeObs == nil {
		out.Verdict = VerdictUnverified
		return out
	}

	out.DetectorUsed = activeDetector.Kind()
	return adjudicateVerification(out, activeDetector, activeObs, activePool, canonicalModel, peerSet)
}

// CaptureModelSignatures runs multi-round probing for baseline calibration.
// On openai_chat and gemini, both logprobs and behavior probe subsets run for rounds rounds;
// on openai_responses and anthropic, only behavior probes run.
func (o *Orchestrator) CaptureModelSignatures(
	ctx context.Context,
	target ProbeTarget,
	model string,
	suite ProbeSuite,
	rounds int,
) (*CapturedModelSamples, error) {
	if o == nil || o.client == nil {
		return nil, errors.New("probe client is not configured")
	}
	trimmedModel := strings.TrimSpace(model)
	if trimmedModel == "" {
		return nil, errors.New("model is required")
	}
	if len(suite.Probes) == 0 {
		return nil, errors.New("probe suite contains no probes")
	}
	if rounds <= 0 {
		rounds = defaultCaptureRounds
	}

	runLogprobs := protocolSupportsLogprobs(target.Protocol) && hasProbesOfKind(suite, DetectorLogprobs)
	runBehavior := hasProbesOfKind(suite, DetectorBehavior)
	if !runLogprobs && !runBehavior {
		return nil, fmt.Errorf("probe suite contains no applicable probes for protocol %s", target.Protocol)
	}

	samples := &CapturedModelSamples{
		Model:    trimmedModel,
		Protocol: target.Protocol,
		SuiteID:  suite.ID,
		Rounds:   rounds,
		Evidence: []ProbeEvidence{},
	}

	mergeCaptureObs := func(obs *ObservedSignature) {
		if obs == nil {
			return
		}
		if obs.PromptInjectionSuspected {
			samples.PromptInjectionSuspected = true
		}
		if obs.ObservedPromptTokens > samples.ObservedPromptTokens {
			samples.ObservedPromptTokens = obs.ObservedPromptTokens
		}
		samples.Evidence = append(samples.Evidence, obs.Evidence...)
	}

	for r := 0; r < rounds; r++ {
		if runLogprobs {
			obs, err := o.logprobs.ProbeModel(ctx, o.client, target, trimmedModel, suite)
			mergeCaptureObs(obs)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, err
				}
				return nil, errors.New(redactSecrets(err.Error(), target))
			}
			if obs != nil && obs.Applicable {
				samples.LogprobsRounds = append(samples.LogprobsRounds, obs)
			}
		}
		if runBehavior {
			obs, err := o.behavior.ProbeModel(ctx, o.client, target, trimmedModel, suite)
			mergeCaptureObs(obs)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, err
				}
				return nil, errors.New(redactSecrets(err.Error(), target))
			}
			if obs != nil && obs.Applicable {
				samples.BehaviorRounds = append(samples.BehaviorRounds, obs)
			}
		}
	}

	if len(samples.LogprobsRounds) > 0 {
		samples.LogprobsSupported = true
		samples.AggregatedLogprobs = aggregateLogprobsRounds(samples.LogprobsRounds)
		samples.LogprobsSelfDivergenceP95 = computeRoundSelfDivP95(o.logprobs, trimmedModel, target.Protocol, suite.ID, samples.LogprobsRounds)
	}
	if len(samples.BehaviorRounds) > 0 {
		samples.AggregatedBehavior = aggregateBehaviorRounds(samples.BehaviorRounds)
		samples.BehaviorSelfDivergenceP95 = computeRoundSelfDivP95(o.behavior, trimmedModel, target.Protocol, suite.ID, samples.BehaviorRounds)
	}

	if samples.AggregatedLogprobs == nil && samples.AggregatedBehavior == nil {
		return nil, errors.New("no usable probe signatures captured")
	}

	return samples, nil
}

type baselineEntry struct {
	baseline  Baseline
	freshness Freshness
}

type distanceReporter interface {
	distanceWithComparable(observed *ObservedSignature, baseline Baseline) (float64, bool)
}

func adjudicateVerification(
	out VerifyModelOutput,
	detector Detector,
	obs *ObservedSignature,
	pool []baselineEntry,
	canonicalModel string,
	peerSet map[string]bool,
) VerifyModelOutput {
	candidates := make([]CandidateScore, 0, len(pool))
	var claimedEntry *baselineEntry
	var claimedDist float64
	var claimedMatchThr, claimedSuspectThr float64

	reporter, hasReporter := detector.(distanceReporter)
	for i := range pool {
		entry := pool[i]
		var d float64
		comparable := true
		if hasReporter {
			d, comparable = reporter.distanceWithComparable(obs, entry.baseline)
		} else {
			d = detector.Distance(obs, entry.baseline)
		}
		if !comparable {
			continue
		}
		d = clampFloat(d, 0, 1)
		matchThr, suspectThr := effectiveThresholds(entry.baseline, detector.Kind())
		isClaimed := strings.EqualFold(entry.baseline.CanonicalModel, canonicalModel)
		cand := CandidateScore{
			CanonicalModel:   entry.baseline.CanonicalModel,
			BaselineID:       entry.baseline.ID,
			Distance:         d,
			Similarity:       clampFloat(1.0-d, 0, 1),
			MatchThreshold:   matchThr,
			SuspectThreshold: suspectThr,
			WithinMatch:      d <= matchThr,
			IsConfusionPeer:  !isClaimed && peerSet[strings.ToLower(entry.baseline.CanonicalModel)],
			Freshness:        entry.freshness,
		}
		candidates = append(candidates, cand)
		if isClaimed {
			copyEntry := entry
			claimedEntry = &copyEntry
			claimedDist = d
			claimedMatchThr = matchThr
			claimedSuspectThr = suspectThr
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Distance != candidates[j].Distance {
			return candidates[i].Distance < candidates[j].Distance
		}
		if candidates[i].Freshness != candidates[j].Freshness {
			return candidates[i].Freshness == FreshnessFresh
		}
		iClaimed := strings.EqualFold(candidates[i].CanonicalModel, canonicalModel)
		jClaimed := strings.EqualFold(candidates[j].CanonicalModel, canonicalModel)
		if iClaimed != jClaimed {
			return iClaimed
		}
		return candidates[i].CanonicalModel < candidates[j].CanonicalModel
	})

	if len(candidates) > defaultMaxTopCandidates {
		out.TopCandidates = append([]CandidateScore(nil), candidates[:defaultMaxTopCandidates]...)
	} else {
		out.TopCandidates = append([]CandidateScore(nil), candidates...)
	}

	if claimedEntry == nil {
		out.Verdict = VerdictUnverified
		out.Confidence = 0
		out.Distance = 0
		return out
	}

	out.Distance = claimedDist
	if claimedEntry.freshness == FreshnessStale {
		out.UsedStaleBaseline = true
	}
	enrichEvidenceWithBaseline(out.Evidence, detector.Kind(), obs, claimedEntry.baseline)

	if claimedDist > claimedSuspectThr {
		out.Verdict = VerdictMismatch
		out.Confidence = computeVerdictConfidence(VerdictMismatch, detector.Kind(), claimedDist, claimedMatchThr, claimedSuspectThr, out.UsedStaleBaseline, out.PromptInjectionSuspected)
		return out
	}

	peerAmbiguous := hasPeerWithinMargin(candidates, canonicalModel, claimedDist, peerAmbiguityMargin)
	lostTopSpot := len(candidates) > 0 &&
		!strings.EqualFold(candidates[0].CanonicalModel, canonicalModel) &&
		candidates[0].Distance < claimedDist

	injectionDowngrade := detector.Kind() == DetectorBehavior && out.PromptInjectionSuspected
	if claimedDist > claimedMatchThr || peerAmbiguous || lostTopSpot || injectionDowngrade {
		out.Verdict = VerdictSuspect
		out.Confidence = computeVerdictConfidence(VerdictSuspect, detector.Kind(), claimedDist, claimedMatchThr, claimedSuspectThr, out.UsedStaleBaseline, out.PromptInjectionSuspected)
		return out
	}

	out.Verdict = VerdictMatch
	out.Confidence = computeVerdictConfidence(VerdictMatch, detector.Kind(), claimedDist, claimedMatchThr, claimedSuspectThr, out.UsedStaleBaseline, out.PromptInjectionSuspected)
	return out
}

func hasPeerWithinMargin(candidates []CandidateScore, canonicalModel string, claimedDist, margin float64) bool {
	for _, c := range candidates {
		if strings.EqualFold(c.CanonicalModel, canonicalModel) {
			continue
		}
		if c.IsConfusionPeer && c.Distance-claimedDist <= margin {
			return true
		}
	}
	return false
}

func computeVerdictConfidence(
	verdict Verdict,
	kind DetectorKind,
	dist, matchThr, suspectThr float64,
	usedStale, injectionSuspected bool,
) float64 {
	var conf float64
	switch verdict {
	case VerdictMatch:
		ratio := 0.0
		if matchThr > 0 {
			ratio = clampFloat(1.0-dist/matchThr, 0, 1)
		}
		if kind == DetectorLogprobs {
			conf = 0.78 + 0.20*ratio
		} else {
			conf = 0.72 + 0.18*ratio
		}
	case VerdictSuspect:
		span := suspectThr - matchThr
		pos := 0.5
		if span > 0 && dist > matchThr {
			pos = clampFloat(1.0-(dist-matchThr)/span, 0, 1)
		}
		conf = 0.35 + 0.25*pos
	case VerdictMismatch:
		denom := math.Max(1.0-suspectThr, 0.1)
		excess := clampFloat((dist-suspectThr)/denom, 0, 1)
		conf = 0.68 + 0.28*excess
	default:
		return 0
	}

	if usedStale {
		conf *= 0.90
	}
	if injectionSuspected && kind == DetectorBehavior {
		conf *= 0.80
	}
	return clampFloat(conf, 0, 0.99)
}

func enrichEvidenceWithBaseline(evidence []ProbeEvidence, kind DetectorKind, obs *ObservedSignature, baseline Baseline) {
	for i := range evidence {
		if evidence[i].DetectorKind != kind || evidence[i].ErrorCode != "" {
			continue
		}
		switch kind {
		case DetectorLogprobs:
			if obs.Logprobs == nil || baseline.Logprobs == nil {
				continue
			}
			obsProbe, okObs := obs.Logprobs.Probes[evidence[i].ProbeID]
			baseProbe, okBase := baseline.Logprobs.Probes[evidence[i].ProbeID]
			if !okObs || !okBase {
				continue
			}
			evidence[i].Distance = JensenShannonDivergence(obsProbe.Distribution, baseProbe.Distribution)
			evidence[i].TopKOverlap = TopKOverlap(obsProbe.Distribution, baseProbe.Distribution, 5)
			evidence[i].BaselineTopTokens = sliceTopTokens(baseProbe.TopTokens, 10)
		case DetectorBehavior:
			if obs.Behavior == nil || baseline.Behavior == nil {
				continue
			}
			obsProbe, okObs := obs.Behavior.Probes[evidence[i].ProbeID]
			baseProbe, okBase := baseline.Behavior.Probes[evidence[i].ProbeID]
			if !okObs || !okBase || len(obsProbe.Samples) == 0 || len(baseProbe.Samples) == 0 {
				continue
			}
			bestSample, bestDist := closestSample(obsProbe.Samples[0], baseProbe.Samples)
			evidence[i].BaselineSampleText = normalizeBehaviorText(bestSample)
			evidence[i].Distance = bestDist
		}
	}
}

func selectBaselinePool(
	baselines []Baseline,
	protocol Protocol,
	suite ProbeSuite,
	kind DetectorKind,
	now time.Time,
) []baselineEntry {
	byModel := make(map[string]baselineEntry)
	order := make([]string, 0)

	for _, b := range baselines {
		if b.Status == StatusArchived {
			continue
		}
		if b.Protocol != protocol || b.DetectorKind != kind {
			continue
		}
		if !baselineMatchesSuite(b, suite) {
			continue
		}
		if !baselineHasPayload(b, kind) {
			continue
		}

		freshness := computeBaselineFreshness(b, now)
		key := strings.ToLower(strings.TrimSpace(b.CanonicalModel))
		if key == "" {
			continue
		}
		existing, exists := byModel[key]
		if !exists {
			order = append(order, key)
			byModel[key] = baselineEntry{baseline: b, freshness: freshness}
			continue
		}
		if existing.freshness == FreshnessStale && freshness == FreshnessFresh {
			byModel[key] = baselineEntry{baseline: b, freshness: freshness}
		}
	}

	out := make([]baselineEntry, 0, len(order))
	for _, key := range order {
		out = append(out, byModel[key])
	}
	return out
}

func baselineMatchesSuite(b Baseline, suite ProbeSuite) bool {
	if suite.ID > 0 && b.SuiteID > 0 {
		return b.SuiteID == suite.ID
	}
	if suite.SuiteKey != "" && b.SuiteKey != "" {
		if b.SuiteKey != suite.SuiteKey {
			return false
		}
		if suite.Version != "" && b.SuiteVersion != "" {
			return b.SuiteVersion == suite.Version
		}
		return true
	}
	return b.SuiteID == suite.ID
}

func baselineHasPayload(b Baseline, kind DetectorKind) bool {
	switch kind {
	case DetectorLogprobs:
		return b.Logprobs != nil && len(b.Logprobs.Probes) > 0
	case DetectorBehavior:
		return b.Behavior != nil && len(b.Behavior.Probes) > 0
	default:
		return false
	}
}

func computeBaselineFreshness(b Baseline, now time.Time) Freshness {
	if b.CollectedAt.IsZero() || b.TTLDays <= 0 {
		return FreshnessFresh
	}
	expiresAt := b.CollectedAt.Add(time.Duration(b.TTLDays) * 24 * time.Hour)
	if now.After(expiresAt) {
		return FreshnessStale
	}
	return FreshnessFresh
}

func findClaimedBaseline(pool []baselineEntry, canonicalModel string) (baselineEntry, bool) {
	for _, entry := range pool {
		if strings.EqualFold(entry.baseline.CanonicalModel, canonicalModel) {
			return entry, true
		}
	}
	return baselineEntry{}, false
}

func effectiveThresholds(b Baseline, kind DetectorKind) (matchThr, suspectThr float64) {
	_, _, suspectCap, defMatch, defSuspect := detectorBounds(kind)
	matchThr = b.MatchThreshold
	suspectThr = b.SuspectThreshold
	if matchThr <= 0 {
		matchThr = defMatch
	}
	if suspectThr <= matchThr {
		if defSuspect > matchThr {
			suspectThr = defSuspect
		} else {
			suspectThr = math.Min(math.Max(2.0*matchThr, matchThr+0.05), suspectCap)
		}
	}
	return matchThr, suspectThr
}

func resolveCanonicalAndPeers(
	claimedModel string,
	explicitCanonical string,
	familyMaps []FamilyMap,
	explicitPeers []string,
) (canonical string, peerSet map[string]bool) {
	aliasIndex := make(map[string]string, len(familyMaps)*3)
	byCanonical := make(map[string]FamilyMap, len(familyMaps))

	for _, fm := range familyMaps {
		canon := strings.TrimSpace(fm.CanonicalModel)
		if canon == "" {
			continue
		}
		lowerCanon := strings.ToLower(canon)
		byCanonical[lowerCanon] = fm
		aliasIndex[lowerCanon] = canon
		for _, alias := range fm.Aliases {
			trimmedAlias := strings.TrimSpace(alias)
			if trimmedAlias != "" {
				aliasIndex[strings.ToLower(trimmedAlias)] = canon
			}
		}
	}

	resolveOne := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if canon, ok := aliasIndex[strings.ToLower(trimmed)]; ok {
			return canon
		}
		noPrefix := strings.TrimPrefix(trimmed, "models/")
		if canon, ok := aliasIndex[strings.ToLower(noPrefix)]; ok {
			return canon
		}
		return trimmed
	}

	if trimmedExplicit := strings.TrimSpace(explicitCanonical); trimmedExplicit != "" {
		canonical = resolveOne(trimmedExplicit)
	} else {
		canonical = resolveOne(claimedModel)
	}

	peerSet = make(map[string]bool)
	if fm, ok := byCanonical[strings.ToLower(canonical)]; ok {
		for _, p := range fm.ConfusionPeers {
			if resolved := resolveOne(p); resolved != "" && !strings.EqualFold(resolved, canonical) {
				peerSet[strings.ToLower(resolved)] = true
			}
		}
	}
	for _, p := range explicitPeers {
		if resolved := resolveOne(p); resolved != "" && !strings.EqualFold(resolved, canonical) {
			peerSet[strings.ToLower(resolved)] = true
		}
	}
	return canonical, peerSet
}

func protocolSupportsLogprobs(protocol Protocol) bool {
	return protocol == ProtocolOpenAIChat || protocol == ProtocolGemini
}

func hasProbesOfKind(suite ProbeSuite, kind DetectorKind) bool {
	for _, p := range suite.Probes {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

func mergeObservedTelemetry(out *VerifyModelOutput, obs *ObservedSignature) {
	if out == nil || obs == nil {
		return
	}
	if obs.PromptInjectionSuspected {
		out.PromptInjectionSuspected = true
	}
	if obs.ObservedPromptTokens > out.ObservedPromptTokens {
		out.ObservedPromptTokens = obs.ObservedPromptTokens
	}
	out.LatencyMS += obs.LatencyMS
	if len(obs.Evidence) > 0 {
		out.Evidence = append(out.Evidence, obs.Evidence...)
	}
}

func failVerifyOutput(out VerifyModelOutput, code, message string, target ProbeTarget) VerifyModelOutput {
	out.Verdict = VerdictError
	out.ErrorCode = code
	out.ErrorMessage = redactSecrets(message, target)
	out.Confidence = 0
	return out
}

type probeSuccessFn func(probe ProbeDefinition, res ProbeCallResult, ev *ProbeEvidence)
type probeSoftInapplicableFn func(res ProbeCallResult) bool

// executeDetectorProbes runs all probes of kind in suite sequentially, performing hoisted
// prompt-injection checks, secret redaction, and fatal vs. transient vs. inapplicable error handling.
func executeDetectorProbes(
	ctx context.Context,
	client ProbeClient,
	target ProbeTarget,
	model string,
	suite ProbeSuite,
	kind DetectorKind,
	requestLogprobs bool,
	onSuccess probeSuccessFn,
	isSoftInapplicable probeSoftInapplicableFn,
) (*ObservedSignature, int, error) {
	obs := &ObservedSignature{
		Kind:         kind,
		ProbeWeights: make(map[string]float64),
		Evidence:     []ProbeEvidence{},
	}

	var lastTransientErr *ProbeError
	successCount := 0

	for _, probe := range suite.Probes {
		if probe.Kind != kind {
			continue
		}
		if ctx != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return obs, successCount, classifyContextError(ctxErr)
			}
		}

		res := client.ExecuteProbe(ctx, target, model, probe, requestLogprobs)
		ev, injected, maxTokensSeen := buildBaseProbeEvidence(probe, kind, res, target)
		if injected {
			obs.PromptInjectionSuspected = true
		}
		if maxTokensSeen > obs.ObservedPromptTokens {
			obs.ObservedPromptTokens = maxTokensSeen
		}
		obs.LatencyMS += res.LatencyMS
		obs.ProbeWeights[probe.ID] = effectiveProbeWeight(probe.Weight)

		if res.ErrorCode != "" {
			obs.Evidence = append(obs.Evidence, ev)
			pErr := &ProbeError{
				Code:       res.ErrorCode,
				Message:    ev.ErrorMessage,
				HTTPStatus: res.HTTPStatus,
			}
			if isFatalProbeError(res.ErrorCode) {
				return obs, successCount, pErr
			}
			if isSoftInapplicable != nil && isSoftInapplicable(res) {
				continue
			}
			lastTransientErr = pErr
			continue
		}

		if onSuccess != nil {
			onSuccess(probe, res, &ev)
		}
		obs.Evidence = append(obs.Evidence, ev)
		successCount++
	}

	if successCount == 0 && lastTransientErr != nil {
		return obs, 0, lastTransientErr
	}
	return obs, successCount, nil
}

func buildBaseProbeEvidence(probe ProbeDefinition, kind DetectorKind, res ProbeCallResult, target ProbeTarget) (ProbeEvidence, bool, int) {
	maxAllowed := probe.ExpectedMaxPromptTokens
	if maxAllowed <= 0 {
		maxAllowed = DefaultExpectedMaxPromptTokens
	}
	maxTokensSeen := maxInt(res.PromptTokens, res.CachedPromptTokens)
	injected := res.PromptTokens > maxAllowed || res.CachedPromptTokens > maxAllowed

	ev := ProbeEvidence{
		ProbeID:                  probe.ID,
		DetectorKind:             kind,
		Weight:                   effectiveProbeWeight(probe.Weight),
		ResponseModel:            redactExactSecrets(res.ResponseModel, target),
		SystemFingerprint:        redactExactSecrets(res.SystemFingerprint, target),
		HasReasoningField:        res.HasReasoningField,
		PromptTokens:             res.PromptTokens,
		CachedPromptTokens:       res.CachedPromptTokens,
		OutputTokens:             res.OutputTokens,
		PromptInjectionSuspected: injected,
		LogprobsSupported:        res.LogprobsSupported,
		LatencyMS:                res.LatencyMS,
		HTTPStatus:               res.HTTPStatus,
		ErrorCode:                res.ErrorCode,
		ErrorMessage:             redactSecretsWithStatus(res.ErrorMessage, res.HTTPStatus, target),
	}
	return ev, injected, maxTokensSeen
}

func effectiveProbeWeight(w float64) float64 {
	if math.IsNaN(w) || math.IsInf(w, 0) || w <= 0 {
		return 1.0
	}
	return w
}

func probeWeight(obs *ObservedSignature, probeID string) float64 {
	if obs != nil && obs.ProbeWeights != nil {
		if w, ok := obs.ProbeWeights[probeID]; ok && w > 0 {
			return w
		}
	}
	return 1.0
}

func isFatalProbeError(code string) bool {
	switch code {
	case errorCodeModelNotFound, errorCodeAuthError, errorCodeSSRFBlocked:
		return true
	default:
		return false
	}
}

func isLogprobsUnsupportedError(res ProbeCallResult) bool {
	if res.LogprobsSupported || len(res.Logprobs) > 0 {
		return false
	}
	if isFatalProbeError(res.ErrorCode) {
		return false
	}
	switch res.ErrorCode {
	case errorCodeRateLimited, errorCodeTimeout, errorCodeContextCanceled:
		return false
	}
	if strings.EqualFold(strings.TrimSpace(res.ErrorCode), "logprobs_unsupported") {
		return true
	}
	switch res.HTTPStatus {
	case 0, http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusNotImplemented:
	default:
		return false
	}

	lowerMsg := strings.ToLower(res.ErrorMessage)
	for _, token := range []string{
		"logprob",
		"top_logprobs",
		"responselogprobs",
		"response_logprobs",
	} {
		if strings.Contains(lowerMsg, token) {
			return true
		}
	}

	if hasSeedParameterToken(lowerMsg) {
		for _, hint := range []string{
			"unsupported",
			"not support",
			"unknown parameter",
			"unrecognized",
			"invalid parameter",
			"not allowed",
			"disallowed",
			"unexpected",
		} {
			if strings.Contains(lowerMsg, hint) {
				return true
			}
		}
	}
	return false
}

func hasSeedParameterToken(lowerMsg string) bool {
	idx := 0
	for {
		pos := strings.Index(lowerMsg[idx:], "seed")
		if pos < 0 {
			return false
		}
		start := idx + pos
		end := start + len("seed")
		prevOK := start == 0 || !isASCIIAlphaNum(lowerMsg[start-1])
		nextOK := end == len(lowerMsg) || !isASCIIAlphaNum(lowerMsg[end])
		if prevOK && nextOK {
			return true
		}
		idx = end
	}
}

func isASCIIAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func classifyContextError(err error) *ProbeError {
	if errors.Is(err, context.DeadlineExceeded) {
		return &ProbeError{Code: errorCodeTimeout, Message: err.Error(), Cause: err}
	}
	return &ProbeError{Code: errorCodeContextCanceled, Message: err.Error(), Cause: err}
}

func redactExactSecrets(s string, target ProbeTarget) string {
	if s == "" {
		return ""
	}
	secrets := collectSecrets(target)
	out := s
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
	return out
}

func computeRoundSelfDivP95(detector Detector, model string, protocol Protocol, suiteID int64, rounds []*ObservedSignature) float64 {
	if len(rounds) < 2 {
		return 0
	}
	distances := make([]float64, 0, len(rounds)*(len(rounds)-1)/2)
	for i := 0; i < len(rounds); i++ {
		for j := i + 1; j < len(rounds); j++ {
			b := Baseline{
				CanonicalModel: model,
				Protocol:       protocol,
				SuiteID:        suiteID,
				DetectorKind:   detector.Kind(),
				Logprobs:       rounds[j].Logprobs,
				Behavior:       rounds[j].Behavior,
			}
			distances = append(distances, detector.Distance(rounds[i], b))
		}
	}
	return ComputeSelfDivergenceP95(distances)
}

func buildPrivatePromptScrubber(suite ProbeSuite) func(string) string {
	if suite.Visibility != VisibilityPrivate || len(suite.Probes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(suite.Probes)*2)
	variants := make([]string, 0, len(suite.Probes)*2)
	addVariant := func(v string) {
		if v == "" {
			return
		}
		lower := strings.ToLower(v)
		if _, ok := seen[lower]; ok {
			return
		}
		seen[lower] = struct{}{}
		variants = append(variants, v)
	}
	for _, p := range suite.Probes {
		trimmed := strings.TrimSpace(p.Prompt)
		addVariant(trimmed)
		addVariant(strings.ReplaceAll(trimmed, "\r\n", "\n"))
		addVariant(normalizeBehaviorText(p.Prompt))
	}
	if len(variants) == 0 {
		return nil
	}
	sort.Slice(variants, func(i, j int) bool {
		return len(variants[i]) > len(variants[j])
	})
	patterns := make([]*regexp.Regexp, 0, len(variants))
	for _, v := range variants {
		patterns = append(patterns, regexp.MustCompile("(?i)"+regexp.QuoteMeta(v)))
	}
	return func(s string) string {
		if s == "" {
			return ""
		}
		out := s
		for _, re := range patterns {
			out = re.ReplaceAllString(out, redactedSecretPlaceholder)
		}
		return out
	}
}
