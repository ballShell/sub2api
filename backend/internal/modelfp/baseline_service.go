package modelfp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	minCaptureSampleRounds = 3
	maxCaptureSampleRounds = 5
	maxCaptureModels       = 20
	maxBaselineLabelChars  = 255
	captureCleanupTimeout  = 5 * time.Second
)

// ImportConflictMode specifies how ImportBundle handles existing entities with the same key.
type ImportConflictMode string

const (
	ImportConflictSkip      ImportConflictMode = "skip"
	ImportConflictOverwrite ImportConflictMode = "overwrite"
)

// CaptureRequest configures an async multi-round baseline capture job.
// Ad-hoc credentials are resolved immediately and never persisted in modelfp_capture_jobs.
type CaptureRequest struct {
	TargetSource     TargetSource      `json:"target_source"`
	AccountID        *int64            `json:"account_id,omitempty"`
	AdHoc            *AdHocTargetInput `json:"adhoc,omitempty"`
	Protocol         Protocol          `json:"protocol,omitempty"`
	BaseURL          string            `json:"base_url,omitempty"`
	APIKey           string            `json:"api_key,omitempty"`
	AuthMode         string            `json:"auth_mode,omitempty"`
	ProxyID          *int64            `json:"proxy_id,omitempty"`
	ExtraHeaders     map[string]string `json:"extra_headers,omitempty"`
	SuiteID          int64             `json:"suite_id,omitempty"`
	Models           []string          `json:"models"`
	SourceType       SourceType        `json:"source_type,omitempty"`
	SourceLabel      string            `json:"source_label,omitempty"`
	UpstreamSnapshot string            `json:"upstream_snapshot,omitempty"`
	SampleRounds     int               `json:"sample_rounds,omitempty"`
	TTLDays          int               `json:"ttl_days,omitempty"`
	Notes            string            `json:"notes,omitempty"`
}

// UpdateBaselineRequest specifies mutable baseline metadata and calibration thresholds.
type UpdateBaselineRequest struct {
	MatchThreshold   *float64 `json:"match_threshold,omitempty"`
	SuspectThreshold *float64 `json:"suspect_threshold,omitempty"`
	TTLDays          *int     `json:"ttl_days,omitempty"`
	Status           *Status  `json:"status,omitempty"`
	Notes            *string  `json:"notes,omitempty"`
}

// ConfusionMatrixRequest selects the (protocol, suite, detector_kind) slice for pairwise distance analysis.
type ConfusionMatrixRequest struct {
	Protocol     Protocol     `json:"protocol"`
	SuiteID      int64        `json:"suite_id,omitempty"`
	DetectorKind DetectorKind `json:"detector_kind"`
}

// ImportBundleRequest imports a checksum-verified fingerprint Bundle into the L2 store.
type ImportBundleRequest struct {
	Bundle       Bundle             `json:"bundle"`
	ConflictMode ImportConflictMode `json:"conflict_mode,omitempty"`
}

// ImportBundleResult summarizes imported and skipped counts across entity categories.
type ImportBundleResult struct {
	SuitesImported     int `json:"suites_imported"`
	SuitesSkipped      int `json:"suites_skipped"`
	FamilyMapsImported int `json:"family_maps_imported"`
	FamilyMapsSkipped  int `json:"family_maps_skipped"`
	BaselinesImported  int `json:"baselines_imported"`
	BaselinesSkipped   int `json:"baselines_skipped"`
}

// CreateSuiteRequest creates a new immutable probe suite version.
type CreateSuiteRequest struct {
	SuiteKey   string            `json:"suite_key"`
	Version    string            `json:"version"`
	Name       string            `json:"name"`
	Visibility Visibility        `json:"visibility,omitempty"`
	IsDefault  bool              `json:"is_default,omitempty"`
	Probes     []ProbeDefinition `json:"probes"`
}

// UpdateSuiteStatusRequest updates suite lifecycle status and default selection.
type UpdateSuiteStatusRequest struct {
	Status    Status `json:"status"`
	IsDefault *bool  `json:"is_default,omitempty"`
}

// BaselineService manages seed bootstrap, dual-engine baseline capture, calibration,
// confusion matrices, probe suites, family maps, and SHA-256 bundle export/import.
type BaselineService struct {
	store        Store
	resolver     *TargetResolver
	orchestrator *Orchestrator

	mu      sync.Mutex
	stopped bool
	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	now     func() time.Time
}

// NewBaselineService constructs a BaselineService backed by Store, TargetResolver, and Orchestrator.
func NewBaselineService(store Store, resolver *TargetResolver, orchestrator *Orchestrator) *BaselineService {
	ctx, cancel := context.WithCancel(context.Background())
	return &BaselineService{
		store:        store,
		resolver:     resolver,
		orchestrator: orchestrator,
		baseCtx:      ctx,
		cancel:       cancel,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// Stop cancels all active async capture jobs and waits for background goroutines to finish.
func (s *BaselineService) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		if s.cancel != nil {
			s.cancel()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *BaselineService) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *BaselineService) ensureStore() error {
	if s == nil || s.store == nil {
		return errors.New("baseline service store is not configured")
	}
	return nil
}

// EnsureSeeds idempotently upserts built-in default seed probe suites and family maps.
func (s *BaselineService) EnsureSeeds(ctx context.Context) error {
	if err := s.ensureStore(); err != nil {
		return err
	}
	suites, families, _, err := LoadSeedData()
	if err != nil {
		return err
	}
	for _, suite := range suites {
		if _, err := s.store.UpsertSeedSuite(ctx, suite); err != nil {
			return fmt.Errorf("upsert seed suite %s/%s: %w", suite.SuiteKey, suite.Version, err)
		}
	}
	for _, fm := range families {
		if _, err := s.store.UpsertFamilyMap(ctx, fm); err != nil {
			return fmt.Errorf("upsert seed family map %s: %w", fm.CanonicalModel, err)
		}
	}
	return nil
}

// ListBaselines retrieves baselines matching filter and enriches each with freshness metadata.
func (s *BaselineService) ListBaselines(ctx context.Context, filter BaselineFilter) ([]BaselineView, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	rows, err := s.store.ListBaselines(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := s.currentTime()
	views := make([]BaselineView, 0, len(rows))
	for _, b := range rows {
		views = append(views, toBaselineView(b, now))
	}
	return views, nil
}

// UpdateBaseline updates mutable thresholds, TTL, status, or notes on an existing baseline.
func (s *BaselineService) UpdateBaseline(ctx context.Context, id int64, req UpdateBaselineRequest) (*BaselineView, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_ID", "baseline id must be positive")
	}

	existing, err := s.store.GetBaseline(ctx, id)
	if err != nil {
		return nil, err
	}

	matchThr := existing.MatchThreshold
	if req.MatchThreshold != nil {
		if err := validateUnitThreshold("match_threshold", *req.MatchThreshold); err != nil {
			return nil, err
		}
		matchThr = *req.MatchThreshold
	}
	suspectThr := existing.SuspectThreshold
	if req.SuspectThreshold != nil {
		if err := validateUnitThreshold("suspect_threshold", *req.SuspectThreshold); err != nil {
			return nil, err
		}
		suspectThr = *req.SuspectThreshold
	}
	if suspectThr > 0 && matchThr > suspectThr {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_THRESHOLDS", "match_threshold cannot exceed suspect_threshold")
	}

	if req.TTLDays != nil && *req.TTLDays <= 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_TTL", "ttl_days must be positive")
	}
	if req.Status != nil {
		if *req.Status != StatusActive && *req.Status != StatusArchived {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_STATUS", fmt.Sprintf("unsupported status %q", *req.Status))
		}
	}

	var notesPtr *string
	if req.Notes != nil {
		trimmed := strings.TrimSpace(*req.Notes)
		notesPtr = &trimmed
	}

	updated, err := s.store.UpdateBaseline(ctx, id, BaselineUpdate{
		MatchThreshold:   req.MatchThreshold,
		SuspectThreshold: req.SuspectThreshold,
		TTLDays:          req.TTLDays,
		Status:           req.Status,
		Notes:            notesPtr,
	})
	if err != nil {
		return nil, err
	}
	view := toBaselineView(*updated, s.currentTime())
	return &view, nil
}

// DeleteBaseline deletes a baseline record by ID.
func (s *BaselineService) DeleteBaseline(ctx context.Context, id int64) error {
	if err := s.ensureStore(); err != nil {
		return err
	}
	if id <= 0 {
		return infraerrors.BadRequest("MODELFP_INVALID_ID", "baseline id must be positive")
	}
	return s.store.DeleteBaseline(ctx, id)
}

// StartCaptureJob validates target coordinates and capture options synchronously,
// persists a secret-free CaptureJob, and executes multi-round dual-engine capture asynchronously.
func (s *BaselineService) StartCaptureJob(ctx context.Context, req CaptureRequest, adminID int64) (*CaptureJob, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if s.resolver == nil || s.orchestrator == nil {
		return nil, errors.New("baseline service dependencies are not configured")
	}

	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "baseline service is shutting down")
	}

	rounds, err := normalizeCaptureRounds(req.SampleRounds)
	if err != nil {
		return nil, err
	}
	models, err := normalizeCaptureModels(req.Models)
	if err != nil {
		return nil, err
	}
	sourceType, err := normalizeSourceType(req.SourceType, SourceOfficialDirect)
	if err != nil {
		return nil, err
	}

	ttlDays := req.TTLDays
	if ttlDays <= 0 {
		ttlDays = defaultBaselineTTLDays
	}

	resolved, err := s.resolveCaptureTarget(ctx, req)
	if err != nil {
		return nil, err
	}

	suite, err := s.resolveCaptureSuite(ctx, req.SuiteID, resolved.Target.Protocol)
	if err != nil {
		return nil, err
	}

	sourceLabel := strings.TrimSpace(req.SourceLabel)
	if sourceLabel == "" {
		sourceLabel = resolved.TargetLabel
	}
	sourceLabel = truncateRunes(redactSecrets(sourceLabel, resolved.Target), maxBaselineLabelChars)
	snapshotOverride := truncateRunes(redactSecrets(strings.TrimSpace(req.UpstreamSnapshot), resolved.Target), maxBaselineLabelChars)
	notes := redactExactSecrets(strings.TrimSpace(req.Notes), resolved.Target)

	for _, m := range models {
		if modelContainsCredentials(m, resolved.Target) {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_MODELS", "model name must not contain target credentials")
		}
	}

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "baseline service is shutting down")
	}
	jobCtx, jobCancel := context.WithCancel(s.baseCtx)
	s.wg.Add(1)
	s.mu.Unlock()

	created, err := s.store.CreateCaptureJob(ctx, CaptureJob{
		Status:          RunStatusQueued,
		Protocol:        resolved.Target.Protocol,
		SuiteID:         suite.ID,
		SourceType:      sourceType,
		SampleRounds:    rounds,
		TotalModels:     len(models),
		CompletedModels: 0,
		Results:         []CaptureModelResult{},
		CreatedBy:       adminID,
	})
	if err != nil {
		jobCancel()
		s.wg.Done()
		return nil, err
	}

	s.mu.Lock()
	stoppedNow := s.stopped
	s.mu.Unlock()
	if stoppedNow {
		now := s.currentTime()
		created.Status = RunStatusCancelled
		created.ErrorMessage = "service stopped before capture started"
		created.FinishedAt = &now
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), captureCleanupTimeout)
		_ = s.store.UpdateCaptureJob(cleanupCtx, *created)
		cleanupCancel()
		jobCancel()
		s.wg.Done()
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "baseline service is shutting down")
	}

	go s.runCaptureJob(
		jobCtx,
		jobCancel,
		*created,
		resolved,
		*suite,
		models,
		sourceLabel,
		snapshotOverride,
		ttlDays,
		notes,
	)

	return created, nil
}

// GetCaptureJob returns the current status and per-model calibration results for a capture job.
func (s *BaselineService) GetCaptureJob(ctx context.Context, id int64) (*CaptureJob, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_ID", "capture job id must be positive")
	}
	return s.store.GetCaptureJob(ctx, id)
}

func (s *BaselineService) runCaptureJob(
	ctx context.Context,
	cancel context.CancelFunc,
	job CaptureJob,
	resolved *ResolvedTarget,
	suite ProbeSuite,
	models []string,
	sourceLabel string,
	snapshotOverride string,
	ttlDays int,
	notes string,
) {
	defer s.wg.Done()
	defer cancel()

	persistFinal := func(status RunStatus, errMsg string) {
		now := s.currentTime()
		job.Status = status
		job.ErrorMessage = redactSecrets(errMsg, resolved.Target)
		job.FinishedAt = &now

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), captureCleanupTimeout)
		defer cleanupCancel()
		_ = s.store.UpdateCaptureJob(cleanupCtx, job)
	}

	job.Status = RunStatusRunning
	if err := s.store.UpdateCaptureJob(ctx, job); err != nil {
		if ctx.Err() != nil {
			persistFinal(RunStatusCancelled, "capture cancelled")
		} else {
			persistFinal(RunStatusFailed, err.Error())
		}
		return
	}

	familyMaps, err := s.store.ListFamilyMaps(ctx)
	if err != nil {
		if ctx.Err() != nil {
			persistFinal(RunStatusCancelled, "capture cancelled")
		} else {
			persistFinal(RunStatusFailed, fmt.Sprintf("load family maps: %v", err))
		}
		return
	}

	succeededCount := 0
	var firstErrMsg string

	for _, claimedModel := range models {
		if ctx.Err() != nil {
			persistFinal(RunStatusCancelled, "capture cancelled")
			return
		}

		canonicalModel, _ := resolveCanonicalAndPeers(claimedModel, "", familyMaps, nil)
		upstreamModel := s.resolver.MapAccountModel(resolved, claimedModel)
		if upstreamModel == "" {
			upstreamModel = claimedModel
		}

		res := CaptureModelResult{
			Model:          redactSecrets(claimedModel, resolved.Target),
			CanonicalModel: redactSecrets(canonicalModel, resolved.Target),
		}

		if modelContainsCredentials(upstreamModel, resolved.Target) {
			safeErr := "upstream model mapping contains credentials and was rejected"
			res.Error = safeErr
			if firstErrMsg == "" {
				firstErrMsg = safeErr
			}
			job.Results = append(job.Results, res)
			job.CompletedModels++
			if err := s.store.UpdateCaptureJob(ctx, job); err != nil {
				if ctx.Err() != nil {
					persistFinal(RunStatusCancelled, "capture cancelled")
					return
				}
				persistFinal(RunStatusFailed, err.Error())
				return
			}
			continue
		}

		samples, capErr := s.orchestrator.CaptureModelSignatures(ctx, resolved.Target, upstreamModel, suite, job.SampleRounds)
		if capErr != nil {
			if ctx.Err() != nil {
				persistFinal(RunStatusCancelled, "capture cancelled")
				return
			}
			safeErr := redactSecrets(capErr.Error(), resolved.Target)
			res.Error = safeErr
			if firstErrMsg == "" {
				firstErrMsg = safeErr
			}
		} else {
			cleanBehavior := sanitizeCapturedBehaviorSignature(samples.AggregatedBehavior, resolved.Target)
			cleanLogprobs := sanitizeCapturedLogprobsSignature(samples.AggregatedLogprobs, resolved.Target)

			snapshot := snapshotOverride
			if snapshot == "" && cleanBehavior != nil && len(cleanBehavior.ResponseModels) > 0 {
				snapshot = truncateRunes(redactSecrets(cleanBehavior.ResponseModels[0], resolved.Target), maxBaselineLabelChars)
			}
			snapshot = truncateRunes(redactSecrets(snapshot, resolved.Target), maxBaselineLabelChars)

			if cleanBehavior == nil {
				safeErr := "missing behavior signature for baseline capture"
				res.Error = safeErr
				if firstErrMsg == "" {
					firstErrMsg = safeErr
				}
			} else {
				logprobsOK := true
				if samples.LogprobsSupported && cleanLogprobs != nil {
					lpID, selfDiv, nearDist, overlap, detail, saveErr := s.persistCapturedBaseline(
						ctx,
						canonicalModel,
						resolved.Target.Protocol,
						suite,
						DetectorLogprobs,
						job.SourceType,
						sourceLabel,
						snapshot,
						job.SampleRounds,
						samples.LogprobsSelfDivergenceP95,
						cleanLogprobs,
						nil,
						ttlDays,
						notes,
					)
					if saveErr != nil {
						logprobsOK = false
						safeErr := redactSecrets(saveErr.Error(), resolved.Target)
						res.Error = safeErr
						if firstErrMsg == "" {
							firstErrMsg = safeErr
						}
					} else {
						res.LogprobsBaselineID = &lpID
						res.LogprobsSelfDivP95 = &selfDiv
						res.LogprobsNearestDist = nearDist
						if overlap {
							res.OverlapWarning = true
							res.OverlapDetails = append(res.OverlapDetails, redactSecrets(detail, resolved.Target))
						}
					}
				}

				if logprobsOK {
					bhID, selfDiv, nearDist, overlap, detail, saveErr := s.persistCapturedBaseline(
						ctx,
						canonicalModel,
						resolved.Target.Protocol,
						suite,
						DetectorBehavior,
						job.SourceType,
						sourceLabel,
						snapshot,
						job.SampleRounds,
						samples.BehaviorSelfDivergenceP95,
						nil,
						cleanBehavior,
						ttlDays,
						notes,
					)
					if saveErr != nil {
						safeErr := redactSecrets(saveErr.Error(), resolved.Target)
						res.Error = safeErr
						if firstErrMsg == "" {
							firstErrMsg = safeErr
						}
					} else {
						res.BehaviorBaselineID = &bhID
						res.BehaviorSelfDivP95 = &selfDiv
						res.BehaviorNearestDist = nearDist
						if overlap {
							res.OverlapWarning = true
							res.OverlapDetails = append(res.OverlapDetails, redactSecrets(detail, resolved.Target))
						}
						succeededCount++
					}
				}
			}
		}

		job.Results = append(job.Results, res)
		job.CompletedModels++
		if err := s.store.UpdateCaptureJob(ctx, job); err != nil {
			if ctx.Err() != nil {
				persistFinal(RunStatusCancelled, "capture cancelled")
				return
			}
			persistFinal(RunStatusFailed, err.Error())
			return
		}
	}

	if succeededCount == 0 {
		if firstErrMsg == "" {
			firstErrMsg = "no baselines captured"
		}
		persistFinal(RunStatusFailed, firstErrMsg)
		return
	}
	persistFinal(RunStatusCompleted, "")
}

func (s *BaselineService) persistCapturedBaseline(
	ctx context.Context,
	canonicalModel string,
	protocol Protocol,
	suite ProbeSuite,
	kind DetectorKind,
	sourceType SourceType,
	sourceLabel string,
	snapshot string,
	sampleRounds int,
	selfDivP95 float64,
	logprobsSig *LogprobsSignature,
	behaviorSig *BehaviorSignature,
	ttlDays int,
	notes string,
) (int64, float64, *float64, bool, string, error) {
	peers, err := s.store.ListBaselines(ctx, BaselineFilter{
		Protocol:     protocol,
		SuiteID:      suite.ID,
		DetectorKind: kind,
		Status:       StatusActive,
	})
	if err != nil {
		return 0, 0, nil, false, "", fmt.Errorf("list peer baselines: %w", err)
	}

	candidate := Baseline{
		CanonicalModel:    canonicalModel,
		Protocol:          protocol,
		SuiteID:           suite.ID,
		DetectorKind:      kind,
		SelfDivergenceP95: selfDivP95,
		Logprobs:          logprobsSig,
		Behavior:          behaviorSig,
	}

	nearDist, nearestPeer := findNearestPeerBaseline(candidate, peers, &suite)
	matchThr, suspectThr := DeriveThresholds(kind, selfDivP95, nearDist)

	overlap := false
	var overlapDetail string
	if nearDist != nil && nearestPeer != nil && selfDivP95 > 0 && *nearDist < 1.5*selfDivP95 {
		overlap = true
		overlapDetail = fmt.Sprintf(
			"%s: nearest peer %s distance=%.4f (1.5*D_self=%.4f)",
			kind,
			nearestPeer.CanonicalModel,
			*nearDist,
			1.5*selfDivP95,
		)
	}

	saved, err := s.store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel:    canonicalModel,
		Protocol:          protocol,
		SuiteID:           suite.ID,
		SuiteKey:          suite.SuiteKey,
		SuiteVersion:      suite.Version,
		DetectorKind:      kind,
		SourceType:        sourceType,
		SourceLabel:       sourceLabel,
		UpstreamSnapshot:  snapshot,
		SampleCount:       sampleRounds,
		Logprobs:          logprobsSig,
		Behavior:          behaviorSig,
		SelfDivergenceP95: selfDivP95,
		MatchThreshold:    matchThr,
		SuspectThreshold:  suspectThr,
		TTLDays:           ttlDays,
		Status:            StatusActive,
		Notes:             notes,
		CollectedAt:       s.currentTime(),
	})
	if err != nil {
		return 0, 0, nil, false, "", fmt.Errorf("save %s baseline: %w", kind, err)
	}

	return saved.ID, selfDivP95, nearDist, overlap, overlapDetail, nil
}

// ConfusionMatrix computes the symmetric pairwise distance matrix and close-pair warnings
// for active baselines in the requested (protocol, suite_id, detector_kind) scope.
func (s *BaselineService) ConfusionMatrix(ctx context.Context, req ConfusionMatrixRequest) (*ConfusionMatrixResult, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}

	proto, err := normalizeSupportedProtocol(req.Protocol, false)
	if err != nil {
		return nil, err
	}

	kind, err := normalizeDetectorKind(req.DetectorKind, proto)
	if err != nil {
		return nil, err
	}

	var suite *ProbeSuite
	if req.SuiteID > 0 {
		suite, err = s.store.GetSuite(ctx, req.SuiteID)
	} else {
		suite, err = s.store.GetDefaultSuite(ctx)
	}
	if err != nil {
		return nil, err
	}

	rows, err := s.store.ListBaselines(ctx, BaselineFilter{
		Protocol:     proto,
		SuiteID:      suite.ID,
		DetectorKind: kind,
		Status:       StatusActive,
	})
	if err != nil {
		return nil, err
	}

	usable := make([]Baseline, 0, len(rows))
	for _, b := range rows {
		if baselineHasPayload(b, kind) {
			usable = append(usable, b)
		}
	}

	res := BuildConfusionMatrix(usable, func(a, b Baseline) float64 {
		d, isComparable := baselineDistance(a, b, suite)
		if !isComparable {
			return 1.0
		}
		return d
	})
	res.Protocol = proto
	res.SuiteID = suite.ID
	res.DetectorKind = kind
	return &res, nil
}

// ExportBundle exports suites, family maps, and active baselines protected by a canonical SHA-256 checksum.
// When includePrivate is false, all visibility=="private" suites and any baselines belonging to them are excluded.
func (s *BaselineService) ExportBundle(ctx context.Context, includePrivate bool) (*Bundle, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}

	allSuites, err := s.store.ListSuites(ctx)
	if err != nil {
		return nil, err
	}
	includedSuites := make([]ProbeSuite, 0, len(allSuites))
	suiteByID := make(map[int64]ProbeSuite, len(allSuites))
	for _, suite := range allSuites {
		if !includePrivate && suite.Visibility != VisibilityPublic {
			continue
		}
		if suite.Probes == nil {
			suite.Probes = []ProbeDefinition{}
		}
		if strings.TrimSpace(suite.ContentHash) == "" {
			hash, hashErr := ComputeContentHash(suite.Probes)
			if hashErr != nil {
				return nil, hashErr
			}
			suite.ContentHash = hash
		}
		includedSuites = append(includedSuites, suite)
		suiteByID[suite.ID] = suite
	}
	sort.Slice(includedSuites, func(i, j int) bool {
		if includedSuites[i].SuiteKey != includedSuites[j].SuiteKey {
			return includedSuites[i].SuiteKey < includedSuites[j].SuiteKey
		}
		return includedSuites[i].Version < includedSuites[j].Version
	})

	familyMaps, err := s.store.ListFamilyMaps(ctx)
	if err != nil {
		return nil, err
	}
	if familyMaps == nil {
		familyMaps = []FamilyMap{}
	}
	sort.Slice(familyMaps, func(i, j int) bool {
		return familyMaps[i].CanonicalModel < familyMaps[j].CanonicalModel
	})

	activeBaselines, err := s.store.ListBaselines(ctx, BaselineFilter{Status: StatusActive})
	if err != nil {
		return nil, err
	}
	exportedBaselines := make([]Baseline, 0, len(activeBaselines))
	for _, b := range activeBaselines {
		suite, ok := suiteByID[b.SuiteID]
		if !ok {
			continue
		}
		if b.SuiteKey == "" {
			b.SuiteKey = suite.SuiteKey
		}
		if b.SuiteVersion == "" {
			b.SuiteVersion = suite.Version
		}
		exportedBaselines = append(exportedBaselines, b)
	}
	sort.Slice(exportedBaselines, func(i, j int) bool {
		if exportedBaselines[i].CanonicalModel != exportedBaselines[j].CanonicalModel {
			return exportedBaselines[i].CanonicalModel < exportedBaselines[j].CanonicalModel
		}
		if exportedBaselines[i].Protocol != exportedBaselines[j].Protocol {
			return exportedBaselines[i].Protocol < exportedBaselines[j].Protocol
		}
		if exportedBaselines[i].SuiteKey != exportedBaselines[j].SuiteKey {
			return exportedBaselines[i].SuiteKey < exportedBaselines[j].SuiteKey
		}
		if exportedBaselines[i].SuiteVersion != exportedBaselines[j].SuiteVersion {
			return exportedBaselines[i].SuiteVersion < exportedBaselines[j].SuiteVersion
		}
		return exportedBaselines[i].DetectorKind < exportedBaselines[j].DetectorKind
	})

	bundle := &Bundle{
		SchemaVersion:  DefaultBundleSchemaVersion,
		ExportedAt:     s.currentTime(),
		IncludePrivate: includePrivate,
		Suites:         includedSuites,
		FamilyMaps:     familyMaps,
		Baselines:      exportedBaselines,
	}
	checksum, err := computeBundleSHA256(*bundle)
	if err != nil {
		return nil, err
	}
	bundle.SHA256 = checksum
	return bundle, nil
}

// ImportBundle verifies the bundle SHA-256 checksum and imports suites, family maps, and baselines
// according to conflict_mode ("skip" or "overwrite").
func (s *BaselineService) ImportBundle(ctx context.Context, req ImportBundleRequest) (*ImportBundleResult, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}

	if req.Bundle.SchemaVersion != DefaultBundleSchemaVersion {
		return nil, infraerrors.BadRequest(
			"MODELFP_INVALID_BUNDLE_SCHEMA",
			fmt.Sprintf("unsupported bundle schema_version %q", req.Bundle.SchemaVersion),
		)
	}

	conflictMode := req.ConflictMode
	if conflictMode == "" {
		conflictMode = ImportConflictSkip
	}
	if conflictMode != ImportConflictSkip && conflictMode != ImportConflictOverwrite {
		return nil, infraerrors.BadRequest(
			"MODELFP_INVALID_CONFLICT_MODE",
			fmt.Sprintf("unsupported conflict_mode %q", req.ConflictMode),
		)
	}

	expectedSHA, err := computeBundleSHA256(req.Bundle)
	if err != nil {
		return nil, err
	}
	providedSHA := strings.ToLower(strings.TrimSpace(req.Bundle.SHA256))
	if len(providedSHA) != len(expectedSHA) || subtle.ConstantTimeCompare([]byte(providedSHA), []byte(expectedSHA)) != 1 {
		return nil, ErrInvalidBundleChecksum
	}

	if err := validateBundleEntities(req.Bundle); err != nil {
		return nil, err
	}

	existingSuites, err := s.store.ListSuites(ctx)
	if err != nil {
		return nil, err
	}
	suiteByKeyVer := make(map[string]ProbeSuite, len(existingSuites))
	hasActiveDefault := false
	for _, existing := range existingSuites {
		suiteByKeyVer[suiteKeyVersion(existing.SuiteKey, existing.Version)] = existing
		if existing.IsDefault && existing.Status == StatusActive {
			hasActiveDefault = true
		}
	}

	if err := prevalidateBundleReferences(req.Bundle, suiteByKeyVer); err != nil {
		return nil, err
	}

	result := &ImportBundleResult{}

	for _, suite := range req.Bundle.Suites {
		key := suiteKeyVersion(suite.SuiteKey, suite.Version)
		if _, exists := suiteByKeyVer[key]; exists {
			result.SuitesSkipped++
			continue
		}

		toCreate := suite
		toCreate.ID = 0
		if hasActiveDefault {
			toCreate.IsDefault = false
		}
		if toCreate.Visibility == "" {
			toCreate.Visibility = VisibilityPublic
		}
		if toCreate.Status == "" {
			toCreate.Status = StatusActive
		}
		if toCreate.Probes == nil {
			toCreate.Probes = []ProbeDefinition{}
		}
		if strings.TrimSpace(toCreate.ContentHash) == "" {
			hash, hashErr := ComputeContentHash(toCreate.Probes)
			if hashErr != nil {
				return nil, hashErr
			}
			toCreate.ContentHash = hash
		}
		created, err := s.store.CreateSuite(ctx, toCreate)
		if err != nil {
			if errors.Is(err, ErrSuiteImmutable) {
				result.SuitesSkipped++
				continue
			}
			return nil, err
		}
		result.SuitesImported++
		suiteByKeyVer[key] = *created
		if created.IsDefault && created.Status == StatusActive {
			hasActiveDefault = true
		}
	}

	existingFamilies, err := s.store.ListFamilyMaps(ctx)
	if err != nil {
		return nil, err
	}
	existingFamilySet := make(map[string]struct{}, len(existingFamilies))
	for _, fm := range existingFamilies {
		existingFamilySet[strings.TrimSpace(fm.CanonicalModel)] = struct{}{}
	}
	for _, fm := range req.Bundle.FamilyMaps {
		canon := strings.TrimSpace(fm.CanonicalModel)
		_, exists := existingFamilySet[canon]
		if exists && conflictMode == ImportConflictSkip {
			result.FamilyMapsSkipped++
			continue
		}
		normalized := normalizeFamilyMapInput(fm)
		if _, err := s.store.UpsertFamilyMap(ctx, normalized); err != nil {
			return nil, err
		}
		existingFamilySet[canon] = struct{}{}
		result.FamilyMapsImported++
	}

	existingBaselines, err := s.store.ListBaselines(ctx, BaselineFilter{Status: StatusActive})
	if err != nil {
		return nil, err
	}
	type baselineActiveKey struct {
		canonicalModel string
		protocol       Protocol
		suiteID        int64
		detectorKind   DetectorKind
	}
	activeKeys := make(map[baselineActiveKey]struct{}, len(existingBaselines))
	for _, b := range existingBaselines {
		activeKeys[baselineActiveKey{
			canonicalModel: strings.TrimSpace(b.CanonicalModel),
			protocol:       b.Protocol,
			suiteID:        b.SuiteID,
			detectorKind:   b.DetectorKind,
		}] = struct{}{}
	}

	bundleSuiteByKeyVer, bundleSuiteByID := indexBundleSuites(req.Bundle.Suites)
	for _, b := range req.Bundle.Baselines {
		suiteRef, err := resolveBundleSuiteForBaseline(b, bundleSuiteByKeyVer, bundleSuiteByID)
		if err != nil {
			return nil, err
		}
		targetSuite, ok := suiteByKeyVer[suiteKeyVersion(suiteRef.SuiteKey, suiteRef.Version)]
		if !ok {
			return nil, infraerrors.BadRequest(
				"MODELFP_INVALID_BUNDLE_SUITE",
				fmt.Sprintf("baseline %q references suite (%s/%s) that failed resolution", b.CanonicalModel, suiteRef.SuiteKey, suiteRef.Version),
			)
		}
		targetSuiteID := targetSuite.ID
		key := baselineActiveKey{
			canonicalModel: strings.TrimSpace(b.CanonicalModel),
			protocol:       b.Protocol,
			suiteID:        targetSuiteID,
			detectorKind:   b.DetectorKind,
		}
		if _, exists := activeKeys[key]; exists && conflictMode == ImportConflictSkip {
			result.BaselinesSkipped++
			continue
		}

		toSave := b
		toSave.ID = 0
		toSave.SuiteID = targetSuiteID
		toSave.SuiteKey = targetSuite.SuiteKey
		toSave.SuiteVersion = targetSuite.Version
		toSave.Status = StatusActive
		if _, err := s.store.UpsertActiveBaseline(ctx, toSave); err != nil {
			return nil, err
		}
		activeKeys[key] = struct{}{}
		result.BaselinesImported++
	}

	return result, nil
}

// ListSuites lists all probe suites ordered by default status, key, and ID.
func (s *BaselineService) ListSuites(ctx context.Context) ([]ProbeSuite, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	return s.store.ListSuites(ctx)
}

// CreateSuite creates a new immutable probe suite version.
// Duplicate (suite_key, version) pairs fail with ErrSuiteImmutable.
func (s *BaselineService) CreateSuite(ctx context.Context, req CreateSuiteRequest, adminID int64) (*ProbeSuite, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}

	suiteKey := strings.TrimSpace(req.SuiteKey)
	version := strings.TrimSpace(req.Version)
	if suiteKey == "" || version == "" {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_SUITE", "suite_key and version are required")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = suiteKey + " " + version
	}

	vis := req.Visibility
	if vis == "" {
		vis = VisibilityPublic
	}
	if vis != VisibilityPublic && vis != VisibilityPrivate {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_VISIBILITY", fmt.Sprintf("unsupported visibility %q", req.Visibility))
	}

	probes, err := normalizeSuiteProbes(req.Probes)
	if err != nil {
		return nil, err
	}

	hash, err := ComputeContentHash(probes)
	if err != nil {
		return nil, err
	}

	return s.store.CreateSuite(ctx, ProbeSuite{
		SuiteKey:    suiteKey,
		Version:     version,
		Name:        name,
		Visibility:  vis,
		Status:      StatusActive,
		IsDefault:   req.IsDefault,
		Probes:      probes,
		ContentHash: hash,
		CreatedBy:   adminID,
	})
}

// UpdateSuiteStatus updates suite active/archived state and default flag.
func (s *BaselineService) UpdateSuiteStatus(ctx context.Context, id int64, req UpdateSuiteStatusRequest) (*ProbeSuite, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_ID", "suite id must be positive")
	}

	existing, err := s.store.GetSuite(ctx, id)
	if err != nil {
		return nil, err
	}

	status := req.Status
	if status == "" {
		status = existing.Status
	}
	if status != StatusActive && status != StatusArchived {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_STATUS", fmt.Sprintf("unsupported status %q", req.Status))
	}

	isDefault := existing.IsDefault
	if req.IsDefault != nil {
		isDefault = *req.IsDefault
	}
	if status == StatusArchived {
		isDefault = false
	}

	return s.store.UpdateSuiteStatus(ctx, id, status, isDefault)
}

// ListFamilyMaps lists all configured model family/alias mappings.
func (s *BaselineService) ListFamilyMaps(ctx context.Context) ([]FamilyMap, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	return s.store.ListFamilyMaps(ctx)
}

// UpsertFamilyMap creates or updates a model family/alias mapping.
func (s *BaselineService) UpsertFamilyMap(ctx context.Context, fm FamilyMap) (*FamilyMap, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	normalized := normalizeFamilyMapInput(fm)
	if normalized.CanonicalModel == "" {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_CANONICAL_MODEL", "canonical_model is required")
	}
	return s.store.UpsertFamilyMap(ctx, normalized)
}

// DeleteFamilyMap deletes a model family mapping by canonical_model.
func (s *BaselineService) DeleteFamilyMap(ctx context.Context, canonicalModel string) error {
	if err := s.ensureStore(); err != nil {
		return err
	}
	canon := strings.TrimSpace(canonicalModel)
	if canon == "" {
		return infraerrors.BadRequest("MODELFP_INVALID_CANONICAL_MODEL", "canonical_model is required")
	}
	return s.store.DeleteFamilyMap(ctx, canon)
}

func (s *BaselineService) resolveCaptureTarget(ctx context.Context, req CaptureRequest) (*ResolvedTarget, error) {
	src := req.TargetSource
	if src == "" {
		hasAccount := req.AccountID != nil && *req.AccountID > 0
		hasAdHoc := req.AdHoc != nil || strings.TrimSpace(req.BaseURL) != "" || strings.TrimSpace(req.APIKey) != ""
		switch {
		case hasAccount && hasAdHoc:
			return nil, infraerrors.BadRequest("MODELFP_AMBIGUOUS_TARGET", "specify either account_id or adhoc target, not both")
		case hasAccount:
			src = TargetSourceAccount
		case hasAdHoc:
			src = TargetSourceAdHoc
		default:
			return nil, infraerrors.BadRequest("MODELFP_INVALID_TARGET_SOURCE", "target_source is required")
		}
	}

	switch src {
	case TargetSourceAccount:
		if req.AccountID == nil || *req.AccountID <= 0 {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_ACCOUNT_ID", "account_id is required for account target")
		}
		protoOverride := req.Protocol
		if protoOverride == "" && req.AdHoc != nil {
			protoOverride = req.AdHoc.Protocol
		}
		return s.resolver.ResolveAccount(ctx, *req.AccountID, protoOverride)
	case TargetSourceAdHoc:
		input := AdHocTargetInput{
			Protocol:     req.Protocol,
			BaseURL:      req.BaseURL,
			APIKey:       req.APIKey,
			AuthMode:     req.AuthMode,
			ProxyID:      req.ProxyID,
			ExtraHeaders: req.ExtraHeaders,
		}
		if req.AdHoc != nil {
			input = *req.AdHoc
			if input.Protocol == "" {
				input.Protocol = req.Protocol
			}
		}
		return s.resolver.ResolveAdHoc(ctx, input)
	default:
		return nil, infraerrors.BadRequest("MODELFP_INVALID_TARGET_SOURCE", fmt.Sprintf("unsupported target_source %q", req.TargetSource))
	}
}

func (s *BaselineService) resolveCaptureSuite(ctx context.Context, suiteID int64, _ Protocol) (*ProbeSuite, error) {
	var (
		suite *ProbeSuite
		err   error
	)
	if suiteID > 0 {
		suite, err = s.store.GetSuite(ctx, suiteID)
	} else {
		suite, err = s.store.GetDefaultSuite(ctx)
	}
	if err != nil {
		return nil, err
	}
	if suite.Status == StatusArchived {
		return nil, infraerrors.BadRequest("MODELFP_SUITE_ARCHIVED", "cannot capture baselines using an archived probe suite")
	}

	if !hasProbesOfKind(*suite, DetectorBehavior) {
		return nil, infraerrors.BadRequest(
			"MODELFP_NO_APPLICABLE_PROBES",
			fmt.Sprintf("suite %s/%s must contain at least one behavior probe for baseline capture", suite.SuiteKey, suite.Version),
		)
	}
	return suite, nil
}

func toBaselineView(b Baseline, now time.Time) BaselineView {
	var expiresAt time.Time
	if !b.CollectedAt.IsZero() && b.TTLDays > 0 {
		expiresAt = b.CollectedAt.UTC().Add(time.Duration(b.TTLDays) * 24 * time.Hour)
	}
	return BaselineView{
		Baseline:  b,
		Freshness: computeBaselineFreshness(b, now),
		ExpiresAt: expiresAt,
	}
}

func findNearestPeerBaseline(candidate Baseline, peers []Baseline, suite *ProbeSuite) (*float64, *Baseline) {
	var (
		hasBest  bool
		bestDist float64
		bestPeer *Baseline
	)
	for i := range peers {
		peer := peers[i]
		if strings.EqualFold(peer.CanonicalModel, candidate.CanonicalModel) {
			continue
		}
		if !baselineHasPayload(peer, candidate.DetectorKind) {
			continue
		}
		dist, isComparable := baselineDistance(candidate, peer, suite)
		if !isComparable {
			continue
		}
		if !hasBest || dist < bestDist {
			hasBest = true
			bestDist = dist
			cp := peer
			bestPeer = &cp
		}
	}
	if !hasBest {
		return nil, nil
	}
	return &bestDist, bestPeer
}

func baselineDistance(a, b Baseline, suite *ProbeSuite) (float64, bool) {
	if a.DetectorKind != b.DetectorKind {
		return 1.0, false
	}
	weights := suiteWeightMap(suite, a.DetectorKind)

	switch a.DetectorKind {
	case DetectorLogprobs:
		if a.Logprobs == nil || b.Logprobs == nil {
			return 1.0, false
		}
		return logprobsBaselineDistance(a.Logprobs, b.Logprobs, weights)
	case DetectorBehavior:
		if a.Behavior == nil || b.Behavior == nil {
			return 1.0, false
		}
		dAB, okAB := directedBehaviorBaselineDistance(a.Behavior, b, weights)
		dBA, okBA := directedBehaviorBaselineDistance(b.Behavior, a, weights)
		if !okAB || !okBA {
			return 1.0, false
		}
		return clampFloat(0.5*(dAB+dBA), 0, 1), true
	default:
		return 1.0, false
	}
}

func suiteWeightMap(suite *ProbeSuite, kind DetectorKind) map[string]float64 {
	if suite == nil || len(suite.Probes) == 0 {
		return nil
	}
	weights := make(map[string]float64, len(suite.Probes))
	for _, p := range suite.Probes {
		if p.Kind == kind {
			weights[p.ID] = effectiveProbeWeight(p.Weight)
		}
	}
	return weights
}

func probeWeightFromMap(weights map[string]float64, probeID string) float64 {
	if weights != nil {
		if w, ok := weights[probeID]; ok && w > 0 {
			return w
		}
	}
	return 1.0
}

func logprobsBaselineDistance(a, b *LogprobsSignature, weights map[string]float64) (float64, bool) {
	if a == nil || b == nil || len(a.Probes) == 0 || len(b.Probes) == 0 {
		return 1.0, false
	}
	probeIDs := make([]string, 0, len(a.Probes))
	for pid := range a.Probes {
		probeIDs = append(probeIDs, pid)
	}
	sort.Strings(probeIDs)

	var weightedSum, totalWeight float64
	for _, pid := range probeIDs {
		pa := a.Probes[pid]
		pb, ok := b.Probes[pid]
		if !ok || len(pa.Distribution) == 0 || len(pb.Distribution) == 0 {
			continue
		}
		w := probeWeightFromMap(weights, pid)
		weightedSum += w * JensenShannonDivergence(pa.Distribution, pb.Distribution)
		totalWeight += w
	}
	if totalWeight <= 0 {
		return 1.0, false
	}
	return clampFloat(weightedSum/totalWeight, 0, 1), true
}

func directedBehaviorBaselineDistance(obs *BehaviorSignature, target Baseline, weights map[string]float64) (float64, bool) {
	if obs == nil || target.Behavior == nil || len(obs.Probes) == 0 || len(target.Behavior.Probes) == 0 {
		return 1.0, false
	}
	probeIDs := make([]string, 0, len(obs.Probes))
	for pid := range obs.Probes {
		probeIDs = append(probeIDs, pid)
	}
	sort.Strings(probeIDs)

	var weightedSum, totalWeight float64
	for _, pid := range probeIDs {
		obsProbe := obs.Probes[pid]
		baseProbe, ok := target.Behavior.Probes[pid]
		if !ok || len(obsProbe.Samples) == 0 || len(baseProbe.Samples) == 0 {
			continue
		}
		expectedFmt := obsProbe.ExpectedFormat
		if expectedFmt == "" {
			expectedFmt = baseProbe.ExpectedFormat
		}
		var sampleDistSum float64
		for _, sample := range obsProbe.Samples {
			_, d := closestSample(sample, baseProbe.Samples)
			if expectedFmt != "" && baseProbe.FormatMatchRate >= 0.8 && !matchesExpectedFormat(sample, expectedFmt) {
				d = clampFloat(d+behaviorFormatPenaltyWeight, 0, 1)
			}
			sampleDistSum += d
		}
		avgSampleDist := sampleDistSum / float64(len(obsProbe.Samples))
		w := probeWeightFromMap(weights, pid)
		weightedSum += w * avgSampleDist
		totalWeight += w
	}
	if totalWeight <= 0 {
		return 1.0, false
	}
	avgProbeDist := clampFloat(weightedSum/totalWeight, 0, 1)
	metaPenalty := behaviorMetaMismatch(obs, target)
	return clampFloat(avgProbeDist+behaviorMetaPenaltyWeight*metaPenalty, 0, 1), true
}

func normalizeCaptureRounds(rounds int) (int, error) {
	if rounds == 0 {
		return defaultCaptureRounds, nil
	}
	if rounds < minCaptureSampleRounds || rounds > maxCaptureSampleRounds {
		return 0, infraerrors.BadRequest(
			"MODELFP_INVALID_SAMPLE_ROUNDS",
			fmt.Sprintf("sample_rounds must be between %d and %d", minCaptureSampleRounds, maxCaptureSampleRounds),
		)
	}
	return rounds, nil
}

func normalizeCaptureModels(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_MODELS", "at least one non-empty model is required")
	}
	if len(out) > maxCaptureModels {
		return nil, infraerrors.BadRequest(
			"MODELFP_TOO_MANY_MODELS",
			fmt.Sprintf("capture supports at most %d models per job", maxCaptureModels),
		)
	}
	return out, nil
}

func normalizeSourceType(raw, fallback SourceType) (SourceType, error) {
	trimmed := SourceType(strings.ToLower(strings.TrimSpace(string(raw))))
	if trimmed == "" {
		return fallback, nil
	}
	switch trimmed {
	case SourceOfficialDirect, SourceTrustedCloud, SourceCrossVerified, SourceCommunitySeed:
		return trimmed, nil
	default:
		return "", infraerrors.BadRequest("MODELFP_INVALID_SOURCE_TYPE", fmt.Sprintf("unsupported source_type %q", raw))
	}
}

func validateUnitThreshold(name string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return infraerrors.BadRequest("MODELFP_INVALID_THRESHOLDS", fmt.Sprintf("%s must be in [0, 1]", name))
	}
	return nil
}

func normalizeSuiteProbes(raw []ProbeDefinition) ([]ProbeDefinition, error) {
	if len(raw) == 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_PROBES", "at least one probe definition is required")
	}
	out := make([]ProbeDefinition, 0, len(raw))
	seenIDs := make(map[string]struct{}, len(raw))
	for i, p := range raw {
		p.ID = strings.TrimSpace(p.ID)
		p.Prompt = strings.TrimSpace(p.Prompt)
		if p.ID == "" {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_PROBES", fmt.Sprintf("probe[%d].id is required", i))
		}
		if _, dup := seenIDs[p.ID]; dup {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_PROBES", fmt.Sprintf("duplicate probe id %q", p.ID))
		}
		seenIDs[p.ID] = struct{}{}
		if p.Kind != DetectorLogprobs && p.Kind != DetectorBehavior {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_PROBES", fmt.Sprintf("probe %q has unsupported kind %q", p.ID, p.Kind))
		}
		if p.Prompt == "" {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_PROBES", fmt.Sprintf("probe %q prompt is required", p.ID))
		}
		if p.MaxTokens <= 0 {
			if p.Kind == DetectorLogprobs {
				p.MaxTokens = defaultLogprobsMaxTokens
			} else {
				p.MaxTokens = defaultBehaviorMaxTokens
			}
		}
		if p.Kind == DetectorLogprobs && p.TopLogprobs <= 0 {
			p.TopLogprobs = defaultTopLogprobs
		}
		p.Weight = effectiveProbeWeight(p.Weight)
		if p.ExpectedMaxPromptTokens <= 0 {
			p.ExpectedMaxPromptTokens = DefaultExpectedMaxPromptTokens
		}
		if p.Seed != nil {
			seed := *p.Seed
			p.Seed = &seed
		}
		out = append(out, p)
	}
	return out, nil
}

func normalizeDetectorKind(raw DetectorKind, proto Protocol) (DetectorKind, error) {
	trimmed := DetectorKind(strings.ToLower(strings.TrimSpace(string(raw))))
	if trimmed == "" {
		if protocolSupportsLogprobs(proto) {
			return DetectorLogprobs, nil
		}
		return DetectorBehavior, nil
	}
	switch trimmed {
	case DetectorLogprobs, DetectorBehavior:
		return trimmed, nil
	default:
		return "", infraerrors.BadRequest("MODELFP_INVALID_DETECTOR_KIND", fmt.Sprintf("unsupported detector_kind %q", raw))
	}
}

func normalizeFamilyMapInput(fm FamilyMap) FamilyMap {
	canon := strings.TrimSpace(fm.CanonicalModel)
	return FamilyMap{
		CanonicalModel: canon,
		Family:         strings.TrimSpace(fm.Family),
		Aliases:        normalizeDistinctStringList(fm.Aliases, canon),
		ConfusionPeers: normalizeDistinctStringList(fm.ConfusionPeers, canon),
	}
}

func normalizeDistinctStringList(raw []string, exclude string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if exclude != "" && strings.EqualFold(trimmed, exclude) {
			continue
		}
		lower := strings.ToLower(trimmed)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

type bundleChecksumPayload struct {
	SchemaVersion  string       `json:"schema_version"`
	ExportedAt     time.Time    `json:"exported_at"`
	IncludePrivate bool         `json:"include_private"`
	Suites         []ProbeSuite `json:"suites"`
	FamilyMaps     []FamilyMap  `json:"family_maps"`
	Baselines      []Baseline   `json:"baselines"`
}

func computeBundleSHA256(bundle Bundle) (string, error) {
	payload := bundleChecksumPayload{
		SchemaVersion:  bundle.SchemaVersion,
		ExportedAt:     bundle.ExportedAt,
		IncludePrivate: bundle.IncludePrivate,
		Suites:         bundle.Suites,
		FamilyMaps:     bundle.FamilyMaps,
		Baselines:      bundle.Baselines,
	}
	return ComputeContentHash(payload)
}

func validateBundleEntities(bundle Bundle) error {
	seenSuiteKeyVer := make(map[string]struct{}, len(bundle.Suites))
	seenSuiteIDs := make(map[int64]struct{}, len(bundle.Suites))
	for i, s := range bundle.Suites {
		if strings.TrimSpace(s.SuiteKey) == "" || strings.TrimSpace(s.Version) == "" {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("suites[%d] requires suite_key and version", i))
		}
		kv := suiteKeyVersion(s.SuiteKey, s.Version)
		if _, dup := seenSuiteKeyVer[kv]; dup {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("duplicate suite %s/%s in bundle", s.SuiteKey, s.Version))
		}
		seenSuiteKeyVer[kv] = struct{}{}
		if s.ID > 0 {
			if _, dup := seenSuiteIDs[s.ID]; dup {
				return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("duplicate suite id %d in bundle", s.ID))
			}
			seenSuiteIDs[s.ID] = struct{}{}
		}
		if s.Visibility != "" && s.Visibility != VisibilityPublic && s.Visibility != VisibilityPrivate {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("suites[%d] has invalid visibility %q", i, s.Visibility))
		}
		if s.Status != "" && s.Status != StatusActive && s.Status != StatusArchived {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("suites[%d] has invalid status %q", i, s.Status))
		}
		probes := s.Probes
		if probes == nil {
			probes = []ProbeDefinition{}
		}
		computedHash, err := ComputeContentHash(probes)
		if err != nil {
			return fmt.Errorf("compute content hash for bundle suite %s/%s: %w", s.SuiteKey, s.Version, err)
		}
		if trimmedHash := strings.TrimSpace(s.ContentHash); trimmedHash != "" && !strings.EqualFold(trimmedHash, computedHash) {
			return infraerrors.BadRequest(
				"MODELFP_INVALID_BUNDLE",
				fmt.Sprintf("suites[%d] (%s/%s) content_hash mismatch", i, s.SuiteKey, s.Version),
			)
		}
	}
	for i, fm := range bundle.FamilyMaps {
		if strings.TrimSpace(fm.CanonicalModel) == "" {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("family_maps[%d] requires canonical_model", i))
		}
	}
	for i, b := range bundle.Baselines {
		if strings.TrimSpace(b.CanonicalModel) == "" {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("baselines[%d] requires canonical_model", i))
		}
		if _, err := normalizeSupportedProtocol(b.Protocol, false); err != nil {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("baselines[%d]: %s", i, infraerrors.Message(err)))
		}
		if b.DetectorKind != DetectorLogprobs && b.DetectorKind != DetectorBehavior {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("baselines[%d] has invalid detector_kind %q", i, b.DetectorKind))
		}
		if _, err := normalizeSourceType(b.SourceType, SourceOfficialDirect); err != nil {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("baselines[%d]: %s", i, infraerrors.Message(err)))
		}
		if !baselineHasPayload(b, b.DetectorKind) {
			return infraerrors.BadRequest("MODELFP_INVALID_BUNDLE", fmt.Sprintf("baselines[%d] missing signature payload for %s", i, b.DetectorKind))
		}
	}
	return nil
}

func prevalidateBundleReferences(bundle Bundle, existingSuitesByKeyVer map[string]ProbeSuite) error {
	for _, s := range bundle.Suites {
		probes := s.Probes
		if probes == nil {
			probes = []ProbeDefinition{}
		}
		bundleHash := strings.TrimSpace(s.ContentHash)
		if bundleHash == "" {
			computed, err := ComputeContentHash(probes)
			if err != nil {
				return err
			}
			bundleHash = computed
		}
		if existing, exists := existingSuitesByKeyVer[suiteKeyVersion(s.SuiteKey, s.Version)]; exists {
			existingHash := strings.TrimSpace(existing.ContentHash)
			if existingHash == "" {
				existingProbes := existing.Probes
				if existingProbes == nil {
					existingProbes = []ProbeDefinition{}
				}
				computed, err := ComputeContentHash(existingProbes)
				if err != nil {
					return err
				}
				existingHash = computed
			}
			if !strings.EqualFold(existingHash, bundleHash) {
				return infraerrors.Conflict(
					ErrSuiteImmutable.Reason,
					fmt.Sprintf("suite %s/%s already exists with a different content_hash", s.SuiteKey, s.Version),
				)
			}
		}
	}

	bundleSuiteByKeyVer, bundleSuiteByID := indexBundleSuites(bundle.Suites)
	for _, b := range bundle.Baselines {
		if _, err := resolveBundleSuiteForBaseline(b, bundleSuiteByKeyVer, bundleSuiteByID); err != nil {
			return err
		}
	}
	return nil
}

func indexBundleSuites(suites []ProbeSuite) (map[string]ProbeSuite, map[int64]ProbeSuite) {
	byKeyVer := make(map[string]ProbeSuite, len(suites))
	byID := make(map[int64]ProbeSuite, len(suites))
	for _, s := range suites {
		byKeyVer[suiteKeyVersion(s.SuiteKey, s.Version)] = s
		if s.ID > 0 {
			byID[s.ID] = s
		}
	}
	return byKeyVer, byID
}

func resolveBundleSuiteForBaseline(
	b Baseline,
	bundleSuiteByKeyVer map[string]ProbeSuite,
	bundleSuiteByID map[int64]ProbeSuite,
) (ProbeSuite, error) {
	hasKeyVer := strings.TrimSpace(b.SuiteKey) != "" && strings.TrimSpace(b.SuiteVersion) != ""
	var byID ProbeSuite
	var hasByID bool
	if b.SuiteID > 0 {
		byID, hasByID = bundleSuiteByID[b.SuiteID]
	}

	if hasKeyVer {
		targetKV := suiteKeyVersion(b.SuiteKey, b.SuiteVersion)
		if s, ok := bundleSuiteByKeyVer[targetKV]; ok {
			if hasByID && suiteKeyVersion(byID.SuiteKey, byID.Version) != targetKV {
				return ProbeSuite{}, infraerrors.BadRequest(
					"MODELFP_INVALID_BUNDLE_SUITE",
					fmt.Sprintf("baseline %q has conflicting suite_id=%d and suite (%s/%s)", b.CanonicalModel, b.SuiteID, b.SuiteKey, b.SuiteVersion),
				)
			}
			return s, nil
		}
	} else if hasByID {
		return byID, nil
	}

	return ProbeSuite{}, infraerrors.BadRequest(
		"MODELFP_INVALID_BUNDLE_SUITE",
		fmt.Sprintf("baseline %q references suite (%s/%s id=%d) not included in bundle", b.CanonicalModel, b.SuiteKey, b.SuiteVersion, b.SuiteID),
	)
}

func modelContainsCredentials(model string, target ProbeTarget) bool {
	if model == "" {
		return false
	}
	if containsAnySecretOrToken(model, collectSecrets(target)) {
		return true
	}
	if key := strings.TrimSpace(target.APIKey); key != "" && strings.Contains(model, key) {
		return true
	}
	return false
}

func sanitizeCapturedLogprobsSignature(sig *LogprobsSignature, target ProbeTarget) *LogprobsSignature {
	if sig == nil {
		return nil
	}
	out := &LogprobsSignature{
		Probes: make(map[string]LogprobsProbeSignature, len(sig.Probes)),
	}
	for pid, p := range sig.Probes {
		cleanPID := redactExactSecrets(pid, target)
		cleanDist := make(map[string]float64, len(p.Distribution))
		keys := make([]string, 0, len(p.Distribution))
		for tok := range p.Distribution {
			keys = append(keys, tok)
		}
		sort.Strings(keys)
		for _, tok := range keys {
			prob := p.Distribution[tok]
			cleanTok := redactExactSecrets(tok, target)
			if cleanTok == "" && tok != "" {
				cleanTok = redactedSecretPlaceholder
			}
			cleanDist[cleanTok] += prob
		}

		var cleanTop []TokenProb
		if len(p.TopTokens) > 0 {
			merged := make(map[string]TokenProb, len(p.TopTokens))
			order := make([]string, 0, len(p.TopTokens))
			for _, tp := range p.TopTokens {
				cleanTok := redactExactSecrets(tp.Token, target)
				if prev, ok := merged[cleanTok]; ok {
					prev.Prob += tp.Prob
					prev.Logprob = 0
					merged[cleanTok] = prev
				} else {
					order = append(order, cleanTok)
					cp := tp
					cp.Token = cleanTok
					if cleanTok != tp.Token {
						cp.Logprob = 0
					}
					merged[cleanTok] = cp
				}
			}
			cleanTop = make([]TokenProb, 0, len(order))
			for _, tok := range order {
				cleanTop = append(cleanTop, merged[tok])
			}
			sort.SliceStable(cleanTop, func(i, j int) bool {
				return cleanTop[i].Prob > cleanTop[j].Prob
			})
		}

		out.Probes[cleanPID] = LogprobsProbeSignature{
			ProbeID:      redactExactSecrets(p.ProbeID, target),
			Distribution: cleanDist,
			TopTokens:    cleanTop,
			SampleCount:  p.SampleCount,
		}
	}
	return out
}

func sanitizeCapturedBehaviorSignature(sig *BehaviorSignature, target ProbeTarget) *BehaviorSignature {
	if sig == nil {
		return nil
	}
	out := &BehaviorSignature{
		Probes:             make(map[string]BehaviorProbeSignature, len(sig.Probes)),
		ResponseModels:     redactDistinctSlice(sig.ResponseModels, target),
		SystemFingerprints: redactDistinctSlice(sig.SystemFingerprints, target),
	}
	if sig.HasReasoningField != nil {
		flag := *sig.HasReasoningField
		out.HasReasoningField = &flag
	}
	for pid, p := range sig.Probes {
		cleanPID := redactExactSecrets(pid, target)
		cleanSamples := make([]string, len(p.Samples))
		for i, sample := range p.Samples {
			cleanSamples[i] = redactExactSecrets(sample, target)
		}
		out.Probes[cleanPID] = BehaviorProbeSignature{
			ProbeID:         redactExactSecrets(p.ProbeID, target),
			Samples:         cleanSamples,
			ExpectedFormat:  p.ExpectedFormat,
			FormatMatchRate: p.FormatMatchRate,
		}
	}
	return out
}

func redactDistinctSlice(items []string, target ProbeTarget) []string {
	if items == nil {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		clean := redactExactSecrets(item, target)
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out
}

func suiteKeyVersion(suiteKey, version string) string {
	return strings.TrimSpace(suiteKey) + "\x00" + strings.TrimSpace(version)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}
