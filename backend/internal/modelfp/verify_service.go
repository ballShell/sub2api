package modelfp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	defaultVerifyConcurrency = 3
	minVerifyConcurrency     = 1
	maxVerifyConcurrency     = 5
	maxVerifyModels          = 50
	maxRunLabelChars         = 255
	verifyCleanupTimeout     = 5 * time.Second
	cancelWaitTimeout        = 200 * time.Millisecond
)

// DiscoverModelsRequest specifies an ad-hoc upstream or existing API-key account for model discovery.
type DiscoverModelsRequest struct {
	TargetSource TargetSource      `json:"target_source"`
	AccountID    *int64            `json:"account_id,omitempty"`
	AdHoc        *AdHocTargetInput `json:"adhoc,omitempty"`
	Protocol     Protocol          `json:"protocol,omitempty"`
	BaseURL      string            `json:"base_url,omitempty"`
	APIKey       string            `json:"api_key,omitempty"`
	AuthMode     string            `json:"auth_mode,omitempty"`
	ProxyID      *int64            `json:"proxy_id,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// DiscoverModelsResponse returns discovered upstream model IDs and secret-free target metadata.
type DiscoverModelsResponse struct {
	TargetSource  TargetSource `json:"target_source"`
	AccountID     *int64       `json:"account_id,omitempty"`
	TargetLabel   string       `json:"target_label"`
	Protocol      Protocol     `json:"protocol"`
	Models        []string     `json:"models"`
	DefaultModels []string     `json:"default_models,omitempty"`
}

// CreateRunRequest configures an asynchronous batch model verification run.
// Ad-hoc credentials are resolved upfront and never persisted to modelfp_runs or modelfp_run_items.
type CreateRunRequest struct {
	TargetSource TargetSource      `json:"target_source"`
	AccountID    *int64            `json:"account_id,omitempty"`
	AdHoc        *AdHocTargetInput `json:"adhoc,omitempty"`
	Protocol     Protocol          `json:"protocol,omitempty"`
	BaseURL      string            `json:"base_url,omitempty"`
	APIKey       string            `json:"api_key,omitempty"`
	AuthMode     string            `json:"auth_mode,omitempty"`
	ProxyID      *int64            `json:"proxy_id,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
	SuiteID      int64             `json:"suite_id,omitempty"`
	Models       []string          `json:"models"`
	Concurrency  int               `json:"concurrency,omitempty"`
}

type targetInputSpec struct {
	TargetSource TargetSource
	AccountID    *int64
	AdHoc        *AdHocTargetInput
	Protocol     Protocol
	BaseURL      string
	APIKey       string
	AuthMode     string
	ProxyID      *int64
	ExtraHeaders map[string]string
}

type activeRunHandle struct {
	cancel    context.CancelFunc
	done      chan struct{}
	cancelled atomic.Bool

	mu       sync.Mutex
	run      Run
	finished bool
}

// VerifyService executes bounded concurrent batch verification runs and manages per-run cancellation.
type VerifyService struct {
	store        Store
	resolver     *TargetResolver
	orchestrator *Orchestrator

	mu         sync.Mutex
	stopped    bool
	baseCtx    context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	activeRuns map[int64]*activeRunHandle
	now        func() time.Time
}

// NewVerifyService constructs a VerifyService backed by Store, TargetResolver, and Orchestrator.
func NewVerifyService(store Store, resolver *TargetResolver, orchestrator *Orchestrator) *VerifyService {
	ctx, cancel := context.WithCancel(context.Background())
	return &VerifyService{
		store:        store,
		resolver:     resolver,
		orchestrator: orchestrator,
		baseCtx:      ctx,
		cancel:       cancel,
		activeRuns:   make(map[int64]*activeRunHandle),
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// Stop cancels all active verification runs and waits for running workers to finish.
func (s *VerifyService) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		for _, handle := range s.activeRuns {
			handle.cancelled.Store(true)
			handle.cancel()
		}
		if s.cancel != nil {
			s.cancel()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *VerifyService) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *VerifyService) ensureStore() error {
	if s == nil || s.store == nil {
		return errors.New("verify service store is not configured")
	}
	return nil
}

// StartRun validates models, target credentials, and probe suite synchronously, persists a
// secret-free Run record, and launches a bounded worker pool to verify models asynchronously.
func (s *VerifyService) StartRun(ctx context.Context, req CreateRunRequest, adminID int64) (*RunDetail, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if s.resolver == nil || s.orchestrator == nil {
		return nil, errors.New("verify service dependencies are not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "verification service is shutting down")
	}

	models, err := normalizeVerifyModels(req.Models)
	if err != nil {
		return nil, err
	}
	concurrency := normalizeVerifyConcurrency(req.Concurrency)

	resolved, err := resolveTargetInput(ctx, s.resolver, targetInputSpec{
		TargetSource: req.TargetSource,
		AccountID:    req.AccountID,
		AdHoc:        req.AdHoc,
		Protocol:     req.Protocol,
		BaseURL:      req.BaseURL,
		APIKey:       req.APIKey,
		AuthMode:     req.AuthMode,
		ProxyID:      req.ProxyID,
		ExtraHeaders: req.ExtraHeaders,
	})
	if err != nil {
		return nil, err
	}

	for _, claimedModel := range models {
		if modelContainsCredentials(claimedModel, resolved.Target) {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_MODELS", "model name must not contain target credentials")
		}
		upstreamModel := s.resolver.MapAccountModel(resolved, claimedModel)
		if modelContainsCredentials(upstreamModel, resolved.Target) {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_MODELS", "mapped upstream model must not contain target credentials")
		}
	}

	suite, err := s.resolveVerifySuite(ctx, req.SuiteID)
	if err != nil {
		return nil, err
	}

	targetLabel := truncateRunes(redactSecrets(resolved.TargetLabel, resolved.Target), maxRunLabelChars)

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "verification service is shutting down")
	}
	runCtx, runCancel := context.WithCancel(s.baseCtx)
	s.wg.Add(1)
	s.mu.Unlock()

	created, err := s.store.CreateRun(ctx, Run{
		TargetSource:    resolved.Target.Source,
		AccountID:       resolved.Target.AccountID,
		TargetLabel:     targetLabel,
		Protocol:        resolved.Target.Protocol,
		SuiteID:         suite.ID,
		Status:          RunStatusQueued,
		TotalModels:     len(models),
		CompletedModels: 0,
		Summary:         RunSummary{},
		CreatedBy:       adminID,
	})
	if err != nil {
		runCancel()
		s.wg.Done()
		return nil, err
	}

	handle := &activeRunHandle{
		cancel: runCancel,
		done:   make(chan struct{}),
		run:    *created,
	}

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		now := s.currentTime()
		created.Status = RunStatusCancelled
		created.ErrorMessage = "service stopped before run started"
		created.FinishedAt = &now
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), verifyCleanupTimeout)
		_ = s.store.UpdateRunProgress(cleanupCtx, *created)
		cleanupCancel()
		runCancel()
		close(handle.done)
		s.wg.Done()
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "verification service is shutting down")
	}
	s.activeRuns[created.ID] = handle
	s.mu.Unlock()

	go s.executeRun(runCtx, handle, resolved, *suite, models, concurrency)

	return &RunDetail{
		Run:   *created,
		Items: []RunItem{},
	}, nil
}

// GetRun returns the current Run header and all persisted RunItems for runID.
func (s *VerifyService) GetRun(ctx context.Context, runID int64) (*RunDetail, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if runID <= 0 {
		return nil, infraerrors.BadRequest("MODELFP_INVALID_ID", "run id must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	items, err := s.store.ListRunItems(ctx, runID)
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []RunItem{}
	}
	return &RunDetail{
		Run:   *run,
		Items: items,
	}, nil
}

// ListRuns returns a paginated list of historical verification runs.
func (s *VerifyService) ListRuns(ctx context.Context, page, pageSize int) (*RunPage, error) {
	if err := s.ensureStore(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.store.ListRuns(ctx, page, pageSize)
}

// CancelRun cancels an active run, stops queued models from starting, and transitions status to cancelled.
func (s *VerifyService) CancelRun(ctx context.Context, runID int64) error {
	if err := s.ensureStore(); err != nil {
		return err
	}
	if runID <= 0 {
		return infraerrors.BadRequest("MODELFP_INVALID_ID", "run id must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	handle := s.activeRuns[runID]
	s.mu.Unlock()

	if handle != nil {
		handle.cancelled.Store(true)
		handle.cancel()

		waitTimer := time.NewTimer(cancelWaitTimeout)
		defer waitTimer.Stop()

		select {
		case <-handle.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-waitTimer.C:
			handle.mu.Lock()
			if !handle.finished {
				now := s.currentTime()
				handle.run.Status = RunStatusCancelled
				if handle.run.ErrorMessage == "" {
					handle.run.ErrorMessage = "run cancelled"
				}
				handle.run.FinishedAt = &now
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), verifyCleanupTimeout)
				err := s.store.UpdateRunProgress(cleanupCtx, handle.run)
				cleanupCancel()
				if err == nil {
					handle.finished = true
				}
				handle.mu.Unlock()
				return err
			}
			handle.mu.Unlock()
			return nil
		}
	}

	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	switch run.Status {
	case RunStatusCancelled:
		return nil
	case RunStatusCompleted, RunStatusFailed:
		return infraerrors.Conflict(
			"MODELFP_RUN_ALREADY_FINISHED",
			fmt.Sprintf("run #%d already finished with status %s", runID, run.Status),
		)
	default:
		now := s.currentTime()
		run.Status = RunStatusCancelled
		if run.ErrorMessage == "" {
			run.ErrorMessage = "run cancelled"
		}
		run.FinishedAt = &now
		return s.store.UpdateRunProgress(ctx, *run)
	}
}

// DeleteRun cancels any active execution for runID and deletes the run and its items from the store.
func (s *VerifyService) DeleteRun(ctx context.Context, runID int64) error {
	if err := s.ensureStore(); err != nil {
		return err
	}
	if runID <= 0 {
		return infraerrors.BadRequest("MODELFP_INVALID_ID", "run id must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	handle := s.activeRuns[runID]
	s.mu.Unlock()
	if handle != nil {
		handle.cancelled.Store(true)
		handle.cancel()
		select {
		case <-handle.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return s.store.DeleteRun(ctx, runID)
}

func (s *VerifyService) removeActiveRun(runID int64) {
	s.mu.Lock()
	delete(s.activeRuns, runID)
	s.mu.Unlock()
}

func (s *VerifyService) executeRun(
	ctx context.Context,
	handle *activeRunHandle,
	resolved *ResolvedTarget,
	suite ProbeSuite,
	models []string,
	concurrency int,
) {
	defer s.wg.Done()
	defer handle.cancel()
	defer func() {
		s.removeActiveRun(handle.run.ID)
		close(handle.done)
	}()

	finalize := func(status RunStatus, errMsg string) {
		handle.mu.Lock()
		defer handle.mu.Unlock()
		if handle.finished {
			return
		}
		now := s.currentTime()
		handle.run.Status = status
		handle.run.ErrorMessage = redactSecrets(errMsg, resolved.Target)
		handle.run.FinishedAt = &now
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), verifyCleanupTimeout)
		defer cleanupCancel()
		_ = s.store.UpdateRunProgress(cleanupCtx, handle.run)
		handle.finished = true
	}

	handle.mu.Lock()
	if handle.cancelled.Load() || ctx.Err() != nil {
		handle.mu.Unlock()
		finalize(RunStatusCancelled, "run cancelled")
		return
	}
	startedAt := s.currentTime()
	handle.run.Status = RunStatusRunning
	handle.run.StartedAt = &startedAt
	startErr := s.store.UpdateRunProgress(ctx, handle.run)
	handle.mu.Unlock()
	if startErr != nil {
		if handle.cancelled.Load() || ctx.Err() != nil {
			finalize(RunStatusCancelled, "run cancelled")
		} else {
			finalize(RunStatusFailed, startErr.Error())
		}
		return
	}

	baselines, err := s.store.ListBaselines(ctx, BaselineFilter{
		Protocol: resolved.Target.Protocol,
		SuiteID:  suite.ID,
		Status:   StatusActive,
	})
	if err != nil {
		if handle.cancelled.Load() || ctx.Err() != nil {
			finalize(RunStatusCancelled, "run cancelled")
		} else {
			finalize(RunStatusFailed, fmt.Sprintf("load baselines: %v", err))
		}
		return
	}

	familyMaps, err := s.store.ListFamilyMaps(ctx)
	if err != nil {
		if handle.cancelled.Load() || ctx.Err() != nil {
			finalize(RunStatusCancelled, "run cancelled")
		} else {
			finalize(RunStatusFailed, fmt.Sprintf("load family maps: %v", err))
		}
		return
	}

	workerCount := concurrency
	if workerCount > len(models) {
		workerCount = len(models)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	var nextIdx atomic.Int64
	var errMu sync.Mutex
	var persistErr error
	recordPersistErr := func(err error) {
		errMu.Lock()
		if persistErr == nil {
			persistErr = err
		}
		errMu.Unlock()
		handle.cancel()
	}

	var workerWG sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for {
				if ctx.Err() != nil || handle.cancelled.Load() {
					return
				}
				idx := int(nextIdx.Add(1) - 1)
				if idx >= len(models) {
					return
				}
				if ctx.Err() != nil || handle.cancelled.Load() {
					return
				}

				claimedModel := models[idx]
				upstreamModel := s.resolver.MapAccountModel(resolved, claimedModel)
				if upstreamModel == "" {
					upstreamModel = claimedModel
				}

				var item RunItem
				if modelContainsCredentials(upstreamModel, resolved.Target) {
					item = RunItem{
						RunID:         handle.run.ID,
						ClaimedModel:  redactExactSecrets(claimedModel, resolved.Target),
						UpstreamModel: redactedSecretPlaceholder,
						Verdict:       VerdictError,
						ErrorCode:     errorCodeInvalidInput,
						ErrorMessage:  "upstream model mapping contains credentials and was rejected",
						TopCandidates: []CandidateScore{},
						Evidence:      []ProbeEvidence{},
						CheckedAt:     s.currentTime(),
					}
				} else {
					out := s.orchestrator.VerifyModel(ctx, VerifyModelInput{
						Target:        resolved.Target,
						ClaimedModel:  claimedModel,
						UpstreamModel: upstreamModel,
						Suite:         suite,
						Baselines:     baselines,
						FamilyMaps:    familyMaps,
						Now:           s.currentTime(),
					})
					item = out.ToRunItem(handle.run.ID)
				}
				item = sanitizeRunItemSecrets(item, resolved.Target)

				handle.mu.Lock()
				if handle.cancelled.Load() || ctx.Err() != nil || handle.finished {
					handle.mu.Unlock()
					return
				}
				if _, insErr := s.store.InsertRunItem(ctx, item); insErr != nil {
					if !(handle.cancelled.Load() || ctx.Err() != nil) {
						recordPersistErr(fmt.Errorf("insert run item for %s: %w", item.ClaimedModel, insErr))
					}
					handle.mu.Unlock()
					return
				}
				handle.run.CompletedModels++
				applyItemToSummary(&handle.run.Summary, item)
				if updErr := s.store.UpdateRunProgress(ctx, handle.run); updErr != nil {
					if !(handle.cancelled.Load() || ctx.Err() != nil) {
						recordPersistErr(fmt.Errorf("update run progress: %w", updErr))
					}
					handle.mu.Unlock()
					return
				}
				handle.mu.Unlock()
			}
		}()
	}

	workerWG.Wait()

	errMu.Lock()
	finalPersistErr := persistErr
	errMu.Unlock()

	switch {
	case finalPersistErr != nil:
		finalize(RunStatusFailed, finalPersistErr.Error())
	case handle.cancelled.Load() || ctx.Err() != nil:
		finalize(RunStatusCancelled, "run cancelled")
	default:
		finalize(RunStatusCompleted, "")
	}
}

func (s *VerifyService) resolveVerifySuite(ctx context.Context, suiteID int64) (*ProbeSuite, error) {
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
		return nil, infraerrors.BadRequest("MODELFP_SUITE_ARCHIVED", "cannot verify models using an archived probe suite")
	}
	if len(suite.Probes) == 0 {
		return nil, infraerrors.BadRequest(
			"MODELFP_NO_APPLICABLE_PROBES",
			fmt.Sprintf("suite %s/%s contains no probes", suite.SuiteKey, suite.Version),
		)
	}
	return suite, nil
}

func resolveTargetInput(ctx context.Context, resolver *TargetResolver, spec targetInputSpec) (*ResolvedTarget, error) {
	if resolver == nil {
		return nil, errors.New("target resolver is not configured")
	}

	src := TargetSource(strings.ToLower(strings.TrimSpace(string(spec.TargetSource))))
	if src == "" {
		hasAccount := spec.AccountID != nil && *spec.AccountID > 0
		hasAdHoc := spec.AdHoc != nil || strings.TrimSpace(spec.BaseURL) != "" || strings.TrimSpace(spec.APIKey) != ""
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
		if spec.AccountID == nil || *spec.AccountID <= 0 {
			return nil, infraerrors.BadRequest("MODELFP_INVALID_ACCOUNT_ID", "account_id is required for account target")
		}
		protoOverride := spec.Protocol
		if protoOverride == "" && spec.AdHoc != nil {
			protoOverride = spec.AdHoc.Protocol
		}
		return resolver.ResolveAccount(ctx, *spec.AccountID, protoOverride)
	case TargetSourceAdHoc:
		input := AdHocTargetInput{
			Protocol:     spec.Protocol,
			BaseURL:      spec.BaseURL,
			APIKey:       spec.APIKey,
			AuthMode:     spec.AuthMode,
			ProxyID:      spec.ProxyID,
			ExtraHeaders: spec.ExtraHeaders,
		}
		if spec.AdHoc != nil {
			input = *spec.AdHoc
			if input.Protocol == "" {
				input.Protocol = spec.Protocol
			}
		}
		return resolver.ResolveAdHoc(ctx, input)
	default:
		return nil, infraerrors.BadRequest("MODELFP_INVALID_TARGET_SOURCE", fmt.Sprintf("unsupported target_source %q", spec.TargetSource))
	}
}

func normalizeVerifyModels(raw []string) ([]string, error) {
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
	if len(out) > maxVerifyModels {
		return nil, infraerrors.BadRequest(
			"MODELFP_TOO_MANY_MODELS",
			fmt.Sprintf("verification run supports at most %d models per batch", maxVerifyModels),
		)
	}
	return out, nil
}

func normalizeVerifyConcurrency(concurrency int) int {
	if concurrency == 0 {
		return defaultVerifyConcurrency
	}
	if concurrency < minVerifyConcurrency {
		return minVerifyConcurrency
	}
	if concurrency > maxVerifyConcurrency {
		return maxVerifyConcurrency
	}
	return concurrency
}

func applyItemToSummary(summary *RunSummary, item RunItem) {
	if summary == nil {
		return
	}
	switch item.Verdict {
	case VerdictMatch:
		summary.Match++
	case VerdictSuspect:
		summary.Suspect++
	case VerdictMismatch:
		summary.Mismatch++
	case VerdictUnverified:
		summary.Unverified++
	case VerdictError:
		summary.Error++
	}
	if item.PromptInjectionSuspected {
		summary.InjectionSuspected++
	}
}

func sanitizeRunItemSecrets(item RunItem, target ProbeTarget) RunItem {
	item.ClaimedModel = redactExactSecrets(item.ClaimedModel, target)
	item.UpstreamModel = redactExactSecrets(item.UpstreamModel, target)
	item.CanonicalModel = redactExactSecrets(item.CanonicalModel, target)
	item.ErrorCode = redactExactSecrets(item.ErrorCode, target)
	item.ErrorMessage = redactSecrets(item.ErrorMessage, target)

	if len(item.TopCandidates) == 0 {
		item.TopCandidates = []CandidateScore{}
	} else {
		cleanCandidates := make([]CandidateScore, len(item.TopCandidates))
		for i, cand := range item.TopCandidates {
			cand.CanonicalModel = redactExactSecrets(cand.CanonicalModel, target)
			cleanCandidates[i] = cand
		}
		item.TopCandidates = cleanCandidates
	}

	if len(item.Evidence) == 0 {
		item.Evidence = []ProbeEvidence{}
	} else {
		cleanEvidence := make([]ProbeEvidence, len(item.Evidence))
		for i, ev := range item.Evidence {
			ev.ProbeID = redactExactSecrets(ev.ProbeID, target)
			ev.ResponseModel = redactExactSecrets(ev.ResponseModel, target)
			ev.SystemFingerprint = redactExactSecrets(ev.SystemFingerprint, target)
			ev.ObservedText = redactExactSecrets(ev.ObservedText, target)
			ev.BaselineSampleText = redactExactSecrets(ev.BaselineSampleText, target)
			ev.ErrorCode = redactExactSecrets(ev.ErrorCode, target)
			ev.ErrorMessage = redactSecretsWithStatus(ev.ErrorMessage, ev.HTTPStatus, target)
			ev.ObservedTopTokens = sanitizeTokenProbSlice(ev.ObservedTopTokens, target)
			ev.BaselineTopTokens = sanitizeTokenProbSlice(ev.BaselineTopTokens, target)
			cleanEvidence[i] = ev
		}
		item.Evidence = cleanEvidence
	}

	return item
}

func sanitizeTokenProbSlice(tokens []TokenProb, target ProbeTarget) []TokenProb {
	if len(tokens) == 0 {
		return nil
	}
	out := make([]TokenProb, len(tokens))
	for i, tp := range tokens {
		tp.Token = redactExactSecrets(tp.Token, target)
		out[i] = tp
	}
	return out
}
