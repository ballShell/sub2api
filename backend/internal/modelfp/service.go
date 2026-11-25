package modelfp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const defaultServiceShutdownTimeout = 10 * time.Second

// Service is the lifecycle and operation facade for the modelfp subsystem.
// It owns schema initialization, seed loading, stale job recovery, model discovery,
// batch verification runs, and delegated baseline/suite/family operations.
type Service struct {
	db        *sql.DB
	store     Store
	client    ProbeClient
	resolver  *TargetResolver
	baselines *BaselineService
	verify    *VerifyService

	startOnce           sync.Once
	lifecycleMu         sync.Mutex
	initErr             error
	ready               atomic.Bool
	stopped             atomic.Bool
	shutdownTimeout     time.Duration
	staleJobGracePeriod time.Duration
	now                 func() time.Time
}

// NewService constructs the modelfp Service facade injected into cmd/server.Application.
func NewService(
	db *sql.DB,
	store Store,
	client ProbeClient,
	resolver *TargetResolver,
	orchestrator *Orchestrator,
	baselines *BaselineService,
) *Service {
	return &Service{
		db:                  db,
		store:               store,
		client:              client,
		resolver:            resolver,
		baselines:           baselines,
		verify:              NewVerifyService(store, resolver, orchestrator),
		shutdownTimeout:     defaultServiceShutdownTimeout,
		staleJobGracePeriod: defaultStaleJobGracePeriod,
		now:                 func() time.Time { return time.Now().UTC() },
	}
}

// Start runs one-time idempotent schema initialization (when db is non-nil),
// seed bootstrap, and stale running/queued job recovery, marking the service ready on success.
// If startup fails, ready stays false so requests fail fast with HTTP 503.
func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("modelfp service is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.startOnce.Do(func() {
		err := s.init(ctx)
		s.lifecycleMu.Lock()
		s.initErr = err
		if err == nil && !s.stopped.Load() {
			s.ready.Store(true)
		}
		s.lifecycleMu.Unlock()
	})

	s.lifecycleMu.Lock()
	err := s.initErr
	s.lifecycleMu.Unlock()
	return err
}

func (s *Service) init(ctx context.Context) error {
	if s.store == nil {
		return errors.New("modelfp service store is not configured")
	}
	if s.stopped.Load() {
		return infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "model fingerprint service is shutting down")
	}
	if s.db != nil {
		if err := EnsureSchema(ctx, s.db); err != nil {
			return fmt.Errorf("ensure modelfp schema: %w", err)
		}
	}
	if s.baselines != nil {
		if err := s.baselines.EnsureSeeds(ctx); err != nil {
			return fmt.Errorf("ensure modelfp seeds: %w", err)
		}
	}
	grace := s.staleJobGracePeriod
	if grace < 0 {
		grace = 0
	}
	staleBefore := s.currentTime().Add(-grace)
	if err := s.store.MarkStaleRunningJobsFailedBefore(ctx, staleBefore, defaultRestartReason); err != nil {
		return fmt.Errorf("mark stale running jobs failed: %w", err)
	}
	return nil
}

func (s *Service) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// Stop cancels all active verification runs and baseline capture jobs and waits
// up to the bounded shutdown timeout for background goroutines to exit.
func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	s.stopped.Store(true)
	s.ready.Store(false)
	s.lifecycleMu.Unlock()

	timeout := s.shutdownTimeout
	if timeout <= 0 {
		timeout = defaultServiceShutdownTimeout
	}

	var wg sync.WaitGroup
	if s.verify != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.verify.Stop()
		}()
	}
	if s.baselines != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.baselines.Stop()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("modelfp service shutdown timed out after %s: %w", timeout, context.DeadlineExceeded)
	}
}

// IsReady reports whether Start completed cleanly and the service has not stopped.
func (s *Service) IsReady() bool {
	return s != nil && s.ready.Load() && !s.stopped.Load()
}

// Baselines returns the underlying BaselineService instance.
func (s *Service) Baselines() *BaselineService {
	if s == nil {
		return nil
	}
	return s.baselines
}

func (s *Service) ensureReady() error {
	if s == nil {
		return infraerrors.ServiceUnavailable("MODELFP_SERVICE_UNAVAILABLE", "model fingerprint service is not configured")
	}
	if s.stopped.Load() {
		return infraerrors.ServiceUnavailable("MODELFP_SERVICE_STOPPED", "model fingerprint service is shutting down")
	}
	if !s.ready.Load() {
		s.lifecycleMu.Lock()
		initErr := s.initErr
		s.lifecycleMu.Unlock()
		if initErr != nil {
			return infraerrors.ServiceUnavailable(
				"MODELFP_SERVICE_DEGRADED",
				"model fingerprint service is unavailable due to startup initialization failure",
			).WithCause(initErr)
		}
		return infraerrors.ServiceUnavailable(
			"MODELFP_SERVICE_NOT_READY",
			"model fingerprint service is not ready",
		)
	}
	return nil
}

func (s *Service) ensureBaselinesReady() error {
	if err := s.ensureReady(); err != nil {
		return err
	}
	if s.baselines == nil {
		return errors.New("baseline service is not configured")
	}
	return nil
}

// DiscoverModels resolves target credentials (ad-hoc or existing API-key account) and queries
// the upstream models listing endpoint while returning secret-free target metadata.
func (s *Service) DiscoverModels(ctx context.Context, req DiscoverModelsRequest) (*DiscoverModelsResponse, error) {
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	if s.client == nil || s.resolver == nil {
		return nil, errors.New("model discovery dependencies are not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	resolved, err := resolveTargetInput(ctx, s.resolver, targetInputSpec(req))
	if err != nil {
		return nil, err
	}

	discovered, err := s.client.DiscoverModels(ctx, resolved.Target)
	if err != nil {
		if errors.Is(err, ErrSSRFBlocked) {
			return nil, ErrSSRFBlocked.WithCause(redactError(err, resolved.Target))
		}
		var appErr *infraerrors.ApplicationError
		if errors.As(err, &appErr) {
			return nil, infraerrors.New(int(appErr.Code), appErr.Reason, redactSecrets(appErr.Message, resolved.Target))
		}
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		safeErr := redactError(err, resolved.Target)
		safeMsg := redactSecrets(err.Error(), resolved.Target)
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, infraerrors.GatewayTimeout("MODELFP_DISCOVERY_TIMEOUT", safeMsg).WithCause(safeErr)
		}
		return nil, infraerrors.New(http.StatusBadGateway, "MODELFP_DISCOVERY_FAILED", safeMsg).WithCause(safeErr)
	}

	cleanDiscovered := sanitizeDiscoveredModelIDs(discovered, resolved.Target)
	cleanDefaults := sanitizeDiscoveredModelIDs(resolved.DefaultModels, resolved.Target)

	var defaultModels []string
	if len(cleanDefaults) > 0 {
		defaultModels = cleanDefaults
	}

	return &DiscoverModelsResponse{
		TargetSource:  resolved.Target.Source,
		AccountID:     resolved.Target.AccountID,
		TargetLabel:   truncateRunes(redactSecrets(resolved.TargetLabel, resolved.Target), maxRunLabelChars),
		Protocol:      resolved.Target.Protocol,
		Models:        cleanDiscovered,
		DefaultModels: defaultModels,
	}, nil
}

// StartRun delegates batch verification run creation to VerifyService after readiness verification.
func (s *Service) StartRun(ctx context.Context, req CreateRunRequest, adminID int64) (*RunDetail, error) {
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	return s.verify.StartRun(ctx, req, adminID)
}

// GetRun retrieves a Run header and its RunItems.
func (s *Service) GetRun(ctx context.Context, runID int64) (*RunDetail, error) {
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	return s.verify.GetRun(ctx, runID)
}

// ListRuns retrieves a paginated list of verification runs.
func (s *Service) ListRuns(ctx context.Context, page, pageSize int) (*RunPage, error) {
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	return s.verify.ListRuns(ctx, page, pageSize)
}

// CancelRun cancels an active verification run.
func (s *Service) CancelRun(ctx context.Context, runID int64) error {
	if err := s.ensureReady(); err != nil {
		return err
	}
	return s.verify.CancelRun(ctx, runID)
}

// DeleteRun cancels any active work for runID and deletes the run record.
func (s *Service) DeleteRun(ctx context.Context, runID int64) error {
	if err := s.ensureReady(); err != nil {
		return err
	}
	return s.verify.DeleteRun(ctx, runID)
}

// ListBaselines lists baselines matching filter with freshness metadata.
func (s *Service) ListBaselines(ctx context.Context, filter BaselineFilter) ([]BaselineView, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.ListBaselines(ctx, filter)
}

// UpdateBaseline updates mutable fields on an existing baseline.
func (s *Service) UpdateBaseline(ctx context.Context, id int64, req UpdateBaselineRequest) (*BaselineView, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.UpdateBaseline(ctx, id, req)
}

// DeleteBaseline deletes a baseline by ID.
func (s *Service) DeleteBaseline(ctx context.Context, id int64) error {
	if err := s.ensureBaselinesReady(); err != nil {
		return err
	}
	return s.baselines.DeleteBaseline(ctx, id)
}

// StartCaptureJob launches an async multi-round baseline capture job.
func (s *Service) StartCaptureJob(ctx context.Context, req CaptureRequest, adminID int64) (*CaptureJob, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.StartCaptureJob(ctx, req, adminID)
}

// GetCaptureJob retrieves the current status and results of a capture job.
func (s *Service) GetCaptureJob(ctx context.Context, id int64) (*CaptureJob, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.GetCaptureJob(ctx, id)
}

// ConfusionMatrix computes pairwise baseline distances for a (protocol, suite_id, detector_kind) slice.
func (s *Service) ConfusionMatrix(ctx context.Context, req ConfusionMatrixRequest) (*ConfusionMatrixResult, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.ConfusionMatrix(ctx, req)
}

// ExportBundle exports suites, family maps, and active baselines protected by SHA-256.
func (s *Service) ExportBundle(ctx context.Context, includePrivate bool) (*Bundle, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.ExportBundle(ctx, includePrivate)
}

// ImportBundle validates SHA-256 and imports suites, family maps, and baselines.
func (s *Service) ImportBundle(ctx context.Context, req ImportBundleRequest) (*ImportBundleResult, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.ImportBundle(ctx, req)
}

// ListSuites lists all probe suites.
func (s *Service) ListSuites(ctx context.Context) ([]ProbeSuite, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.ListSuites(ctx)
}

// CreateSuite creates a new immutable probe suite version.
func (s *Service) CreateSuite(ctx context.Context, req CreateSuiteRequest, adminID int64) (*ProbeSuite, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.CreateSuite(ctx, req, adminID)
}

// UpdateSuiteStatus updates status and default flag on a probe suite.
func (s *Service) UpdateSuiteStatus(ctx context.Context, id int64, req UpdateSuiteStatusRequest) (*ProbeSuite, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.UpdateSuiteStatus(ctx, id, req)
}

// ListFamilyMaps lists all model family/alias mappings.
func (s *Service) ListFamilyMaps(ctx context.Context) ([]FamilyMap, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.ListFamilyMaps(ctx)
}

// UpsertFamilyMap creates or updates a model family/alias mapping.
func (s *Service) UpsertFamilyMap(ctx context.Context, fm FamilyMap) (*FamilyMap, error) {
	if err := s.ensureBaselinesReady(); err != nil {
		return nil, err
	}
	return s.baselines.UpsertFamilyMap(ctx, fm)
}

// DeleteFamilyMap deletes a model family mapping by canonical model.
func (s *Service) DeleteFamilyMap(ctx context.Context, canonicalModel string) error {
	if err := s.ensureBaselinesReady(); err != nil {
		return err
	}
	return s.baselines.DeleteFamilyMap(ctx, canonicalModel)
}

func sanitizeDiscoveredModelIDs(raw []string, target ProbeTarget) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" || modelContainsCredentials(trimmed, target) {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
