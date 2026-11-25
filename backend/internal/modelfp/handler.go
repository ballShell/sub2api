package modelfp

import (
	"context"
	"math"
	"strconv"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

// AdminService defines the service operations required by AdminHandler.
// *Service satisfies this interface.
type AdminService interface {
	DiscoverModels(ctx context.Context, req DiscoverModelsRequest) (*DiscoverModelsResponse, error)
	StartRun(ctx context.Context, req CreateRunRequest, adminID int64) (*RunDetail, error)
	ListRuns(ctx context.Context, page, pageSize int) (*RunPage, error)
	GetRun(ctx context.Context, runID int64) (*RunDetail, error)
	CancelRun(ctx context.Context, runID int64) error
	DeleteRun(ctx context.Context, runID int64) error
	ListBaselines(ctx context.Context, filter BaselineFilter) ([]BaselineView, error)
	StartCaptureJob(ctx context.Context, req CaptureRequest, adminID int64) (*CaptureJob, error)
	GetCaptureJob(ctx context.Context, id int64) (*CaptureJob, error)
	ConfusionMatrix(ctx context.Context, req ConfusionMatrixRequest) (*ConfusionMatrixResult, error)
	UpdateBaseline(ctx context.Context, id int64, req UpdateBaselineRequest) (*BaselineView, error)
	DeleteBaseline(ctx context.Context, id int64) error
	ExportBundle(ctx context.Context, includePrivate bool) (*Bundle, error)
	ImportBundle(ctx context.Context, req ImportBundleRequest) (*ImportBundleResult, error)
	ListSuites(ctx context.Context) ([]ProbeSuite, error)
	CreateSuite(ctx context.Context, req CreateSuiteRequest, adminID int64) (*ProbeSuite, error)
	UpdateSuiteStatus(ctx context.Context, id int64, req UpdateSuiteStatusRequest) (*ProbeSuite, error)
	ListFamilyMaps(ctx context.Context) ([]FamilyMap, error)
	UpsertFamilyMap(ctx context.Context, fm FamilyMap) (*FamilyMap, error)
	DeleteFamilyMap(ctx context.Context, canonicalModel string) error
}

var _ AdminService = (*Service)(nil)

// AdminHandler serves the 20 administrative HTTP endpoints under /api/v1/admin/model-fingerprint.
type AdminHandler struct {
	service AdminService
}

// NewAdminHandler constructs an AdminHandler backed by AdminService.
func NewAdminHandler(service AdminService) *AdminHandler {
	return &AdminHandler{service: service}
}

func (h *AdminHandler) ensureService() (AdminService, error) {
	if h == nil || h.service == nil {
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_UNAVAILABLE", "model fingerprint service is not configured")
	}
	if s, ok := h.service.(*Service); ok && s == nil {
		return nil, infraerrors.ServiceUnavailable("MODELFP_SERVICE_UNAVAILABLE", "model fingerprint service is not configured")
	}
	return h.service, nil
}

// DiscoverModels queries the upstream models listing endpoint for ad-hoc credentials or an existing API-key account.
func (h *AdminHandler) DiscoverModels(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req DiscoverModelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	res, err := svc.DiscoverModels(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

// CreateRun starts an asynchronous batch model verification run.
func (h *AdminHandler) CreateRun(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req CreateRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	res, err := svc.StartRun(c.Request.Context(), req, adminID(c))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

// ListRuns returns a paginated list of verification runs.
func (h *AdminHandler) ListRuns(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	page, err := positiveIntQuery(c, "page", 1, 0)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pageSize, err := positiveIntQuery(c, "page_size", defaultRunPageSize, maxRunPageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if page > math.MaxInt/pageSize {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_PAGINATION", "invalid pagination parameters"))
		return
	}
	res, err := svc.ListRuns(c.Request.Context(), page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

// GetRun returns the run header and per-model verification items.
func (h *AdminHandler) GetRun(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveIDParam(c, "id", "run id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	res, err := svc.GetRun(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

// CancelRun cancels an active verification run.
func (h *AdminHandler) CancelRun(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveIDParam(c, "id", "run id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := svc.CancelRun(c.Request.Context(), id); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"cancelled": true})
}

// DeleteRun cancels any active work for the run and deletes its record.
func (h *AdminHandler) DeleteRun(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveIDParam(c, "id", "run id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := svc.DeleteRun(c.Request.Context(), id); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"deleted": true})
}

// ListBaselines lists baselines matching optional query filters with freshness metadata.
func (h *AdminHandler) ListBaselines(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	filter, err := baselineFilterFromQuery(c)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	views, err := svc.ListBaselines(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if views == nil {
		views = []BaselineView{}
	}
	response.Success(c, views)
}

// StartCapture launches an async multi-round baseline capture job.
func (h *AdminHandler) StartCapture(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req CaptureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	job, err := svc.StartCaptureJob(c.Request.Context(), req, adminID(c))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, job)
}

// GetCaptureJob retrieves the current status and per-model calibration results of a capture job.
func (h *AdminHandler) GetCaptureJob(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	jobID, err := positiveIDParam(c, "job_id", "capture job id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	job, err := svc.GetCaptureJob(c.Request.Context(), jobID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, job)
}

// ConfusionMatrix computes the pairwise distance matrix for a (protocol, suite_id, detector_kind) slice.
func (h *AdminHandler) ConfusionMatrix(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req ConfusionMatrixRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	res, err := svc.ConfusionMatrix(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

// UpdateBaseline updates mutable thresholds, TTL, status, or notes on a baseline.
func (h *AdminHandler) UpdateBaseline(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveIDParam(c, "id", "baseline id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req UpdateBaselineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	updated, err := svc.UpdateBaseline(c.Request.Context(), id, req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, updated)
}

// DeleteBaseline deletes a baseline record by ID.
func (h *AdminHandler) DeleteBaseline(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveIDParam(c, "id", "baseline id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := svc.DeleteBaseline(c.Request.Context(), id); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"deleted": true})
}

// ExportBaselines exports suites, family maps, and active baselines protected by a SHA-256 checksum.
func (h *AdminHandler) ExportBaselines(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	includePrivate := false
	if raw := strings.TrimSpace(c.Query("include_private")); raw != "" {
		parsed, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_INCLUDE_PRIVATE", "include_private must be a boolean"))
			return
		}
		includePrivate = parsed
	}
	bundle, err := svc.ExportBundle(c.Request.Context(), includePrivate)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, bundle)
}

// ImportBaselines verifies bundle SHA-256 and imports suites, family maps, and baselines.
func (h *AdminHandler) ImportBaselines(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req ImportBundleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	res, err := svc.ImportBundle(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

// ListSuites lists all probe suites.
func (h *AdminHandler) ListSuites(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	suites, err := svc.ListSuites(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if suites == nil {
		suites = []ProbeSuite{}
	}
	response.Success(c, suites)
}

// CreateSuite creates a new immutable probe suite version.
func (h *AdminHandler) CreateSuite(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req CreateSuiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	suite, err := svc.CreateSuite(c.Request.Context(), req, adminID(c))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, suite)
}

// UpdateSuiteStatus updates active/archived status and default flag on a probe suite.
func (h *AdminHandler) UpdateSuiteStatus(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveIDParam(c, "id", "suite id must be positive")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var req UpdateSuiteStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	if strings.TrimSpace(string(req.Status)) == "" && req.IsDefault == nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "status or is_default is required"))
		return
	}
	suite, err := svc.UpdateSuiteStatus(c.Request.Context(), id, req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, suite)
}

// ListFamilyMaps lists all model family/alias mappings.
func (h *AdminHandler) ListFamilyMaps(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	families, err := svc.ListFamilyMaps(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if families == nil {
		families = []FamilyMap{}
	}
	response.Success(c, families)
}

// UpsertFamilyMap creates or updates a model family/alias mapping.
func (h *AdminHandler) UpsertFamilyMap(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pathModel := strings.TrimSpace(c.Param("canonical_model"))
	if pathModel == "" {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_CANONICAL_MODEL", "canonical_model is required"))
		return
	}
	var req FamilyMap
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_REQUEST", "invalid request payload"))
		return
	}
	bodyModel := strings.TrimSpace(req.CanonicalModel)
	if bodyModel != "" && bodyModel != pathModel {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_CANONICAL_MODEL", "canonical_model in path does not match request body"))
		return
	}
	req.CanonicalModel = pathModel
	saved, err := svc.UpsertFamilyMap(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, saved)
}

// DeleteFamilyMap deletes a model family mapping by canonical_model.
func (h *AdminHandler) DeleteFamilyMap(c *gin.Context) {
	svc, err := h.ensureService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pathModel := strings.TrimSpace(c.Param("canonical_model"))
	if pathModel == "" {
		response.ErrorFrom(c, infraerrors.BadRequest("MODELFP_INVALID_CANONICAL_MODEL", "canonical_model is required"))
		return
	}
	if err := svc.DeleteFamilyMap(c.Request.Context(), pathModel); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"deleted": true})
}

func adminID(c *gin.Context) int64 {
	if c == nil {
		return 0
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		return 0
	}
	return subject.UserID
}

func positiveIDParam(c *gin.Context, key, msg string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param(key)), 10, 64)
	if err != nil || id <= 0 {
		return 0, infraerrors.BadRequest("MODELFP_INVALID_ID", msg)
	}
	return id, nil
}

func positiveIntQuery(c *gin.Context, key string, defaultValue, maxValue int) (int, error) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 || (maxValue > 0 && parsed > maxValue) {
		return 0, infraerrors.BadRequest("MODELFP_INVALID_PAGINATION", "invalid pagination parameters")
	}
	return parsed, nil
}

func baselineFilterFromQuery(c *gin.Context) (BaselineFilter, error) {
	proto, err := normalizeSupportedProtocol(Protocol(c.Query("protocol")), true)
	if err != nil {
		return BaselineFilter{}, err
	}

	var suiteID int64
	if rawSuite := strings.TrimSpace(c.Query("suite_id")); rawSuite != "" {
		parsed, parseErr := strconv.ParseInt(rawSuite, 10, 64)
		if parseErr != nil || parsed <= 0 {
			return BaselineFilter{}, infraerrors.BadRequest("MODELFP_INVALID_ID", "suite_id must be positive")
		}
		suiteID = parsed
	}

	var detectorKind DetectorKind
	if rawKind := strings.ToLower(strings.TrimSpace(c.Query("detector_kind"))); rawKind != "" {
		kind := DetectorKind(rawKind)
		if kind != DetectorLogprobs && kind != DetectorBehavior {
			return BaselineFilter{}, infraerrors.BadRequest("MODELFP_INVALID_DETECTOR_KIND", "unsupported detector_kind filter")
		}
		detectorKind = kind
	}

	var status Status
	if rawStatus := strings.ToLower(strings.TrimSpace(c.Query("status"))); rawStatus != "" {
		st := Status(rawStatus)
		if st != StatusActive && st != StatusArchived {
			return BaselineFilter{}, infraerrors.BadRequest("MODELFP_INVALID_STATUS", "unsupported status filter")
		}
		status = st
	}

	var visibility Visibility
	if rawVis := strings.ToLower(strings.TrimSpace(c.Query("visibility"))); rawVis != "" {
		vis := Visibility(rawVis)
		if vis != VisibilityPublic && vis != VisibilityPrivate {
			return BaselineFilter{}, infraerrors.BadRequest("MODELFP_INVALID_VISIBILITY", "unsupported visibility filter")
		}
		visibility = vis
	}

	return BaselineFilter{
		Protocol:       proto,
		SuiteID:        suiteID,
		CanonicalModel: strings.TrimSpace(c.Query("canonical_model")),
		DetectorKind:   detectorKind,
		Status:         status,
		Visibility:     visibility,
	}, nil
}
