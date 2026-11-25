package modelfp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/modelfp/seeds"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// Protocol identifies one of the four supported upstream LLM API wire protocols.
type Protocol string

const (
	ProtocolOpenAIChat      Protocol = "openai_chat"
	ProtocolOpenAIResponses Protocol = "openai_responses"
	ProtocolAnthropic       Protocol = "anthropic"
	ProtocolGemini          Protocol = "gemini"
)

// DetectorKind identifies a fingerprint detection engine.
type DetectorKind string

const (
	DetectorLogprobs DetectorKind = "logprobs"
	DetectorBehavior DetectorKind = "behavior"
)

// Verdict represents the outcome of verifying a claimed model against baselines.
type Verdict string

const (
	VerdictMatch      Verdict = "match"
	VerdictSuspect    Verdict = "suspect"
	VerdictMismatch   Verdict = "mismatch"
	VerdictUnverified Verdict = "unverified"
	VerdictError      Verdict = "error"
)

// Visibility distinguishes public suites from private canary suites.
type Visibility string

const (
	VisibilityPublic  Visibility = "public"
	VisibilityPrivate Visibility = "private"
)

// Status represents lifecycle state for suites and baselines.
type Status string

const (
	StatusActive   Status = "active"
	StatusArchived Status = "archived"
)

// Freshness indicates whether a baseline is within its configured TTL window.
type Freshness string

const (
	FreshnessFresh Freshness = "fresh"
	FreshnessStale Freshness = "stale"
)

// TargetSource specifies whether verification targets an ad-hoc upstream or an existing Sub2API account.
type TargetSource string

const (
	TargetSourceAdHoc   TargetSource = "adhoc"
	TargetSourceAccount TargetSource = "account"
)

// SourceType records the provenance of a baseline fingerprint.
type SourceType string

const (
	SourceOfficialDirect SourceType = "official_direct"
	SourceTrustedCloud   SourceType = "trusted_cloud"
	SourceCrossVerified  SourceType = "cross_verified"
	SourceCommunitySeed  SourceType = "community_seed"
)

// RunStatus represents async batch run and capture job lifecycle states.
type RunStatus string

const (
	RunStatusQueued    RunStatus = "queued"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusCancelled RunStatus = "cancelled"
	RunStatusFailed    RunStatus = "failed"
)

const (
	DefaultExpectedMaxPromptTokens = 500
	DefaultOtherToken              = "<OTHER>"
	DefaultBundleSchemaVersion     = "v1"
)

var (
	// ErrUnsupportedAccountType indicates a non-API-key or unsupported platform account was selected.
	ErrUnsupportedAccountType = infraerrors.BadRequest(
		"MODELFP_UNSUPPORTED_ACCOUNT_TYPE",
		"only standalone API key accounts on supported REST platforms are supported",
	)
	// ErrInvalidBundleChecksum indicates bundle SHA-256 verification failed during import.
	ErrInvalidBundleChecksum = infraerrors.BadRequest(
		"MODELFP_INVALID_BUNDLE_CHECKSUM",
		"bundle sha256 checksum verification failed",
	)
	// ErrSuiteImmutable indicates an existing suite version cannot be mutated in place.
	ErrSuiteImmutable = infraerrors.Conflict(
		"MODELFP_SUITE_IMMUTABLE",
		"probe suite version already exists and is immutable",
	)
	// ErrNotFound indicates the requested modelfp entity does not exist.
	ErrNotFound = infraerrors.NotFound(
		"MODELFP_NOT_FOUND",
		"model fingerprint resource not found",
	)
)

// ProbeDefinition describes a single probe within a ProbeSuite.
type ProbeDefinition struct {
	ID                      string       `json:"id"`
	Kind                    DetectorKind `json:"kind"`
	Prompt                  string       `json:"prompt"`
	SystemPrompt            string       `json:"system_prompt,omitempty"`
	MaxTokens               int          `json:"max_tokens"`
	Temperature             float64      `json:"temperature"`
	TopLogprobs             int          `json:"top_logprobs,omitempty"`
	Seed                    *int         `json:"seed,omitempty"`
	Weight                  float64      `json:"weight"`
	ExpectedMaxPromptTokens int          `json:"expected_max_prompt_tokens"`
	ExpectedFormat          string       `json:"expected_format,omitempty"`
	Description             string       `json:"description,omitempty"`
}

// ProbeSuite represents a versioned collection of logprobs and behavior probes.
type ProbeSuite struct {
	ID          int64             `json:"id"`
	SuiteKey    string            `json:"suite_key"`
	Version     string            `json:"version"`
	Name        string            `json:"name"`
	Visibility  Visibility        `json:"visibility"`
	Status      Status            `json:"status"`
	IsDefault   bool              `json:"is_default"`
	Probes      []ProbeDefinition `json:"probes"`
	ContentHash string            `json:"content_hash"`
	CreatedBy   int64             `json:"created_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// TokenProb holds a single token string (preserving byte/whitespace differences) and probability.
type TokenProb struct {
	Token   string  `json:"token"`
	Prob    float64 `json:"prob"`
	Logprob float64 `json:"logprob,omitempty"`
}

// LogprobsProbeSignature stores the normalized first-token distribution for one logprobs probe.
type LogprobsProbeSignature struct {
	ProbeID      string             `json:"probe_id"`
	Distribution map[string]float64 `json:"distribution"`
	TopTokens    []TokenProb        `json:"top_tokens,omitempty"`
	SampleCount  int                `json:"sample_count,omitempty"`
}

// LogprobsSignature stores per-probe first-token distributions for a model baseline.
type LogprobsSignature struct {
	Probes map[string]LogprobsProbeSignature `json:"probes"`
}

// BehaviorProbeSignature stores observed responses and format metadata for one behavior probe.
type BehaviorProbeSignature struct {
	ProbeID         string   `json:"probe_id"`
	Samples         []string `json:"samples"`
	ExpectedFormat  string   `json:"expected_format,omitempty"`
	FormatMatchRate float64  `json:"format_match_rate,omitempty"`
}

// BehaviorSignature stores multi-probe behavioral responses and protocol metadata for a model baseline.
type BehaviorSignature struct {
	Probes             map[string]BehaviorProbeSignature `json:"probes"`
	ResponseModels     []string                          `json:"response_models,omitempty"`
	SystemFingerprints []string                          `json:"system_fingerprints,omitempty"`
	HasReasoningField  *bool                             `json:"has_reasoning_field,omitempty"`
}

// Baseline represents a calibrated fingerprint record in modelfp_baselines.
type Baseline struct {
	ID                int64              `json:"id"`
	CanonicalModel    string             `json:"canonical_model"`
	Protocol          Protocol           `json:"protocol"`
	SuiteID           int64              `json:"suite_id"`
	SuiteKey          string             `json:"suite_key,omitempty"`
	SuiteVersion      string             `json:"suite_version,omitempty"`
	DetectorKind      DetectorKind       `json:"detector_kind"`
	SourceType        SourceType         `json:"source_type"`
	SourceLabel       string             `json:"source_label"`
	UpstreamSnapshot  string             `json:"upstream_snapshot,omitempty"`
	SampleCount       int                `json:"sample_count"`
	Logprobs          *LogprobsSignature `json:"logprobs,omitempty"`
	Behavior          *BehaviorSignature `json:"behavior,omitempty"`
	SelfDivergenceP95 float64            `json:"self_divergence_p95"`
	MatchThreshold    float64            `json:"match_threshold"`
	SuspectThreshold  float64            `json:"suspect_threshold"`
	TTLDays           int                `json:"ttl_days"`
	Status            Status             `json:"status"`
	Notes             string             `json:"notes,omitempty"`
	CollectedAt       time.Time          `json:"collected_at"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

// BaselineView enriches Baseline with computed freshness metadata for API queries.
type BaselineView struct {
	Baseline
	Freshness Freshness `json:"freshness"`
	ExpiresAt time.Time `json:"expires_at"`
}

// FamilyMap maps model aliases to canonical identifiers and nearby downgrade confusion peers.
type FamilyMap struct {
	CanonicalModel string    `json:"canonical_model"`
	Family         string    `json:"family"`
	Aliases        []string  `json:"aliases"`
	ConfusionPeers []string  `json:"confusion_peers"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

// ProbeTarget carries resolved endpoint credentials and transport configuration.
// Sensitive fields are marked json:"-" so secrets can never be serialized accidentally.
type ProbeTarget struct {
	Source       TargetSource      `json:"source,omitempty"`
	AccountID    *int64            `json:"account_id,omitempty"`
	Protocol     Protocol          `json:"protocol"`
	BaseURL      string            `json:"base_url"`
	APIKey       string            `json:"-"`
	AuthMode     string            `json:"auth_mode,omitempty"`
	ProxyID      *int64            `json:"proxy_id,omitempty"`
	ProxyURL     string            `json:"-"`
	ExtraHeaders map[string]string `json:"-"`
}

// CandidateScore represents a ranked candidate baseline match for a verified model.
type CandidateScore struct {
	CanonicalModel   string    `json:"canonical_model"`
	BaselineID       int64     `json:"baseline_id,omitempty"`
	Distance         float64   `json:"distance"`
	Similarity       float64   `json:"similarity"`
	MatchThreshold   float64   `json:"match_threshold,omitempty"`
	SuspectThreshold float64   `json:"suspect_threshold,omitempty"`
	WithinMatch      bool      `json:"within_match"`
	IsConfusionPeer  bool      `json:"is_confusion_peer,omitempty"`
	Freshness        Freshness `json:"freshness,omitempty"`
}

// ProbeEvidence records per-probe execution telemetry without storing private prompts or credentials.
type ProbeEvidence struct {
	ProbeID                  string       `json:"probe_id"`
	DetectorKind             DetectorKind `json:"detector_kind"`
	Distance                 float64      `json:"distance"`
	Weight                   float64      `json:"weight"`
	ResponseModel            string       `json:"response_model,omitempty"`
	SystemFingerprint        string       `json:"system_fingerprint,omitempty"`
	HasReasoningField        bool         `json:"has_reasoning_field,omitempty"`
	PromptTokens             int          `json:"prompt_tokens,omitempty"`
	CachedPromptTokens       int          `json:"cached_prompt_tokens,omitempty"`
	OutputTokens             int          `json:"output_tokens,omitempty"`
	PromptInjectionSuspected bool         `json:"prompt_injection_suspected,omitempty"`
	LogprobsSupported        bool         `json:"logprobs_supported,omitempty"`
	TopKOverlap              float64      `json:"top_k_overlap,omitempty"`
	ObservedTopTokens        []TokenProb  `json:"observed_top_tokens,omitempty"`
	BaselineTopTokens        []TokenProb  `json:"baseline_top_tokens,omitempty"`
	ObservedText             string       `json:"observed_text,omitempty"`
	BaselineSampleText       string       `json:"baseline_sample_text,omitempty"`
	LatencyMS                int          `json:"latency_ms,omitempty"`
	HTTPStatus               int          `json:"http_status,omitempty"`
	ErrorCode                string       `json:"error_code,omitempty"`
	ErrorMessage             string       `json:"error_message,omitempty"`
}

// RunSummary aggregates verdict counts across all items in a batch verification run.
type RunSummary struct {
	Match              int `json:"match"`
	Suspect            int `json:"suspect"`
	Mismatch           int `json:"mismatch"`
	Unverified         int `json:"unverified"`
	Error              int `json:"error"`
	InjectionSuspected int `json:"injection_suspected"`
}

// Run represents a batch verification job persisted in modelfp_runs.
type Run struct {
	ID              int64        `json:"id"`
	TargetSource    TargetSource `json:"target_source"`
	AccountID       *int64       `json:"account_id,omitempty"`
	TargetLabel     string       `json:"target_label"`
	Protocol        Protocol     `json:"protocol"`
	SuiteID         int64        `json:"suite_id"`
	Status          RunStatus    `json:"status"`
	TotalModels     int          `json:"total_models"`
	CompletedModels int          `json:"completed_models"`
	Summary         RunSummary   `json:"summary"`
	ErrorMessage    string       `json:"error_message,omitempty"`
	CreatedBy       int64        `json:"created_by,omitempty"`
	StartedAt       *time.Time   `json:"started_at,omitempty"`
	FinishedAt      *time.Time   `json:"finished_at,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at,omitempty"`
}

// RunItem represents the verification verdict and evidence for one model in a Run.
type RunItem struct {
	ID                       int64            `json:"id"`
	RunID                    int64            `json:"run_id"`
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

// RunDetail combines a Run header with its per-model RunItems.
type RunDetail struct {
	Run
	Items []RunItem `json:"items"`
}

// RunPage represents a paginated list of verification runs.
type RunPage struct {
	Items    []Run `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

// CaptureModelResult summarizes calibration output for one model in a CaptureJob.
type CaptureModelResult struct {
	Model               string   `json:"model"`
	CanonicalModel      string   `json:"canonical_model"`
	LogprobsBaselineID  *int64   `json:"logprobs_baseline_id,omitempty"`
	BehaviorBaselineID  *int64   `json:"behavior_baseline_id,omitempty"`
	LogprobsSelfDivP95  *float64 `json:"logprobs_self_div_p95,omitempty"`
	LogprobsNearestDist *float64 `json:"logprobs_nearest_dist,omitempty"`
	BehaviorSelfDivP95  *float64 `json:"behavior_self_div_p95,omitempty"`
	BehaviorNearestDist *float64 `json:"behavior_nearest_dist,omitempty"`
	OverlapWarning      bool     `json:"overlap_warning"`
	OverlapDetails      []string `json:"overlap_details,omitempty"`
	Error               string   `json:"error,omitempty"`
}

// CaptureJob represents an async multi-round baseline capture task in modelfp_capture_jobs.
type CaptureJob struct {
	ID              int64                `json:"id"`
	Status          RunStatus            `json:"status"`
	Protocol        Protocol             `json:"protocol"`
	SuiteID         int64                `json:"suite_id"`
	SourceType      SourceType           `json:"source_type"`
	SampleRounds    int                  `json:"sample_rounds"`
	TotalModels     int                  `json:"total_models"`
	CompletedModels int                  `json:"completed_models"`
	Results         []CaptureModelResult `json:"results"`
	ErrorMessage    string               `json:"error_message,omitempty"`
	CreatedBy       int64                `json:"created_by,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at,omitempty"`
	FinishedAt      *time.Time           `json:"finished_at,omitempty"`
}

// Bundle is a portable JSON export/import archive protected by a SHA-256 checksum.
type Bundle struct {
	SchemaVersion  string       `json:"schema_version"`
	ExportedAt     time.Time    `json:"exported_at"`
	IncludePrivate bool         `json:"include_private"`
	Suites         []ProbeSuite `json:"suites"`
	FamilyMaps     []FamilyMap  `json:"family_maps"`
	Baselines      []Baseline   `json:"baselines"`
	SHA256         string       `json:"sha256"`
}

// ConfusionPair highlights a pair of models whose baselines lie close together.
type ConfusionPair struct {
	ModelA         string  `json:"model_a"`
	ModelB         string  `json:"model_b"`
	Distance       float64 `json:"distance"`
	OverlapWarning bool    `json:"overlap_warning"`
}

// ConfusionMatrixResult contains pairwise baseline distances and close-neighbor warnings.
type ConfusionMatrixResult struct {
	Protocol       Protocol        `json:"protocol,omitempty"`
	SuiteID        int64           `json:"suite_id,omitempty"`
	DetectorKind   DetectorKind    `json:"detector_kind,omitempty"`
	Models         []string        `json:"models"`
	Matrix         [][]float64     `json:"matrix"`
	ClosePairs     []ConfusionPair `json:"close_pairs"`
	MinOffDiagonal float64         `json:"min_off_diagonal"`
}

// LoadSeedData loads and validates the embedded L1 seed suites, family maps, and baselines.
func LoadSeedData() ([]ProbeSuite, []FamilyMap, []Baseline, error) {
	rawSuites, err := seeds.LoadDefaultSuites()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load default suites: %w", err)
	}
	var suites []ProbeSuite
	if err := json.Unmarshal(rawSuites, &suites); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal default suites: %w", err)
	}
	for i := range suites {
		if suites[i].ContentHash == "" {
			hash, err := ComputeContentHash(suites[i].Probes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("hash default suite %s/%s: %w", suites[i].SuiteKey, suites[i].Version, err)
			}
			suites[i].ContentHash = hash
		}
	}

	rawFamilies, err := seeds.LoadDefaultFamilyMaps()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load default family maps: %w", err)
	}
	var families []FamilyMap
	if err := json.Unmarshal(rawFamilies, &families); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal default family maps: %w", err)
	}

	rawBaselines, err := seeds.LoadDefaultBaselines()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load default baselines: %w", err)
	}
	var baselines []Baseline
	if err := json.Unmarshal(rawBaselines, &baselines); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal default baselines: %w", err)
	}

	return suites, families, baselines, nil
}
