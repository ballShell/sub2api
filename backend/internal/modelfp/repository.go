package modelfp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	defaultBaselineTTLDays = 60
	defaultCaptureJobRound = 3
	defaultRestartReason   = "server restarted"
	defaultRunPageSize     = 20
	maxRunPageSize         = 100
)

// BaselineFilter specifies optional filter predicates when listing baselines.
type BaselineFilter struct {
	Protocol       Protocol     `json:"protocol,omitempty"`
	SuiteID        int64        `json:"suite_id,omitempty"`
	CanonicalModel string       `json:"canonical_model,omitempty"`
	DetectorKind   DetectorKind `json:"detector_kind,omitempty"`
	Status         Status       `json:"status,omitempty"`
	Visibility     Visibility   `json:"visibility,omitempty"`
}

// BaselineUpdate specifies mutable calibration and lifecycle fields on a Baseline.
type BaselineUpdate struct {
	MatchThreshold   *float64 `json:"match_threshold,omitempty"`
	SuspectThreshold *float64 `json:"suspect_threshold,omitempty"`
	TTLDays          *int     `json:"ttl_days,omitempty"`
	Status           *Status  `json:"status,omitempty"`
	Notes            *string  `json:"notes,omitempty"`
}

// Store defines persistence operations for modelfp suites, baselines, family maps, runs, and capture jobs.
type Store interface {
	UpsertSeedSuite(ctx context.Context, suite ProbeSuite) (*ProbeSuite, error)
	CreateSuite(ctx context.Context, suite ProbeSuite) (*ProbeSuite, error)
	GetSuite(ctx context.Context, id int64) (*ProbeSuite, error)
	GetDefaultSuite(ctx context.Context) (*ProbeSuite, error)
	ListSuites(ctx context.Context) ([]ProbeSuite, error)
	UpdateSuiteStatus(ctx context.Context, id int64, status Status, isDefault bool) (*ProbeSuite, error)

	UpsertActiveBaseline(ctx context.Context, baseline Baseline) (*Baseline, error)
	ListBaselines(ctx context.Context, filter BaselineFilter) ([]Baseline, error)
	GetBaseline(ctx context.Context, id int64) (*Baseline, error)
	UpdateBaseline(ctx context.Context, id int64, update BaselineUpdate) (*Baseline, error)
	DeleteBaseline(ctx context.Context, id int64) error

	UpsertFamilyMap(ctx context.Context, fm FamilyMap) (*FamilyMap, error)
	ListFamilyMaps(ctx context.Context) ([]FamilyMap, error)
	DeleteFamilyMap(ctx context.Context, canonicalModel string) error

	CreateRun(ctx context.Context, run Run) (*Run, error)
	UpdateRunProgress(ctx context.Context, run Run) error
	GetRun(ctx context.Context, id int64) (*Run, error)
	ListRuns(ctx context.Context, page, pageSize int) (*RunPage, error)
	DeleteRun(ctx context.Context, id int64) error
	InsertRunItem(ctx context.Context, item RunItem) (*RunItem, error)
	ListRunItems(ctx context.Context, runID int64) ([]RunItem, error)

	CreateCaptureJob(ctx context.Context, job CaptureJob) (*CaptureJob, error)
	UpdateCaptureJob(ctx context.Context, job CaptureJob) error
	GetCaptureJob(ctx context.Context, id int64) (*CaptureJob, error)

	MarkStaleRunningJobsFailed(ctx context.Context, reason string) error
}

// PostgresStore implements Store using parameterized PostgreSQL queries over *sql.DB.
type PostgresStore struct {
	db *sql.DB
}

var _ Store = (*PostgresStore)(nil)

// NewPostgresStore constructs a PostgreSQL-backed Store.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

type sqlScanner interface {
	Scan(dest ...any) error
}

func (s *PostgresStore) ensureDB() error {
	if s == nil || s.db == nil {
		return errors.New("modelfp postgres store: database handle is nil")
	}
	return nil
}

func (s *PostgresStore) UpsertSeedSuite(ctx context.Context, suite ProbeSuite) (*ProbeSuite, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	norm, probesJSON, err := normalizeSuiteForWrite(suite)
	if err != nil {
		return nil, err
	}

	row := s.db.QueryRowContext(ctx, `
		INSERT INTO modelfp_probe_suites (
			suite_key, version, name, visibility, status, is_default,
			probes_json, content_hash, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			($6::boolean AND NOT EXISTS (SELECT 1 FROM modelfp_probe_suites WHERE is_default = TRUE AND status = 'active')),
			$7::jsonb, $8, $9, NOW(), NOW()
		)
		ON CONFLICT (suite_key, version) DO UPDATE SET
			name = EXCLUDED.name,
			visibility = EXCLUDED.visibility,
			probes_json = EXCLUDED.probes_json,
			content_hash = EXCLUDED.content_hash,
			updated_at = NOW()
		RETURNING id, suite_key, version, name, visibility, status, is_default, probes_json, content_hash, created_by, created_at, updated_at
	`, norm.SuiteKey, norm.Version, norm.Name, string(norm.Visibility), string(norm.Status),
		norm.IsDefault, probesJSON, norm.ContentHash, norm.CreatedBy)

	return scanSuite(row)
}

func (s *PostgresStore) CreateSuite(ctx context.Context, suite ProbeSuite) (*ProbeSuite, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	norm, probesJSON, err := normalizeSuiteForWrite(suite)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `
		INSERT INTO modelfp_probe_suites (
			suite_key, version, name, visibility, status, is_default,
			probes_json, content_hash, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, NOW(), NOW())
		RETURNING id, suite_key, version, name, visibility, status, is_default, probes_json, content_hash, created_by, created_at, updated_at
	`, norm.SuiteKey, norm.Version, norm.Name, string(norm.Visibility), string(norm.Status),
		norm.IsDefault, probesJSON, norm.ContentHash, norm.CreatedBy)

	created, err := scanSuite(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrSuiteImmutable.WithCause(err)
		}
		return nil, err
	}

	if created.IsDefault {
		if _, err := tx.ExecContext(ctx, `
			UPDATE modelfp_probe_suites
			SET is_default = FALSE, updated_at = NOW()
			WHERE is_default = TRUE AND id <> $1
		`, created.ID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return created, nil
}

func (s *PostgresStore) GetSuite(ctx context.Context, id int64) (*ProbeSuite, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, suite_key, version, name, visibility, status, is_default,
		       probes_json, content_hash, created_by, created_at, updated_at
		FROM modelfp_probe_suites
		WHERE id = $1
	`, id)
	suite, err := scanSuite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound.WithCause(err)
	}
	return suite, err
}

func (s *PostgresStore) GetDefaultSuite(ctx context.Context) (*ProbeSuite, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, suite_key, version, name, visibility, status, is_default,
		       probes_json, content_hash, created_by, created_at, updated_at
		FROM modelfp_probe_suites
		WHERE is_default = TRUE AND status = 'active'
		ORDER BY id DESC
		LIMIT 1
	`)
	suite, err := scanSuite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound.WithCause(err)
	}
	return suite, err
}

func (s *PostgresStore) ListSuites(ctx context.Context) ([]ProbeSuite, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, suite_key, version, name, visibility, status, is_default,
		       probes_json, content_hash, created_by, created_at, updated_at
		FROM modelfp_probe_suites
		ORDER BY is_default DESC, suite_key ASC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	suites := make([]ProbeSuite, 0)
	for rows.Next() {
		suite, scanErr := scanSuite(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		suites = append(suites, *suite)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return suites, nil
}

func (s *PostgresStore) UpdateSuiteStatus(ctx context.Context, id int64, status Status, isDefault bool) (*ProbeSuite, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	if status == "" {
		status = StatusActive
	}
	if status == StatusArchived {
		isDefault = false
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `
		UPDATE modelfp_probe_suites
		SET status = $2, is_default = $3, updated_at = NOW()
		WHERE id = $1
		RETURNING id, suite_key, version, name, visibility, status, is_default, probes_json, content_hash, created_by, created_at, updated_at
	`, id, string(status), isDefault)

	updated, err := scanSuite(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound.WithCause(err)
		}
		return nil, err
	}

	if updated.IsDefault {
		if _, err := tx.ExecContext(ctx, `
			UPDATE modelfp_probe_suites
			SET is_default = FALSE, updated_at = NOW()
			WHERE is_default = TRUE AND id <> $1
		`, updated.ID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *PostgresStore) UpsertActiveBaseline(ctx context.Context, baseline Baseline) (*Baseline, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	norm, sigJSON, err := normalizeBaselineForWrite(baseline)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE modelfp_baselines
		SET status = 'archived', updated_at = NOW()
		WHERE canonical_model = $1
		  AND protocol = $2
		  AND suite_id = $3
		  AND detector_kind = $4
		  AND status = 'active'
	`, norm.CanonicalModel, string(norm.Protocol), norm.SuiteID, string(norm.DetectorKind)); err != nil {
		return nil, err
	}

	row := tx.QueryRowContext(ctx, `
		INSERT INTO modelfp_baselines (
			canonical_model, protocol, suite_id, detector_kind,
			source_type, source_label, upstream_snapshot, sample_count,
			signature_json, self_divergence_p95, match_threshold, suspect_threshold,
			ttl_days, status, notes, collected_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9::jsonb, $10, $11, $12,
			$13, $14, $15, $16, NOW(), NOW()
		)
		RETURNING id, canonical_model, protocol, suite_id, detector_kind,
		          source_type, source_label, upstream_snapshot, sample_count,
		          signature_json, self_divergence_p95, match_threshold, suspect_threshold,
		          ttl_days, status, notes, collected_at, created_at, updated_at
	`, norm.CanonicalModel, string(norm.Protocol), norm.SuiteID, string(norm.DetectorKind),
		string(norm.SourceType), norm.SourceLabel, norm.UpstreamSnapshot, norm.SampleCount,
		sigJSON, norm.SelfDivergenceP95, norm.MatchThreshold, norm.SuspectThreshold,
		norm.TTLDays, string(norm.Status), norm.Notes, norm.CollectedAt)

	saved, err := scanBaselineWithoutJoin(row)
	if err != nil {
		return nil, err
	}
	if saved.SuiteKey == "" {
		saved.SuiteKey = norm.SuiteKey
	}
	if saved.SuiteVersion == "" {
		saved.SuiteVersion = norm.SuiteVersion
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return saved, nil
}

func (s *PostgresStore) ListBaselines(ctx context.Context, filter BaselineFilter) ([]Baseline, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}

	var query strings.Builder
	query.WriteString(`
		SELECT b.id, b.canonical_model, b.protocol, b.suite_id,
		       COALESCE(s.suite_key, ''), COALESCE(s.version, ''),
		       b.detector_kind, b.source_type, b.source_label, b.upstream_snapshot,
		       b.sample_count, b.signature_json, b.self_divergence_p95,
		       b.match_threshold, b.suspect_threshold, b.ttl_days,
		       b.status, b.notes, b.collected_at, b.created_at, b.updated_at
		FROM modelfp_baselines b
		LEFT JOIN modelfp_probe_suites s ON s.id = b.suite_id`)

	clauses := make([]string, 0, 6)
	args := make([]any, 0, 6)
	appendFilter := func(clause string, val any) {
		args = append(args, val)
		clauses = append(clauses, clause+"$"+strconv.Itoa(len(args)))
	}

	if filter.Protocol != "" {
		appendFilter("b.protocol = ", string(filter.Protocol))
	}
	if filter.SuiteID > 0 {
		appendFilter("b.suite_id = ", filter.SuiteID)
	}
	if model := strings.TrimSpace(filter.CanonicalModel); model != "" {
		args = append(args, model)
		clauses = append(clauses, "LOWER(b.canonical_model) = LOWER($"+strconv.Itoa(len(args))+")")
	}
	if filter.DetectorKind != "" {
		appendFilter("b.detector_kind = ", string(filter.DetectorKind))
	}
	if filter.Status != "" {
		appendFilter("b.status = ", string(filter.Status))
	}
	if filter.Visibility != "" {
		appendFilter("s.visibility = ", string(filter.Visibility))
	}

	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	query.WriteString(" ORDER BY b.canonical_model ASC, b.protocol ASC, b.detector_kind ASC, b.id DESC")

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]Baseline, 0)
	for rows.Next() {
		b, scanErr := scanBaselineWithJoin(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) GetBaseline(ctx context.Context, id int64) (*Baseline, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT b.id, b.canonical_model, b.protocol, b.suite_id,
		       COALESCE(s.suite_key, ''), COALESCE(s.version, ''),
		       b.detector_kind, b.source_type, b.source_label, b.upstream_snapshot,
		       b.sample_count, b.signature_json, b.self_divergence_p95,
		       b.match_threshold, b.suspect_threshold, b.ttl_days,
		       b.status, b.notes, b.collected_at, b.created_at, b.updated_at
		FROM modelfp_baselines b
		LEFT JOIN modelfp_probe_suites s ON s.id = b.suite_id
		WHERE b.id = $1
	`, id)
	b, err := scanBaselineWithJoin(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound.WithCause(err)
	}
	return b, err
}

func (s *PostgresStore) UpdateBaseline(ctx context.Context, id int64, update BaselineUpdate) (*Baseline, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `
		SELECT b.id, b.canonical_model, b.protocol, b.suite_id,
		       COALESCE(s.suite_key, ''), COALESCE(s.version, ''),
		       b.detector_kind, b.source_type, b.source_label, b.upstream_snapshot,
		       b.sample_count, b.signature_json, b.self_divergence_p95,
		       b.match_threshold, b.suspect_threshold, b.ttl_days,
		       b.status, b.notes, b.collected_at, b.created_at, b.updated_at
		FROM modelfp_baselines b
		LEFT JOIN modelfp_probe_suites s ON s.id = b.suite_id
		WHERE b.id = $1
		FOR UPDATE OF b
	`, id)
	existing, err := scanBaselineWithJoin(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound.WithCause(err)
		}
		return nil, err
	}

	matchThr := existing.MatchThreshold
	if update.MatchThreshold != nil {
		matchThr = *update.MatchThreshold
	}
	suspectThr := existing.SuspectThreshold
	if update.SuspectThreshold != nil {
		suspectThr = *update.SuspectThreshold
	}
	ttlDays := existing.TTLDays
	if update.TTLDays != nil {
		ttlDays = *update.TTLDays
	}
	status := existing.Status
	if update.Status != nil {
		status = *update.Status
	}
	notes := existing.Notes
	if update.Notes != nil {
		notes = *update.Notes
	}

	if status == StatusActive && existing.Status != StatusActive {
		if _, err := tx.ExecContext(ctx, `
			UPDATE modelfp_baselines
			SET status = 'archived', updated_at = NOW()
			WHERE canonical_model = $1
			  AND protocol = $2
			  AND suite_id = $3
			  AND detector_kind = $4
			  AND status = 'active'
			  AND id <> $5
		`, existing.CanonicalModel, string(existing.Protocol), existing.SuiteID, string(existing.DetectorKind), id); err != nil {
			return nil, err
		}
	}

	updRow := tx.QueryRowContext(ctx, `
		UPDATE modelfp_baselines
		SET match_threshold = $2,
		    suspect_threshold = $3,
		    ttl_days = $4,
		    status = $5,
		    notes = $6,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, canonical_model, protocol, suite_id, detector_kind,
		          source_type, source_label, upstream_snapshot, sample_count,
		          signature_json, self_divergence_p95, match_threshold, suspect_threshold,
		          ttl_days, status, notes, collected_at, created_at, updated_at
	`, id, matchThr, suspectThr, ttlDays, string(status), notes)

	updated, err := scanBaselineWithoutJoin(updRow)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound.WithCause(err)
		}
		return nil, err
	}
	updated.SuiteKey = existing.SuiteKey
	updated.SuiteVersion = existing.SuiteVersion

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *PostgresStore) DeleteBaseline(ctx context.Context, id int64) error {
	if err := s.ensureDB(); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM modelfp_baselines WHERE id = $1`, id)
	return requireAffectedRow(res, err)
}

func (s *PostgresStore) UpsertFamilyMap(ctx context.Context, fm FamilyMap) (*FamilyMap, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	canon := strings.TrimSpace(fm.CanonicalModel)
	if canon == "" {
		return nil, errors.New("canonical_model is required")
	}
	aliases := fm.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	peers := fm.ConfusionPeers
	if peers == nil {
		peers = []string{}
	}
	aliasesJSON, err := json.Marshal(aliases)
	if err != nil {
		return nil, fmt.Errorf("marshal family map aliases: %w", err)
	}
	peersJSON, err := json.Marshal(peers)
	if err != nil {
		return nil, fmt.Errorf("marshal family map confusion peers: %w", err)
	}

	row := s.db.QueryRowContext(ctx, `
		INSERT INTO modelfp_family_maps (
			canonical_model, family, aliases_json, confusion_peers_json, updated_at
		) VALUES ($1, $2, $3::jsonb, $4::jsonb, NOW())
		ON CONFLICT (canonical_model) DO UPDATE SET
			family = EXCLUDED.family,
			aliases_json = EXCLUDED.aliases_json,
			confusion_peers_json = EXCLUDED.confusion_peers_json,
			updated_at = NOW()
		RETURNING canonical_model, family, aliases_json, confusion_peers_json, updated_at
	`, canon, strings.TrimSpace(fm.Family), aliasesJSON, peersJSON)

	return scanFamilyMap(row)
}

func (s *PostgresStore) ListFamilyMaps(ctx context.Context) ([]FamilyMap, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT canonical_model, family, aliases_json, confusion_peers_json, updated_at
		FROM modelfp_family_maps
		ORDER BY family ASC, canonical_model ASC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]FamilyMap, 0)
	for rows.Next() {
		fm, scanErr := scanFamilyMap(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *fm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteFamilyMap(ctx context.Context, canonicalModel string) error {
	if err := s.ensureDB(); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM modelfp_family_maps WHERE canonical_model = $1`, strings.TrimSpace(canonicalModel))
	return requireAffectedRow(res, err)
}

func (s *PostgresStore) CreateRun(ctx context.Context, run Run) (*Run, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	if run.Status == "" {
		run.Status = RunStatusQueued
	}
	summaryJSON, err := json.Marshal(run.Summary)
	if err != nil {
		return nil, fmt.Errorf("marshal run summary: %w", err)
	}

	row := s.db.QueryRowContext(ctx, `
		INSERT INTO modelfp_runs (
			target_source, account_id, target_label, protocol, suite_id,
			status, total_models, completed_models, summary_json,
			error_message, created_by, started_at, finished_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9::jsonb,
			$10, $11, $12, $13, NOW()
		)
		RETURNING id, target_source, account_id, target_label, protocol, suite_id,
		          status, total_models, completed_models, summary_json,
		          error_message, created_by, started_at, finished_at, created_at
	`, string(run.TargetSource), nullableInt64Arg(run.AccountID), run.TargetLabel, string(run.Protocol), run.SuiteID,
		string(run.Status), run.TotalModels, run.CompletedModels, summaryJSON,
		run.ErrorMessage, run.CreatedBy, nullableTimeArg(run.StartedAt), nullableTimeArg(run.FinishedAt))

	return scanRun(row)
}

func (s *PostgresStore) UpdateRunProgress(ctx context.Context, run Run) error {
	if err := s.ensureDB(); err != nil {
		return err
	}
	summaryJSON, err := json.Marshal(run.Summary)
	if err != nil {
		return fmt.Errorf("marshal run summary: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE modelfp_runs
		SET status = $2,
		    completed_models = $3,
		    summary_json = $4::jsonb,
		    error_message = $5,
		    started_at = COALESCE($6, started_at),
		    finished_at = COALESCE($7, finished_at)
		WHERE id = $1
	`, run.ID, string(run.Status), run.CompletedModels, summaryJSON, run.ErrorMessage,
		nullableTimeArg(run.StartedAt), nullableTimeArg(run.FinishedAt))
	return requireAffectedRow(res, err)
}

func (s *PostgresStore) GetRun(ctx context.Context, id int64) (*Run, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, target_source, account_id, target_label, protocol, suite_id,
		       status, total_models, completed_models, summary_json,
		       error_message, created_by, started_at, finished_at, created_at
		FROM modelfp_runs
		WHERE id = $1
	`, id)
	run, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound.WithCause(err)
	}
	return run, err
}

func (s *PostgresStore) ListRuns(ctx context.Context, page, pageSize int) (*RunPage, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	page, pageSize = normalizePagination(page, pageSize)

	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM modelfp_runs`).Scan(&total); err != nil {
		return nil, err
	}

	out := &RunPage{
		Items:    make([]Run, 0),
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}
	if total == 0 {
		return out, nil
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_source, account_id, target_label, protocol, suite_id,
		       status, total_models, completed_models, summary_json,
		       error_message, created_by, started_at, finished_at, created_at
		FROM modelfp_runs
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2
	`, pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		run, scanErr := scanRun(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out.Items = append(out.Items, *run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteRun(ctx context.Context, id int64) error {
	if err := s.ensureDB(); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM modelfp_runs WHERE id = $1`, id)
	return requireAffectedRow(res, err)
}

func (s *PostgresStore) InsertRunItem(ctx context.Context, item RunItem) (*RunItem, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	candidates := item.TopCandidates
	if candidates == nil {
		candidates = []CandidateScore{}
	}
	evidence := item.Evidence
	if evidence == nil {
		evidence = []ProbeEvidence{}
	}
	candidatesJSON, err := json.Marshal(candidates)
	if err != nil {
		return nil, fmt.Errorf("marshal top candidates: %w", err)
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("marshal probe evidence: %w", err)
	}
	checkedAt := item.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	row := s.db.QueryRowContext(ctx, `
		INSERT INTO modelfp_run_items (
			run_id, claimed_model, upstream_model, canonical_model, verdict,
			detector_used, confidence, distance, prompt_injection_suspected,
			observed_prompt_tokens, used_stale_baseline, top_candidates_json,
			evidence_json, latency_ms, error_code, error_message, checked_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12::jsonb,
			$13::jsonb, $14, $15, $16, $17
		)
		RETURNING id, run_id, claimed_model, upstream_model, canonical_model, verdict,
		          detector_used, confidence, distance, prompt_injection_suspected,
		          observed_prompt_tokens, used_stale_baseline, top_candidates_json,
		          evidence_json, latency_ms, error_code, error_message, checked_at
	`, item.RunID, item.ClaimedModel, item.UpstreamModel, item.CanonicalModel, string(item.Verdict),
		string(item.DetectorUsed), item.Confidence, item.Distance, item.PromptInjectionSuspected,
		item.ObservedPromptTokens, item.UsedStaleBaseline, candidatesJSON,
		evidenceJSON, item.LatencyMS, item.ErrorCode, item.ErrorMessage, checkedAt.UTC())

	return scanRunItem(row)
}

func (s *PostgresStore) ListRunItems(ctx context.Context, runID int64) ([]RunItem, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, run_id, claimed_model, upstream_model, canonical_model, verdict,
		       detector_used, confidence, distance, prompt_injection_suspected,
		       observed_prompt_tokens, used_stale_baseline, top_candidates_json,
		       evidence_json, latency_ms, error_code, error_message, checked_at
		FROM modelfp_run_items
		WHERE run_id = $1
		ORDER BY id ASC
	`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]RunItem, 0)
	for rows.Next() {
		item, scanErr := scanRunItem(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) CreateCaptureJob(ctx context.Context, job CaptureJob) (*CaptureJob, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	if job.Status == "" {
		job.Status = RunStatusQueued
	}
	if job.SourceType == "" {
		job.SourceType = SourceOfficialDirect
	}
	if job.SampleRounds <= 0 {
		job.SampleRounds = defaultCaptureJobRound
	}
	results := job.Results
	if results == nil {
		results = []CaptureModelResult{}
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("marshal capture results: %w", err)
	}

	row := s.db.QueryRowContext(ctx, `
		INSERT INTO modelfp_capture_jobs (
			status, protocol, suite_id, source_type, sample_rounds,
			total_models, completed_models, results_json, error_message,
			created_by, created_at, finished_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8::jsonb, $9,
			$10, NOW(), $11
		)
		RETURNING id, status, protocol, suite_id, source_type, sample_rounds,
		          total_models, completed_models, results_json, error_message,
		          created_by, created_at, finished_at
	`, string(job.Status), string(job.Protocol), job.SuiteID, string(job.SourceType), job.SampleRounds,
		job.TotalModels, job.CompletedModels, resultsJSON, job.ErrorMessage,
		job.CreatedBy, nullableTimeArg(job.FinishedAt))

	return scanCaptureJob(row)
}

func (s *PostgresStore) UpdateCaptureJob(ctx context.Context, job CaptureJob) error {
	if err := s.ensureDB(); err != nil {
		return err
	}
	results := job.Results
	if results == nil {
		results = []CaptureModelResult{}
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("marshal capture results: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE modelfp_capture_jobs
		SET status = $2,
		    completed_models = $3,
		    results_json = $4::jsonb,
		    error_message = $5,
		    finished_at = COALESCE($6, finished_at)
		WHERE id = $1
	`, job.ID, string(job.Status), job.CompletedModels, resultsJSON, job.ErrorMessage, nullableTimeArg(job.FinishedAt))
	return requireAffectedRow(res, err)
}

func (s *PostgresStore) GetCaptureJob(ctx context.Context, id int64) (*CaptureJob, error) {
	if err := s.ensureDB(); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, status, protocol, suite_id, source_type, sample_rounds,
		       total_models, completed_models, results_json, error_message,
		       created_by, created_at, finished_at
		FROM modelfp_capture_jobs
		WHERE id = $1
	`, id)
	job, err := scanCaptureJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound.WithCause(err)
	}
	return job, err
}

func (s *PostgresStore) MarkStaleRunningJobsFailed(ctx context.Context, reason string) error {
	if err := s.ensureDB(); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = defaultRestartReason
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE modelfp_runs
		SET status = 'failed',
		    error_message = $1,
		    finished_at = NOW()
		WHERE status IN ('queued', 'running')
	`, reason); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE modelfp_capture_jobs
		SET status = 'failed',
		    error_message = $1,
		    finished_at = NOW()
		WHERE status IN ('queued', 'running')
	`, reason); err != nil {
		return err
	}

	return tx.Commit()
}

func normalizeSuiteForWrite(suite ProbeSuite) (ProbeSuite, []byte, error) {
	suite.SuiteKey = strings.TrimSpace(suite.SuiteKey)
	suite.Version = strings.TrimSpace(suite.Version)
	suite.Name = strings.TrimSpace(suite.Name)
	if suite.SuiteKey == "" || suite.Version == "" {
		return ProbeSuite{}, nil, errors.New("suite_key and version are required")
	}
	if suite.Visibility == "" {
		suite.Visibility = VisibilityPublic
	}
	if suite.Status == "" {
		suite.Status = StatusActive
	}
	if suite.Status == StatusArchived {
		suite.IsDefault = false
	}
	if suite.Probes == nil {
		suite.Probes = []ProbeDefinition{}
	}
	probesJSON, err := json.Marshal(suite.Probes)
	if err != nil {
		return ProbeSuite{}, nil, fmt.Errorf("marshal suite probes: %w", err)
	}
	if strings.TrimSpace(suite.ContentHash) == "" {
		hash, err := ComputeContentHash(suite.Probes)
		if err != nil {
			return ProbeSuite{}, nil, fmt.Errorf("compute suite content hash: %w", err)
		}
		suite.ContentHash = hash
	}
	return suite, probesJSON, nil
}

func normalizeBaselineForWrite(b Baseline) (Baseline, []byte, error) {
	b.CanonicalModel = strings.TrimSpace(b.CanonicalModel)
	if b.CanonicalModel == "" {
		return Baseline{}, nil, errors.New("canonical_model is required")
	}
	if b.Protocol == "" {
		return Baseline{}, nil, errors.New("protocol is required")
	}
	if b.SuiteID <= 0 {
		return Baseline{}, nil, errors.New("suite_id must be positive")
	}
	if b.DetectorKind == "" {
		return Baseline{}, nil, errors.New("detector_kind is required")
	}
	if b.SourceType == "" {
		b.SourceType = SourceOfficialDirect
	}
	if b.TTLDays <= 0 {
		b.TTLDays = defaultBaselineTTLDays
	}
	b.Status = StatusActive
	if b.CollectedAt.IsZero() {
		b.CollectedAt = time.Now().UTC()
	} else {
		b.CollectedAt = b.CollectedAt.UTC()
	}

	sigBytes, err := marshalBaselineSignature(b)
	if err != nil {
		return Baseline{}, nil, err
	}
	return b, sigBytes, nil
}

func marshalBaselineSignature(b Baseline) ([]byte, error) {
	switch b.DetectorKind {
	case DetectorLogprobs:
		if b.Logprobs == nil {
			return []byte("{}"), nil
		}
		raw, err := json.Marshal(b.Logprobs)
		if err != nil {
			return nil, fmt.Errorf("marshal logprobs signature: %w", err)
		}
		return raw, nil
	case DetectorBehavior:
		if b.Behavior == nil {
			return []byte("{}"), nil
		}
		raw, err := json.Marshal(b.Behavior)
		if err != nil {
			return nil, fmt.Errorf("marshal behavior signature: %w", err)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unsupported detector kind: %s", b.DetectorKind)
	}
}

func unmarshalBaselineSignature(kind DetectorKind, raw []byte, b *Baseline) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("{}")) {
		return nil
	}
	switch kind {
	case DetectorLogprobs:
		var sig LogprobsSignature
		if err := json.Unmarshal(trimmed, &sig); err != nil {
			return fmt.Errorf("unmarshal logprobs signature: %w", err)
		}
		if sig.Probes != nil {
			b.Logprobs = &sig
		}
	case DetectorBehavior:
		var sig BehaviorSignature
		if err := json.Unmarshal(trimmed, &sig); err != nil {
			return fmt.Errorf("unmarshal behavior signature: %w", err)
		}
		if sig.Probes != nil || len(sig.ResponseModels) > 0 || len(sig.SystemFingerprints) > 0 || sig.HasReasoningField != nil {
			b.Behavior = &sig
		}
	}
	return nil
}

func scanSuite(row sqlScanner) (*ProbeSuite, error) {
	var s ProbeSuite
	var vis, status string
	var probesRaw []byte
	var createdBy sql.NullInt64
	err := row.Scan(
		&s.ID, &s.SuiteKey, &s.Version, &s.Name, &vis, &status, &s.IsDefault,
		&probesRaw, &s.ContentHash, &createdBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.Visibility = Visibility(vis)
	s.Status = Status(status)
	if createdBy.Valid {
		s.CreatedBy = createdBy.Int64
	}
	if err := unmarshalJSONSlice(probesRaw, &s.Probes); err != nil {
		return nil, fmt.Errorf("unmarshal suite probes: %w", err)
	}
	if s.Probes == nil {
		s.Probes = []ProbeDefinition{}
	}
	return &s, nil
}

func scanBaselineWithoutJoin(row sqlScanner) (*Baseline, error) {
	var b Baseline
	var proto, kind, srcType, status string
	var sigRaw []byte
	err := row.Scan(
		&b.ID, &b.CanonicalModel, &proto, &b.SuiteID, &kind,
		&srcType, &b.SourceLabel, &b.UpstreamSnapshot, &b.SampleCount,
		&sigRaw, &b.SelfDivergenceP95, &b.MatchThreshold, &b.SuspectThreshold,
		&b.TTLDays, &status, &b.Notes, &b.CollectedAt, &b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	b.Protocol = Protocol(proto)
	b.DetectorKind = DetectorKind(kind)
	b.SourceType = SourceType(srcType)
	b.Status = Status(status)
	if err := unmarshalBaselineSignature(b.DetectorKind, sigRaw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func scanBaselineWithJoin(row sqlScanner) (*Baseline, error) {
	var b Baseline
	var proto, kind, srcType, status string
	var sigRaw []byte
	err := row.Scan(
		&b.ID, &b.CanonicalModel, &proto, &b.SuiteID,
		&b.SuiteKey, &b.SuiteVersion,
		&kind, &srcType, &b.SourceLabel, &b.UpstreamSnapshot,
		&b.SampleCount, &sigRaw, &b.SelfDivergenceP95,
		&b.MatchThreshold, &b.SuspectThreshold, &b.TTLDays,
		&status, &b.Notes, &b.CollectedAt, &b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	b.Protocol = Protocol(proto)
	b.DetectorKind = DetectorKind(kind)
	b.SourceType = SourceType(srcType)
	b.Status = Status(status)
	if err := unmarshalBaselineSignature(b.DetectorKind, sigRaw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func scanFamilyMap(row sqlScanner) (*FamilyMap, error) {
	var fm FamilyMap
	var aliasesRaw, peersRaw []byte
	if err := row.Scan(&fm.CanonicalModel, &fm.Family, &aliasesRaw, &peersRaw, &fm.UpdatedAt); err != nil {
		return nil, err
	}
	if err := unmarshalJSONSlice(aliasesRaw, &fm.Aliases); err != nil {
		return nil, fmt.Errorf("unmarshal family aliases: %w", err)
	}
	if fm.Aliases == nil {
		fm.Aliases = []string{}
	}
	if err := unmarshalJSONSlice(peersRaw, &fm.ConfusionPeers); err != nil {
		return nil, fmt.Errorf("unmarshal family confusion peers: %w", err)
	}
	if fm.ConfusionPeers == nil {
		fm.ConfusionPeers = []string{}
	}
	return &fm, nil
}

func scanRun(row sqlScanner) (*Run, error) {
	var r Run
	var src, proto, status string
	var accountID, createdBy sql.NullInt64
	var startedAt, finishedAt sql.NullTime
	var summaryRaw []byte
	err := row.Scan(
		&r.ID, &src, &accountID, &r.TargetLabel, &proto, &r.SuiteID,
		&status, &r.TotalModels, &r.CompletedModels, &summaryRaw,
		&r.ErrorMessage, &createdBy, &startedAt, &finishedAt, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.TargetSource = TargetSource(src)
	r.Protocol = Protocol(proto)
	r.Status = RunStatus(status)
	if accountID.Valid {
		v := accountID.Int64
		r.AccountID = &v
	}
	if createdBy.Valid {
		r.CreatedBy = createdBy.Int64
	}
	if startedAt.Valid {
		t := startedAt.Time.UTC()
		r.StartedAt = &t
	}
	if finishedAt.Valid {
		t := finishedAt.Time.UTC()
		r.FinishedAt = &t
	}
	trimmed := bytes.TrimSpace(summaryRaw)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		if err := json.Unmarshal(trimmed, &r.Summary); err != nil {
			return nil, fmt.Errorf("unmarshal run summary: %w", err)
		}
	}
	return &r, nil
}

func scanRunItem(row sqlScanner) (*RunItem, error) {
	var item RunItem
	var verdict, detectorUsed string
	var candidatesRaw, evidenceRaw []byte
	err := row.Scan(
		&item.ID, &item.RunID, &item.ClaimedModel, &item.UpstreamModel, &item.CanonicalModel, &verdict,
		&detectorUsed, &item.Confidence, &item.Distance, &item.PromptInjectionSuspected,
		&item.ObservedPromptTokens, &item.UsedStaleBaseline, &candidatesRaw,
		&evidenceRaw, &item.LatencyMS, &item.ErrorCode, &item.ErrorMessage, &item.CheckedAt,
	)
	if err != nil {
		return nil, err
	}
	item.Verdict = Verdict(verdict)
	item.DetectorUsed = DetectorKind(detectorUsed)
	if err := unmarshalJSONSlice(candidatesRaw, &item.TopCandidates); err != nil {
		return nil, fmt.Errorf("unmarshal top candidates: %w", err)
	}
	if item.TopCandidates == nil {
		item.TopCandidates = []CandidateScore{}
	}
	if err := unmarshalJSONSlice(evidenceRaw, &item.Evidence); err != nil {
		return nil, fmt.Errorf("unmarshal probe evidence: %w", err)
	}
	if item.Evidence == nil {
		item.Evidence = []ProbeEvidence{}
	}
	return &item, nil
}

func scanCaptureJob(row sqlScanner) (*CaptureJob, error) {
	var job CaptureJob
	var status, proto, srcType string
	var createdBy sql.NullInt64
	var finishedAt sql.NullTime
	var resultsRaw []byte
	err := row.Scan(
		&job.ID, &status, &proto, &job.SuiteID, &srcType, &job.SampleRounds,
		&job.TotalModels, &job.CompletedModels, &resultsRaw, &job.ErrorMessage,
		&createdBy, &job.CreatedAt, &finishedAt,
	)
	if err != nil {
		return nil, err
	}
	job.Status = RunStatus(status)
	job.Protocol = Protocol(proto)
	job.SourceType = SourceType(srcType)
	if createdBy.Valid {
		job.CreatedBy = createdBy.Int64
	}
	if finishedAt.Valid {
		t := finishedAt.Time.UTC()
		job.FinishedAt = &t
	}
	if err := unmarshalJSONSlice(resultsRaw, &job.Results); err != nil {
		return nil, fmt.Errorf("unmarshal capture results: %w", err)
	}
	if job.Results == nil {
		job.Results = []CaptureModelResult{}
	}
	return &job, nil
}

func unmarshalJSONSlice[T any](raw []byte, dst *[]T) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*dst = []T{}
		return nil
	}
	return json.Unmarshal(trimmed, dst)
}

func requireAffectedRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}

func nullableInt64Arg(ptr *int64) any {
	if ptr == nil {
		return nil
	}
	return *ptr
}

func nullableTimeArg(ptr *time.Time) any {
	if ptr == nil {
		return nil
	}
	return ptr.UTC()
}

func normalizePagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultRunPageSize
	}
	if pageSize > maxRunPageSize {
		pageSize = maxRunPageSize
	}
	return page, pageSize
}
