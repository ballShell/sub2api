package modelfp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const (
	ddlCreateProbeSuites = `CREATE TABLE IF NOT EXISTS modelfp_probe_suites (
		id           BIGSERIAL PRIMARY KEY,
		suite_key    VARCHAR(128) NOT NULL,
		version      VARCHAR(64) NOT NULL,
		name         VARCHAR(255) NOT NULL DEFAULT '',
		visibility   VARCHAR(16) NOT NULL DEFAULT 'public',
		status       VARCHAR(16) NOT NULL DEFAULT 'active',
		is_default   BOOLEAN NOT NULL DEFAULT FALSE,
		probes_json  JSONB NOT NULL DEFAULT '[]'::jsonb,
		content_hash VARCHAR(64) NOT NULL DEFAULT '',
		created_by   BIGINT NOT NULL DEFAULT 0,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT uq_modelfp_probe_suites_key_version UNIQUE (suite_key, version),
		CONSTRAINT chk_modelfp_probe_suites_visibility CHECK (visibility IN ('public', 'private')),
		CONSTRAINT chk_modelfp_probe_suites_status CHECK (status IN ('active', 'archived')),
		CONSTRAINT chk_modelfp_probe_suites_probes_json CHECK (jsonb_typeof(probes_json) = 'array')
	)`

	ddlCreateBaselines = `CREATE TABLE IF NOT EXISTS modelfp_baselines (
		id                  BIGSERIAL PRIMARY KEY,
		canonical_model     VARCHAR(255) NOT NULL,
		protocol            VARCHAR(32) NOT NULL,
		suite_id            BIGINT NOT NULL REFERENCES modelfp_probe_suites(id),
		detector_kind       VARCHAR(32) NOT NULL,
		source_type         VARCHAR(32) NOT NULL DEFAULT 'official_direct',
		source_label        VARCHAR(255) NOT NULL DEFAULT '',
		upstream_snapshot   VARCHAR(255) NOT NULL DEFAULT '',
		sample_count        INT NOT NULL DEFAULT 0,
		signature_json      JSONB NOT NULL DEFAULT '{}'::jsonb,
		self_divergence_p95 DOUBLE PRECISION NOT NULL DEFAULT 0,
		match_threshold     DOUBLE PRECISION NOT NULL DEFAULT 0,
		suspect_threshold   DOUBLE PRECISION NOT NULL DEFAULT 0,
		ttl_days            INT NOT NULL DEFAULT 60,
		status              VARCHAR(16) NOT NULL DEFAULT 'active',
		notes               TEXT NOT NULL DEFAULT '',
		collected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT chk_modelfp_baselines_protocol CHECK (protocol IN ('openai_chat', 'openai_responses', 'anthropic', 'gemini')),
		CONSTRAINT chk_modelfp_baselines_detector CHECK (detector_kind IN ('logprobs', 'behavior')),
		CONSTRAINT chk_modelfp_baselines_source_type CHECK (source_type IN ('official_direct', 'trusted_cloud', 'cross_verified', 'community_seed')),
		CONSTRAINT chk_modelfp_baselines_status CHECK (status IN ('active', 'archived')),
		CONSTRAINT chk_modelfp_baselines_signature_json CHECK (jsonb_typeof(signature_json) = 'object')
	)`

	ddlCreateBaselinesActiveUniqueIndex = `CREATE UNIQUE INDEX IF NOT EXISTS uq_modelfp_baselines_active
		ON modelfp_baselines (canonical_model, protocol, suite_id, detector_kind)
		WHERE status = 'active'`

	ddlCreateBaselinesLookupIndex = `CREATE INDEX IF NOT EXISTS idx_modelfp_baselines_lookup
		ON modelfp_baselines (protocol, suite_id, detector_kind, status)`

	ddlCreateBaselinesModelIndex = `CREATE INDEX IF NOT EXISTS idx_modelfp_baselines_model
		ON modelfp_baselines (canonical_model)`

	ddlCreateFamilyMaps = `CREATE TABLE IF NOT EXISTS modelfp_family_maps (
		canonical_model      VARCHAR(255) PRIMARY KEY,
		family               VARCHAR(128) NOT NULL DEFAULT '',
		aliases_json         JSONB NOT NULL DEFAULT '[]'::jsonb,
		confusion_peers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
		updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT chk_modelfp_family_maps_aliases_json CHECK (jsonb_typeof(aliases_json) = 'array'),
		CONSTRAINT chk_modelfp_family_maps_peers_json CHECK (jsonb_typeof(confusion_peers_json) = 'array')
	)`

	ddlCreateRuns = `CREATE TABLE IF NOT EXISTS modelfp_runs (
		id               BIGSERIAL PRIMARY KEY,
		target_source    VARCHAR(16) NOT NULL,
		account_id       BIGINT,
		target_label     VARCHAR(255) NOT NULL DEFAULT '',
		protocol         VARCHAR(32) NOT NULL,
		suite_id         BIGINT NOT NULL,
		status           VARCHAR(16) NOT NULL DEFAULT 'queued',
		total_models     INT NOT NULL DEFAULT 0,
		completed_models INT NOT NULL DEFAULT 0,
		summary_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
		error_message    TEXT NOT NULL DEFAULT '',
		created_by       BIGINT NOT NULL DEFAULT 0,
		started_at       TIMESTAMPTZ,
		finished_at      TIMESTAMPTZ,
		created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT chk_modelfp_runs_target_source CHECK (target_source IN ('adhoc', 'account')),
		CONSTRAINT chk_modelfp_runs_protocol CHECK (protocol IN ('openai_chat', 'openai_responses', 'anthropic', 'gemini')),
		CONSTRAINT chk_modelfp_runs_status CHECK (status IN ('queued', 'running', 'completed', 'cancelled', 'failed')),
		CONSTRAINT chk_modelfp_runs_summary_json CHECK (jsonb_typeof(summary_json) = 'object')
	)`

	ddlAlterRunsAddUpdatedAt = `ALTER TABLE modelfp_runs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`

	ddlCreateRunsCreatedIndex = `CREATE INDEX IF NOT EXISTS idx_modelfp_runs_created
		ON modelfp_runs (created_at DESC, id DESC)`

	ddlCreateRunsStatusIndex = `CREATE INDEX IF NOT EXISTS idx_modelfp_runs_status
		ON modelfp_runs (status)`

	ddlCreateRunItems = `CREATE TABLE IF NOT EXISTS modelfp_run_items (
		id                         BIGSERIAL PRIMARY KEY,
		run_id                     BIGINT NOT NULL REFERENCES modelfp_runs(id) ON DELETE CASCADE,
		claimed_model              VARCHAR(255) NOT NULL,
		upstream_model             VARCHAR(255) NOT NULL DEFAULT '',
		canonical_model            VARCHAR(255) NOT NULL DEFAULT '',
		verdict                    VARCHAR(16) NOT NULL,
		detector_used              VARCHAR(32) NOT NULL DEFAULT '',
		confidence                 DOUBLE PRECISION NOT NULL DEFAULT 0,
		distance                   DOUBLE PRECISION NOT NULL DEFAULT 0,
		prompt_injection_suspected BOOLEAN NOT NULL DEFAULT FALSE,
		observed_prompt_tokens     INT NOT NULL DEFAULT 0,
		used_stale_baseline        BOOLEAN NOT NULL DEFAULT FALSE,
		top_candidates_json        JSONB NOT NULL DEFAULT '[]'::jsonb,
		evidence_json              JSONB NOT NULL DEFAULT '[]'::jsonb,
		latency_ms                 INT NOT NULL DEFAULT 0,
		error_code                 VARCHAR(64) NOT NULL DEFAULT '',
		error_message              TEXT NOT NULL DEFAULT '',
		checked_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT chk_modelfp_run_items_verdict CHECK (verdict IN ('match', 'suspect', 'mismatch', 'unverified', 'error')),
		CONSTRAINT chk_modelfp_run_items_detector CHECK (detector_used IN ('', 'logprobs', 'behavior')),
		CONSTRAINT chk_modelfp_run_items_candidates_json CHECK (jsonb_typeof(top_candidates_json) = 'array'),
		CONSTRAINT chk_modelfp_run_items_evidence_json CHECK (jsonb_typeof(evidence_json) = 'array')
	)`

	ddlCreateRunItemsRunIndex = `CREATE INDEX IF NOT EXISTS idx_modelfp_run_items_run
		ON modelfp_run_items (run_id, id)`

	ddlCreateCaptureJobs = `CREATE TABLE IF NOT EXISTS modelfp_capture_jobs (
		id               BIGSERIAL PRIMARY KEY,
		status           VARCHAR(16) NOT NULL DEFAULT 'queued',
		protocol         VARCHAR(32) NOT NULL,
		suite_id         BIGINT NOT NULL,
		source_type      VARCHAR(32) NOT NULL DEFAULT 'official_direct',
		sample_rounds    INT NOT NULL DEFAULT 3,
		total_models     INT NOT NULL DEFAULT 0,
		completed_models INT NOT NULL DEFAULT 0,
		results_json     JSONB NOT NULL DEFAULT '[]'::jsonb,
		error_message    TEXT NOT NULL DEFAULT '',
		created_by       BIGINT NOT NULL DEFAULT 0,
		created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		finished_at      TIMESTAMPTZ,
		CONSTRAINT chk_modelfp_capture_jobs_status CHECK (status IN ('queued', 'running', 'completed', 'cancelled', 'failed')),
		CONSTRAINT chk_modelfp_capture_jobs_protocol CHECK (protocol IN ('openai_chat', 'openai_responses', 'anthropic', 'gemini')),
		CONSTRAINT chk_modelfp_capture_jobs_source_type CHECK (source_type IN ('official_direct', 'trusted_cloud', 'cross_verified', 'community_seed')),
		CONSTRAINT chk_modelfp_capture_jobs_results_json CHECK (jsonb_typeof(results_json) = 'array')
	)`

	ddlAlterCaptureJobsAddUpdatedAt = `ALTER TABLE modelfp_capture_jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`

	ddlCreateCaptureJobsStatusIndex = `CREATE INDEX IF NOT EXISTS idx_modelfp_capture_jobs_status
		ON modelfp_capture_jobs (status, created_at DESC)`
)

// SchemaStatements returns the ordered, idempotent PostgreSQL DDL statements
// for all 6 modelfp tables and their indexes.
func SchemaStatements() []string {
	return []string{
		ddlCreateProbeSuites,
		ddlCreateBaselines,
		ddlCreateBaselinesActiveUniqueIndex,
		ddlCreateBaselinesLookupIndex,
		ddlCreateBaselinesModelIndex,
		ddlCreateFamilyMaps,
		ddlCreateRuns,
		ddlAlterRunsAddUpdatedAt,
		ddlCreateRunsCreatedIndex,
		ddlCreateRunsStatusIndex,
		ddlCreateRunItems,
		ddlCreateRunItemsRunIndex,
		ddlCreateCaptureJobs,
		ddlAlterCaptureJobsAddUpdatedAt,
		ddlCreateCaptureJobsStatusIndex,
	}
}

// EnsureSchema executes all idempotent modelfp DDL statements against db.
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("modelfp schema: database handle is nil")
	}
	for i, stmt := range SchemaStatements() {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("modelfp schema statement %d: %w", i, err)
		}
	}
	return nil
}
