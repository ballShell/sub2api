package modelfp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestSchemaDDLContainsAllSixTablesAndPartialUniqueIndex(t *testing.T) {
	stmts := SchemaStatements()
	require.NotEmpty(t, stmts)

	joined := strings.ToLower(strings.Join(stmts, "\n"))
	requiredTables := []string{
		"modelfp_probe_suites",
		"modelfp_baselines",
		"modelfp_family_maps",
		"modelfp_runs",
		"modelfp_run_items",
		"modelfp_capture_jobs",
	}
	for _, tbl := range requiredTables {
		pattern := fmt.Sprintf(`create\s+table\s+if\s+not\s+exists\s+%s\b`, regexp.QuoteMeta(tbl))
		require.Regexpf(t, pattern, joined, "expected idempotent CREATE TABLE IF NOT EXISTS for %s", tbl)
	}

	partialUniquePattern := `create\s+unique\s+index\s+if\s+not\s+exists\s+\w+\s+on\s+modelfp_baselines\s*\(\s*canonical_model\s*,\s*protocol\s*,\s*suite_id\s*,\s*detector_kind\s*\)\s+where\s+status\s*=\s*'active'`
	require.Regexp(t, partialUniquePattern, joined, "expected partial unique active baseline index")

	// Verify EnsureSchema executes all DDL statements cleanly and rejects nil db.
	require.Error(t, EnsureSchema(context.Background(), nil))

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	for range stmts {
		mock.ExpectExec(`.+`).WillReturnResult(sqlmock.NewResult(0, 0))
	}
	require.NoError(t, EnsureSchema(context.Background(), db))
	require.NoError(t, mock.ExpectationsWereMet())

	// Verify EnsureSchema propagates DDL errors.
	dbErr, mockErr, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = dbErr.Close() }()
	mockErr.ExpectExec(`.+`).WillReturnError(errors.New("ddl failure"))
	require.ErrorContains(t, EnsureSchema(context.Background(), dbErr), "ddl failure")
	require.NoError(t, mockErr.ExpectationsWereMet())
}

func TestMarkStaleRunningJobsFailed(t *testing.T) {
	ctx := context.Background()

	t.Run("postgres_sqlmock", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()

		store := NewPostgresStore(db)
		mock.ExpectBegin()
		mock.ExpectExec(`(?s)UPDATE\s+modelfp_runs\s+SET\s+status\s*=\s*'failed'.*error_message\s*=\s*\$1.*finished_at\s*=\s*NOW\(\)\s+WHERE\s+status\s+IN\s*\(\s*'queued'\s*,\s*'running'\s*\)`).
			WithArgs("server restarted").
			WillReturnResult(sqlmock.NewResult(0, 2))
		mock.ExpectExec(`(?s)UPDATE\s+modelfp_capture_jobs\s+SET\s+status\s*=\s*'failed'.*error_message\s*=\s*\$1.*finished_at\s*=\s*NOW\(\)\s+WHERE\s+status\s+IN\s*\(\s*'queued'\s*,\s*'running'\s*\)`).
			WithArgs("server restarted").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		require.NoError(t, store.MarkStaleRunningJobsFailed(ctx, "server restarted"))
		require.NoError(t, mock.ExpectationsWereMet())

		// Blank reason defaults to "server restarted".
		mock.ExpectBegin()
		mock.ExpectExec(`UPDATE\s+modelfp_runs`).WithArgs("server restarted").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`UPDATE\s+modelfp_capture_jobs`).WithArgs("server restarted").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()
		require.NoError(t, store.MarkStaleRunningJobsFailed(ctx, "   "))
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("memory_store_state_transitions", func(t *testing.T) {
		store := NewMemoryStore()
		suite, err := store.UpsertSeedSuite(ctx, ProbeSuite{
			SuiteKey:   "builtin-public",
			Version:    "v1",
			Name:       "Builtin",
			Visibility: VisibilityPublic,
			Status:     StatusActive,
			IsDefault:  true,
		})
		require.NoError(t, err)

		oldFinished := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

		queuedRun, err := store.CreateRun(ctx, Run{TargetSource: TargetSourceAdHoc, TargetLabel: "q", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, Status: RunStatusQueued, TotalModels: 1})
		require.NoError(t, err)
		runningRun, err := store.CreateRun(ctx, Run{TargetSource: TargetSourceAdHoc, TargetLabel: "r", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, Status: RunStatusRunning, TotalModels: 1})
		require.NoError(t, err)
		completedRun, err := store.CreateRun(ctx, Run{TargetSource: TargetSourceAdHoc, TargetLabel: "c", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, Status: RunStatusCompleted, TotalModels: 1, FinishedAt: &oldFinished})
		require.NoError(t, err)
		cancelledRun, err := store.CreateRun(ctx, Run{TargetSource: TargetSourceAdHoc, TargetLabel: "x", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, Status: RunStatusCancelled, TotalModels: 1, ErrorMessage: "user cancelled", FinishedAt: &oldFinished})
		require.NoError(t, err)
		priorFailedRun, err := store.CreateRun(ctx, Run{TargetSource: TargetSourceAdHoc, TargetLabel: "f", Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, Status: RunStatusFailed, TotalModels: 1, ErrorMessage: "prior failure", FinishedAt: &oldFinished})
		require.NoError(t, err)

		queuedJob, err := store.CreateCaptureJob(ctx, CaptureJob{Status: RunStatusQueued, Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, SourceType: SourceOfficialDirect, SampleRounds: 3, TotalModels: 1})
		require.NoError(t, err)
		runningJob, err := store.CreateCaptureJob(ctx, CaptureJob{Status: RunStatusRunning, Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, SourceType: SourceOfficialDirect, SampleRounds: 3, TotalModels: 1})
		require.NoError(t, err)
		completedJob, err := store.CreateCaptureJob(ctx, CaptureJob{Status: RunStatusCompleted, Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, SourceType: SourceOfficialDirect, SampleRounds: 3, TotalModels: 1, FinishedAt: &oldFinished})
		require.NoError(t, err)
		cancelledJob, err := store.CreateCaptureJob(ctx, CaptureJob{Status: RunStatusCancelled, Protocol: ProtocolOpenAIChat, SuiteID: suite.ID, SourceType: SourceOfficialDirect, SampleRounds: 3, TotalModels: 1, ErrorMessage: "cancelled", FinishedAt: &oldFinished})
		require.NoError(t, err)

		require.NoError(t, store.MarkStaleRunningJobsFailed(ctx, "server restarted"))

		for _, id := range []int64{queuedRun.ID, runningRun.ID} {
			got, err := store.GetRun(ctx, id)
			require.NoError(t, err)
			require.Equal(t, RunStatusFailed, got.Status)
			require.Equal(t, "server restarted", got.ErrorMessage)
			require.NotNil(t, got.FinishedAt)
		}

		gotCompleted, err := store.GetRun(ctx, completedRun.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCompleted, gotCompleted.Status)
		require.Empty(t, gotCompleted.ErrorMessage)
		require.Equal(t, &oldFinished, gotCompleted.FinishedAt)

		gotCancelled, err := store.GetRun(ctx, cancelledRun.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCancelled, gotCancelled.Status)
		require.Equal(t, "user cancelled", gotCancelled.ErrorMessage)
		require.Equal(t, &oldFinished, gotCancelled.FinishedAt)

		gotPriorFailed, err := store.GetRun(ctx, priorFailedRun.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusFailed, gotPriorFailed.Status)
		require.Equal(t, "prior failure", gotPriorFailed.ErrorMessage)
		require.Equal(t, &oldFinished, gotPriorFailed.FinishedAt)

		for _, id := range []int64{queuedJob.ID, runningJob.ID} {
			got, err := store.GetCaptureJob(ctx, id)
			require.NoError(t, err)
			require.Equal(t, RunStatusFailed, got.Status)
			require.Equal(t, "server restarted", got.ErrorMessage)
			require.NotNil(t, got.FinishedAt)
		}

		gotCompletedJob, err := store.GetCaptureJob(ctx, completedJob.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCompleted, gotCompletedJob.Status)
		require.Equal(t, &oldFinished, gotCompletedJob.FinishedAt)

		gotCancelledJob, err := store.GetCaptureJob(ctx, cancelledJob.ID)
		require.NoError(t, err)
		require.Equal(t, RunStatusCancelled, gotCancelledJob.Status)
		require.Equal(t, "cancelled", gotCancelledJob.ErrorMessage)
		require.Equal(t, &oldFinished, gotCancelledJob.FinishedAt)
	})
}

func TestUpsertActiveBaselineArchivesPrevious(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	t.Run("postgres_sqlmock", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()

		store := NewPostgresStore(db)
		lpSig := &LogprobsSignature{
			Probes: map[string]LogprobsProbeSignature{
				"lp-1": {ProbeID: "lp-1", Distribution: map[string]float64{"yes": 0.9, DefaultOtherToken: 0.1}},
			},
		}

		mock.ExpectBegin()
		mock.ExpectExec(`(?s)UPDATE\s+modelfp_baselines\s+SET\s+status\s*=\s*'archived'.*WHERE\s+canonical_model\s*=\s*\$1\s+AND\s+protocol\s*=\s*\$2\s+AND\s+suite_id\s*=\s*\$3\s+AND\s+detector_kind\s*=\s*\$4\s+AND\s+status\s*=\s*'active'`).
			WithArgs("gpt-4o", string(ProtocolOpenAIChat), int64(1), string(DetectorLogprobs)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_baselines`).
			WithArgs(
				"gpt-4o",
				string(ProtocolOpenAIChat),
				int64(1),
				string(DetectorLogprobs),
				string(SourceOfficialDirect),
				"official",
				"gpt-4o-2024-11-20",
				3,
				sqlmock.AnyArg(),
				0.02,
				0.06,
				0.15,
				60,
				string(StatusActive),
				"v2",
				now,
			).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "canonical_model", "protocol", "suite_id", "detector_kind",
				"source_type", "source_label", "upstream_snapshot", "sample_count",
				"signature_json", "self_divergence_p95", "match_threshold", "suspect_threshold",
				"ttl_days", "status", "notes", "collected_at", "created_at", "updated_at",
			}).AddRow(
				int64(42), "gpt-4o", string(ProtocolOpenAIChat), int64(1), string(DetectorLogprobs),
				string(SourceOfficialDirect), "official", "gpt-4o-2024-11-20", 3,
				[]byte(`{"probes":{"lp-1":{"probe_id":"lp-1","distribution":{"<OTHER>":0.1,"yes":0.9}}}}`),
				0.02, 0.06, 0.15, 60, string(StatusActive), "v2", now, now, now,
			))
		mock.ExpectCommit()

		saved, err := store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel:    "gpt-4o",
			Protocol:          ProtocolOpenAIChat,
			SuiteID:           1,
			SuiteKey:          "builtin-public",
			SuiteVersion:      "v1",
			DetectorKind:      DetectorLogprobs,
			SourceType:        SourceOfficialDirect,
			SourceLabel:       "official",
			UpstreamSnapshot:  "gpt-4o-2024-11-20",
			SampleCount:       3,
			Logprobs:          lpSig,
			SelfDivergenceP95: 0.02,
			MatchThreshold:    0.06,
			SuspectThreshold:  0.15,
			TTLDays:           60,
			Notes:             "v2",
			CollectedAt:       now,
		})
		require.NoError(t, err)
		require.Equal(t, int64(42), saved.ID)
		require.Equal(t, StatusActive, saved.Status)
		require.NotNil(t, saved.Logprobs)
		require.InDelta(t, 0.9, saved.Logprobs.Probes["lp-1"].Distribution["yes"], 1e-9)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("memory_store_archives_same_tuple_only", func(t *testing.T) {
		store := NewMemoryStore()
		suite, err := store.UpsertSeedSuite(ctx, ProbeSuite{
			SuiteKey:   "builtin-public",
			Version:    "v1",
			Name:       "Builtin",
			Visibility: VisibilityPublic,
			Status:     StatusActive,
			IsDefault:  true,
		})
		require.NoError(t, err)

		b1, err := store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel: "gpt-4o",
			Protocol:       ProtocolOpenAIChat,
			SuiteID:        suite.ID,
			DetectorKind:   DetectorLogprobs,
			SourceType:     SourceOfficialDirect,
			SourceLabel:    "run-1",
			Logprobs:       &LogprobsSignature{Probes: map[string]LogprobsProbeSignature{"lp-1": {ProbeID: "lp-1", Distribution: map[string]float64{"a": 1}}}},
			CollectedAt:    now,
		})
		require.NoError(t, err)

		// Different detector_kind on same model/protocol/suite must remain active.
		bh, err := store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel: "gpt-4o",
			Protocol:       ProtocolOpenAIChat,
			SuiteID:        suite.ID,
			DetectorKind:   DetectorBehavior,
			SourceType:     SourceOfficialDirect,
			SourceLabel:    "run-1",
			Behavior:       &BehaviorSignature{Probes: map[string]BehaviorProbeSignature{"bh-1": {ProbeID: "bh-1", Samples: []string{"ok"}}}},
			CollectedAt:    now,
		})
		require.NoError(t, err)

		// Replacing logprobs baseline archives b1 and activates b2.
		b2, err := store.UpsertActiveBaseline(ctx, Baseline{
			CanonicalModel: "gpt-4o",
			Protocol:       ProtocolOpenAIChat,
			SuiteID:        suite.ID,
			DetectorKind:   DetectorLogprobs,
			SourceType:     SourceOfficialDirect,
			SourceLabel:    "run-2",
			Logprobs:       &LogprobsSignature{Probes: map[string]LogprobsProbeSignature{"lp-1": {ProbeID: "lp-1", Distribution: map[string]float64{"b": 1}}}},
			CollectedAt:    now.Add(time.Minute),
		})
		require.NoError(t, err)

		oldRow, err := store.GetBaseline(ctx, b1.ID)
		require.NoError(t, err)
		require.Equal(t, StatusArchived, oldRow.Status)

		newRow, err := store.GetBaseline(ctx, b2.ID)
		require.NoError(t, err)
		require.Equal(t, StatusActive, newRow.Status)
		require.Equal(t, "builtin-public", newRow.SuiteKey)
		require.Equal(t, "v1", newRow.SuiteVersion)

		bhRow, err := store.GetBaseline(ctx, bh.ID)
		require.NoError(t, err)
		require.Equal(t, StatusActive, bhRow.Status)

		activeLP, err := store.ListBaselines(ctx, BaselineFilter{
			CanonicalModel: "gpt-4o",
			Protocol:       ProtocolOpenAIChat,
			SuiteID:        suite.ID,
			DetectorKind:   DetectorLogprobs,
			Status:         StatusActive,
		})
		require.NoError(t, err)
		require.Len(t, activeLP, 1)
		require.Equal(t, b2.ID, activeLP[0].ID)
	})
}

func TestPostgresStoreSuitesAndErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 11, 0, 0, 0, time.UTC)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	store := NewPostgresStore(db)

	probesJSON := []byte(`[{"id":"lp-1","kind":"logprobs","prompt":"hi","max_tokens":1,"temperature":0,"weight":1,"expected_max_prompt_tokens":500}]`)
	suiteCols := []string{"id", "suite_key", "version", "name", "visibility", "status", "is_default", "probes_json", "content_hash", "created_by", "created_at", "updated_at"}

	// CreateSuite duplicate returns ErrSuiteImmutable.
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_probe_suites`).
		WillReturnError(&pq.Error{Code: "23505", Message: "duplicate key value violates unique constraint"})
	mock.ExpectRollback()
	_, err = store.CreateSuite(ctx, ProbeSuite{
		SuiteKey:   "builtin-public",
		Version:    "v1",
		Name:       "Builtin",
		Visibility: VisibilityPublic,
		Status:     StatusActive,
		Probes:     []ProbeDefinition{{ID: "lp-1", Kind: DetectorLogprobs, Prompt: "hi", MaxTokens: 1, Weight: 1, ExpectedMaxPromptTokens: 500}},
	})
	require.ErrorIs(t, err, ErrSuiteImmutable)
	require.NoError(t, mock.ExpectationsWereMet())

	// GetSuite sql.ErrNoRows maps to ErrNotFound.
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_probe_suites\s+WHERE\s+id\s*=\s*\$1`).
		WithArgs(int64(999)).
		WillReturnError(sql.ErrNoRows)
	_, err = store.GetSuite(ctx, 999)
	require.ErrorIs(t, err, ErrNotFound)

	// GetDefaultSuite returns active default.
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_probe_suites\s+WHERE\s+is_default\s*=\s*TRUE\s+AND\s+status\s*=\s*'active'`).
		WillReturnRows(sqlmock.NewRows(suiteCols).AddRow(int64(1), "builtin-public", "v1", "Builtin", "public", "active", true, probesJSON, "abc", int64(0), now, now))
	defSuite, err := store.GetDefaultSuite(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), defSuite.ID)
	require.True(t, defSuite.IsDefault)
	require.Len(t, defSuite.Probes, 1)

	// UpdateSuiteStatus sets target and clears other defaults when isDefault=true.
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)UPDATE\s+modelfp_probe_suites\s+SET\s+status\s*=\s*\$2,\s*is_default\s*=\s*\$3,\s*updated_at\s*=\s*NOW\(\)\s+WHERE\s+id\s*=\s*\$1\s+RETURNING`).
		WithArgs(int64(2), string(StatusActive), true).
		WillReturnRows(sqlmock.NewRows(suiteCols).AddRow(int64(2), "canary", "v1", "Canary", "private", "active", true, probesJSON, "def", int64(7), now, now))
	mock.ExpectExec(`(?s)UPDATE\s+modelfp_probe_suites\s+SET\s+is_default\s*=\s*FALSE,\s*updated_at\s*=\s*NOW\(\)\s+WHERE\s+is_default\s*=\s*TRUE\s+AND\s+id\s*<>\s*\$1`).
		WithArgs(int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	updated, err := store.UpdateSuiteStatus(ctx, 2, StatusActive, true)
	require.NoError(t, err)
	require.Equal(t, VisibilityPrivate, updated.Visibility)
	require.True(t, updated.IsDefault)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreBaselinesFamiliesRunsAndCaptures(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 11, 30, 0, 0, time.UTC)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	store := NewPostgresStore(db)

	// ListBaselines with Visibility filter joins suites and decodes BehaviorSignature.
	baselineCols := []string{
		"id", "canonical_model", "protocol", "suite_id", "suite_key", "suite_version", "detector_kind",
		"source_type", "source_label", "upstream_snapshot", "sample_count",
		"signature_json", "self_divergence_p95", "match_threshold", "suspect_threshold",
		"ttl_days", "status", "notes", "collected_at", "created_at", "updated_at",
	}
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_baselines\s+b\s+LEFT\s+JOIN\s+modelfp_probe_suites\s+s\s+ON\s+s\.id\s*=\s*b\.suite_id\s+WHERE\s+b\.protocol\s*=\s*\$1\s+AND\s+s\.visibility\s*=\s*\$2`).
		WithArgs(string(ProtocolAnthropic), string(VisibilityPublic)).
		WillReturnRows(sqlmock.NewRows(baselineCols).AddRow(
			int64(5), "claude-opus-4-6", string(ProtocolAnthropic), int64(1), "builtin-public", "v1", string(DetectorBehavior),
			string(SourceOfficialDirect), "official", "", 3,
			[]byte(`{"probes":{"bh-1":{"probe_id":"bh-1","samples":["42"]}},"response_models":["claude-opus-4-6"]}`),
			0.05, 0.18, 0.32, 60, string(StatusActive), "", now, now, now,
		))
	baselines, err := store.ListBaselines(ctx, BaselineFilter{
		Protocol:   ProtocolAnthropic,
		Visibility: VisibilityPublic,
	})
	require.NoError(t, err)
	require.Len(t, baselines, 1)
	require.NotNil(t, baselines[0].Behavior)
	require.Equal(t, []string{"claude-opus-4-6"}, baselines[0].Behavior.ResponseModels)

	// DeleteBaseline missing row -> ErrNotFound.
	mock.ExpectExec(`DELETE\s+FROM\s+modelfp_baselines\s+WHERE\s+id\s*=\s*\$1`).
		WithArgs(int64(404)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, store.DeleteBaseline(ctx, 404), ErrNotFound)

	// FamilyMap upsert + list + delete.
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_family_maps.*ON\s+CONFLICT\s*\(\s*canonical_model\s*\)\s+DO\s+UPDATE`).
		WithArgs("claude-opus-4-6", "claude-4", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"canonical_model", "family", "aliases_json", "confusion_peers_json", "updated_at"}).
			AddRow("claude-opus-4-6", "claude-4", []byte(`["claude-opus-4.6"]`), []byte(`["claude-sonnet-4-6"]`), now))
	fm, err := store.UpsertFamilyMap(ctx, FamilyMap{
		CanonicalModel: "claude-opus-4-6",
		Family:         "claude-4",
		Aliases:        []string{"claude-opus-4.6"},
		ConfusionPeers: []string{"claude-sonnet-4-6"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"claude-sonnet-4-6"}, fm.ConfusionPeers)

	// Run create + RunItem insert (preserving UsedStaleBaseline).
	acctID := int64(7)
	runCols := []string{"id", "target_source", "account_id", "target_label", "protocol", "suite_id", "status", "total_models", "completed_models", "summary_json", "error_message", "created_by", "started_at", "finished_at", "created_at"}
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_runs`).
		WithArgs(string(TargetSourceAccount), int64(7), "account #7", string(ProtocolOpenAIChat), int64(1), string(RunStatusQueued), 2, 0, sqlmock.AnyArg(), "", int64(1), nil, nil).
		WillReturnRows(sqlmock.NewRows(runCols).AddRow(int64(10), "account", int64(7), "account #7", "openai_chat", int64(1), "queued", 2, 0, []byte(`{}`), "", int64(1), nil, nil, now))
	createdRun, err := store.CreateRun(ctx, Run{
		TargetSource: TargetSourceAccount,
		AccountID:    &acctID,
		TargetLabel:  "account #7",
		Protocol:     ProtocolOpenAIChat,
		SuiteID:      1,
		Status:       RunStatusQueued,
		TotalModels:  2,
		CreatedBy:    1,
	})
	require.NoError(t, err)
	require.Equal(t, int64(10), createdRun.ID)
	require.NotNil(t, createdRun.AccountID)
	require.Equal(t, int64(7), *createdRun.AccountID)

	itemCols := []string{"id", "run_id", "claimed_model", "upstream_model", "canonical_model", "verdict", "detector_used", "confidence", "distance", "prompt_injection_suspected", "observed_prompt_tokens", "used_stale_baseline", "top_candidates_json", "evidence_json", "latency_ms", "error_code", "error_message", "checked_at"}
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_run_items`).
		WillReturnRows(sqlmock.NewRows(itemCols).AddRow(
			int64(100), int64(10), "gpt-4o", "gpt-4o", "gpt-4o", "match", "logprobs", 0.95, 0.01, false, 24, true,
			[]byte(`[{"canonical_model":"gpt-4o","distance":0.01,"similarity":0.99,"within_match":true}]`),
			[]byte(`[{"probe_id":"lp-1","detector_kind":"logprobs","distance":0.01,"weight":1}]`),
			120, "", "", now,
		))
	savedItem, err := store.InsertRunItem(ctx, RunItem{
		RunID:                10,
		ClaimedModel:         "gpt-4o",
		UpstreamModel:        "gpt-4o",
		CanonicalModel:       "gpt-4o",
		Verdict:              VerdictMatch,
		DetectorUsed:         DetectorLogprobs,
		Confidence:           0.95,
		Distance:             0.01,
		ObservedPromptTokens: 24,
		UsedStaleBaseline:    true,
		TopCandidates:        []CandidateScore{{CanonicalModel: "gpt-4o", Distance: 0.01, Similarity: 0.99, WithinMatch: true}},
		Evidence:             []ProbeEvidence{{ProbeID: "lp-1", DetectorKind: DetectorLogprobs, Distance: 0.01, Weight: 1}},
		LatencyMS:            120,
		CheckedAt:            now,
	})
	require.NoError(t, err)
	require.True(t, savedItem.UsedStaleBaseline)
	require.Len(t, savedItem.TopCandidates, 1)

	// CaptureJob create + update.
	jobCols := []string{"id", "status", "protocol", "suite_id", "source_type", "sample_rounds", "total_models", "completed_models", "results_json", "error_message", "created_by", "created_at", "finished_at"}
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_capture_jobs`).
		WillReturnRows(sqlmock.NewRows(jobCols).AddRow(int64(21), "queued", "openai_chat", int64(1), "official_direct", 3, 1, 0, []byte(`[]`), "", int64(1), now, nil))
	job, err := store.CreateCaptureJob(ctx, CaptureJob{
		Status:       RunStatusQueued,
		Protocol:     ProtocolOpenAIChat,
		SuiteID:      1,
		SourceType:   SourceOfficialDirect,
		SampleRounds: 3,
		TotalModels:  1,
		CreatedBy:    1,
	})
	require.NoError(t, err)
	require.Equal(t, int64(21), job.ID)

	mock.ExpectExec(`(?s)UPDATE\s+modelfp_capture_jobs`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	job.Status = RunStatusCompleted
	job.CompletedModels = 1
	job.FinishedAt = &now
	require.NoError(t, store.UpdateCaptureJob(ctx, *job))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMemoryStoreContractAndConcurrency(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Seed suite upsert preserves status/default on re-upsert.
	s1, err := store.UpsertSeedSuite(ctx, ProbeSuite{
		SuiteKey:   "builtin-public",
		Version:    "v1",
		Name:       "Builtin v1",
		Visibility: VisibilityPublic,
		Status:     StatusActive,
		IsDefault:  true,
		Probes:     []ProbeDefinition{{ID: "lp-1", Kind: DetectorLogprobs, Prompt: "hi", MaxTokens: 1, Weight: 1, ExpectedMaxPromptTokens: 500}},
	})
	require.NoError(t, err)
	require.True(t, s1.IsDefault)

	// Create private suite + make it default.
	s2, err := store.CreateSuite(ctx, ProbeSuite{
		SuiteKey:   "canary",
		Version:    "v1",
		Name:       "Canary",
		Visibility: VisibilityPrivate,
		Status:     StatusActive,
		IsDefault:  true,
		Probes:     []ProbeDefinition{{ID: "bh-1", Kind: DetectorBehavior, Prompt: "canary", MaxTokens: 32, Weight: 1, ExpectedMaxPromptTokens: 500}},
	})
	require.NoError(t, err)
	require.True(t, s2.IsDefault)

	// Duplicate CreateSuite returns ErrSuiteImmutable.
	_, err = store.CreateSuite(ctx, ProbeSuite{SuiteKey: "canary", Version: "v1"})
	require.ErrorIs(t, err, ErrSuiteImmutable)

	// Re-upserting seed suite must not steal IsDefault back from s2.
	s1Again, err := store.UpsertSeedSuite(ctx, ProbeSuite{
		SuiteKey:   "builtin-public",
		Version:    "v1",
		Name:       "Builtin v1 Updated",
		Visibility: VisibilityPublic,
		Status:     StatusActive,
		IsDefault:  true,
		Probes:     []ProbeDefinition{{ID: "lp-1", Kind: DetectorLogprobs, Prompt: "hi2", MaxTokens: 1, Weight: 1, ExpectedMaxPromptTokens: 500}},
	})
	require.NoError(t, err)
	require.False(t, s1Again.IsDefault)
	require.Equal(t, "Builtin v1 Updated", s1Again.Name)

	def, err := store.GetDefaultSuite(ctx)
	require.NoError(t, err)
	require.Equal(t, s2.ID, def.ID)

	// Archive s2 -> clears IsDefault.
	s2Arch, err := store.UpdateSuiteStatus(ctx, s2.ID, StatusArchived, true)
	require.NoError(t, err)
	require.Equal(t, StatusArchived, s2Arch.Status)
	require.False(t, s2Arch.IsDefault)

	// Restore s1 as default.
	s1Def, err := store.UpdateSuiteStatus(ctx, s1.ID, StatusActive, true)
	require.NoError(t, err)
	require.True(t, s1Def.IsDefault)

	// Baselines visibility filtering + UpdateBaseline + DeleteBaseline.
	bPub, err := store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel: "gpt-4o",
		Protocol:       ProtocolOpenAIChat,
		SuiteID:        s1.ID,
		DetectorKind:   DetectorLogprobs,
		SourceType:     SourceOfficialDirect,
		Logprobs:       &LogprobsSignature{Probes: map[string]LogprobsProbeSignature{"lp-1": {ProbeID: "lp-1", Distribution: map[string]float64{"x": 1}}}},
	})
	require.NoError(t, err)
	_, err = store.UpsertActiveBaseline(ctx, Baseline{
		CanonicalModel: "gpt-4o",
		Protocol:       ProtocolOpenAIChat,
		SuiteID:        s2.ID,
		DetectorKind:   DetectorBehavior,
		SourceType:     SourceOfficialDirect,
		Behavior:       &BehaviorSignature{Probes: map[string]BehaviorProbeSignature{"bh-1": {ProbeID: "bh-1", Samples: []string{"ok"}}}},
	})
	require.NoError(t, err)

	pubOnly, err := store.ListBaselines(ctx, BaselineFilter{Visibility: VisibilityPublic})
	require.NoError(t, err)
	require.Len(t, pubOnly, 1)
	require.Equal(t, bPub.ID, pubOnly[0].ID)

	newThr := 0.09
	newNotes := "tuned"
	updB, err := store.UpdateBaseline(ctx, bPub.ID, BaselineUpdate{MatchThreshold: &newThr, Notes: &newNotes})
	require.NoError(t, err)
	require.InDelta(t, 0.09, updB.MatchThreshold, 1e-9)
	require.Equal(t, "tuned", updB.Notes)

	require.NoError(t, store.DeleteBaseline(ctx, bPub.ID))
	require.ErrorIs(t, store.DeleteBaseline(ctx, bPub.ID), ErrNotFound)

	// FamilyMap CRUD.
	_, err = store.UpsertFamilyMap(ctx, FamilyMap{CanonicalModel: "gpt-4o", Family: "gpt-4o", Aliases: []string{"chatgpt-4o-latest"}, ConfusionPeers: []string{"gpt-4o-mini"}})
	require.NoError(t, err)
	fms, err := store.ListFamilyMaps(ctx)
	require.NoError(t, err)
	require.Len(t, fms, 1)
	require.NoError(t, store.DeleteFamilyMap(ctx, "gpt-4o"))
	require.ErrorIs(t, store.DeleteFamilyMap(ctx, "gpt-4o"), ErrNotFound)

	// Concurrent Run + RunItem writes under -race.
	run, err := store.CreateRun(ctx, Run{TargetSource: TargetSourceAdHoc, TargetLabel: "api.example.com", Protocol: ProtocolOpenAIChat, SuiteID: s1.ID, Status: RunStatusRunning, TotalModels: 6})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			model := fmt.Sprintf("model-%d", idx)
			_, itemErr := store.InsertRunItem(ctx, RunItem{
				RunID:             run.ID,
				ClaimedModel:      model,
				UpstreamModel:     model,
				CanonicalModel:    model,
				Verdict:           VerdictMatch,
				UsedStaleBaseline: idx%2 == 0,
				TopCandidates:     []CandidateScore{{CanonicalModel: model, Distance: 0.01}},
				Evidence:          []ProbeEvidence{{ProbeID: "lp-1", DetectorKind: DetectorLogprobs}},
			})
			require.NoError(t, itemErr)
		}(i)
	}
	wg.Wait()

	items, err := store.ListRunItems(ctx, run.ID)
	require.NoError(t, err)
	require.Len(t, items, 6)

	page, err := store.ListRuns(ctx, 1, 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)

	require.NoError(t, store.DeleteRun(ctx, run.ID))
	itemsAfterDel, err := store.ListRunItems(ctx, run.ID)
	require.NoError(t, err)
	require.Empty(t, itemsAfterDel)
}

func TestPostgresStoreRemainingMethodsAndNilSafety(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// Nil DB guards on PostgresStore must return clear errors without panicking.
	var nilStore *PostgresStore
	_, err := nilStore.GetSuite(ctx, 1)
	require.Error(t, err)
	_, err = NewPostgresStore(nil).ListSuites(ctx)
	require.Error(t, err)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	store := NewPostgresStore(db)

	probesJSON := []byte(`[{"id":"lp-1","kind":"logprobs","prompt":"hi","max_tokens":1,"temperature":0,"weight":1,"expected_max_prompt_tokens":500}]`)
	suiteCols := []string{"id", "suite_key", "version", "name", "visibility", "status", "is_default", "probes_json", "content_hash", "created_by", "created_at", "updated_at"}

	// UpsertSeedSuite
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_probe_suites.*ON\s+CONFLICT\s*\(\s*suite_key\s*,\s*version\s*\)\s+DO\s+UPDATE`).
		WillReturnRows(sqlmock.NewRows(suiteCols).AddRow(int64(1), "builtin-public", "v1", "Builtin", "public", "active", true, probesJSON, "hash1", int64(0), now, now))
	seedSuite, err := store.UpsertSeedSuite(ctx, ProbeSuite{
		SuiteKey:  "builtin-public",
		Version:   "v1",
		Name:      "Builtin",
		IsDefault: true,
		Probes:    []ProbeDefinition{{ID: "lp-1", Kind: DetectorLogprobs, Prompt: "hi", MaxTokens: 1, Weight: 1, ExpectedMaxPromptTokens: 500}},
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), seedSuite.ID)
	require.True(t, seedSuite.IsDefault)

	// CreateSuite happy path with IsDefault=true clears previous defaults.
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)INSERT\s+INTO\s+modelfp_probe_suites`).
		WillReturnRows(sqlmock.NewRows(suiteCols).AddRow(int64(2), "canary", "v1", "Canary", "private", "active", true, probesJSON, "hash2", int64(3), now, now))
	mock.ExpectExec(`(?s)UPDATE\s+modelfp_probe_suites\s+SET\s+is_default\s*=\s*FALSE`).
		WithArgs(int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	createdSuite, err := store.CreateSuite(ctx, ProbeSuite{
		SuiteKey:   "canary",
		Version:    "v1",
		Name:       "Canary",
		Visibility: VisibilityPrivate,
		IsDefault:  true,
		CreatedBy:  3,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), createdSuite.ID)

	// GetSuite + ListSuites
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_probe_suites\s+WHERE\s+id\s*=\s*\$1`).
		WithArgs(int64(2)).
		WillReturnRows(sqlmock.NewRows(suiteCols).AddRow(int64(2), "canary", "v1", "Canary", "private", "active", true, probesJSON, "hash2", int64(3), now, now))
	gotSuite, err := store.GetSuite(ctx, 2)
	require.NoError(t, err)
	require.Equal(t, "canary", gotSuite.SuiteKey)

	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_probe_suites\s+ORDER\s+BY`).
		WillReturnRows(sqlmock.NewRows(suiteCols).
			AddRow(int64(2), "canary", "v1", "Canary", "private", "active", true, probesJSON, "hash2", int64(3), now, now).
			AddRow(int64(1), "builtin-public", "v1", "Builtin", "public", "active", false, probesJSON, "hash1", int64(0), now, now))
	suites, err := store.ListSuites(ctx)
	require.NoError(t, err)
	require.Len(t, suites, 2)

	// GetBaseline (happy + ErrNotFound)
	baselineJoinCols := []string{
		"id", "canonical_model", "protocol", "suite_id", "suite_key", "suite_version", "detector_kind",
		"source_type", "source_label", "upstream_snapshot", "sample_count",
		"signature_json", "self_divergence_p95", "match_threshold", "suspect_threshold",
		"ttl_days", "status", "notes", "collected_at", "created_at", "updated_at",
	}
	baselineRawCols := []string{
		"id", "canonical_model", "protocol", "suite_id", "detector_kind",
		"source_type", "source_label", "upstream_snapshot", "sample_count",
		"signature_json", "self_divergence_p95", "match_threshold", "suspect_threshold",
		"ttl_days", "status", "notes", "collected_at", "created_at", "updated_at",
	}
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_baselines\s+b\s+LEFT\s+JOIN\s+modelfp_probe_suites.*WHERE\s+b\.id\s*=\s*\$1`).
		WithArgs(int64(999)).
		WillReturnError(sql.ErrNoRows)
	_, err = store.GetBaseline(ctx, 999)
	require.ErrorIs(t, err, ErrNotFound)

	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_baselines\s+b\s+LEFT\s+JOIN\s+modelfp_probe_suites.*WHERE\s+b\.id\s*=\s*\$1`).
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows(baselineJoinCols).AddRow(
			int64(5), "gpt-4o", "openai_chat", int64(1), "builtin-public", "v1", "logprobs",
			"official_direct", "official", "", 3, []byte(`{"probes":{"lp-1":{"probe_id":"lp-1","distribution":{"hi":1}}}}`),
			0.01, 0.05, 0.12, 60, "active", "", now, now, now,
		))
	gotBase, err := store.GetBaseline(ctx, 5)
	require.NoError(t, err)
	require.Equal(t, "builtin-public", gotBase.SuiteKey)
	require.NotNil(t, gotBase.Logprobs)

	// UpdateBaseline reactivating archived row archives previous active row in same tuple.
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_baselines\s+b.*WHERE\s+b\.id\s*=\s*\$1\s+FOR\s+UPDATE`).
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows(baselineJoinCols).AddRow(
			int64(5), "gpt-4o", "openai_chat", int64(1), "builtin-public", "v1", "logprobs",
			"official_direct", "official", "", 3, []byte(`{"probes":{"lp-1":{"probe_id":"lp-1","distribution":{"hi":1}}}}`),
			0.01, 0.05, 0.12, 60, "archived", "old", now, now, now,
		))
	mock.ExpectExec(`(?s)UPDATE\s+modelfp_baselines\s+SET\s+status\s*=\s*'archived'.*AND\s+id\s*<>\s*\$5`).
		WithArgs("gpt-4o", "openai_chat", int64(1), "logprobs", int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)UPDATE\s+modelfp_baselines\s+SET\s+match_threshold\s*=\s*\$2.*WHERE\s+id\s*=\s*\$1\s+RETURNING`).
		WithArgs(int64(5), 0.08, 0.12, 60, "active", "restored").
		WillReturnRows(sqlmock.NewRows(baselineRawCols).AddRow(
			int64(5), "gpt-4o", "openai_chat", int64(1), "logprobs",
			"official_direct", "official", "", 3, []byte(`{"probes":{"lp-1":{"probe_id":"lp-1","distribution":{"hi":1}}}}`),
			0.01, 0.08, 0.12, 60, "active", "restored", now, now, now,
		))
	mock.ExpectCommit()

	reactivate := StatusActive
	newMatch := 0.08
	newNote := "restored"
	updBase, err := store.UpdateBaseline(ctx, 5, BaselineUpdate{MatchThreshold: &newMatch, Status: &reactivate, Notes: &newNote})
	require.NoError(t, err)
	require.Equal(t, StatusActive, updBase.Status)
	require.InDelta(t, 0.08, updBase.MatchThreshold, 1e-9)
	require.Equal(t, "builtin-public", updBase.SuiteKey)

	// ListFamilyMaps & DeleteFamilyMap
	mock.ExpectQuery(`(?s)SELECT\s+canonical_model,\s*family,\s*aliases_json,\s*confusion_peers_json,\s*updated_at\s+FROM\s+modelfp_family_maps`).
		WillReturnRows(sqlmock.NewRows([]string{"canonical_model", "family", "aliases_json", "confusion_peers_json", "updated_at"}).
			AddRow("gpt-4o", "gpt-4o", []byte(`["chatgpt-4o-latest"]`), []byte(`["gpt-4o-mini"]`), now))
	fms, err := store.ListFamilyMaps(ctx)
	require.NoError(t, err)
	require.Len(t, fms, 1)

	mock.ExpectExec(`DELETE\s+FROM\s+modelfp_family_maps\s+WHERE\s+canonical_model\s*=\s*\$1`).
		WithArgs("gpt-4o").
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, store.DeleteFamilyMap(ctx, "gpt-4o"))

	// UpdateRunProgress, GetRun, ListRuns, ListRunItems, DeleteRun
	mock.ExpectExec(`(?s)UPDATE\s+modelfp_runs\s+SET\s+status\s*=\s*\$2.*WHERE\s+id\s*=\s*\$1`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, store.UpdateRunProgress(ctx, Run{
		ID:              10,
		Status:          RunStatusCompleted,
		CompletedModels: 2,
		Summary:         RunSummary{Match: 2},
		StartedAt:       &now,
		FinishedAt:      &now,
	}))

	runCols := []string{"id", "target_source", "account_id", "target_label", "protocol", "suite_id", "status", "total_models", "completed_models", "summary_json", "error_message", "created_by", "started_at", "finished_at", "created_at"}
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_runs\s+WHERE\s+id\s*=\s*\$1`).
		WithArgs(int64(10)).
		WillReturnRows(sqlmock.NewRows(runCols).AddRow(int64(10), "adhoc", nil, "api.example.com", "openai_chat", int64(1), "completed", 2, 2, []byte(`{"match":2}`), "", int64(1), now, now, now))
	gotRun, err := store.GetRun(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 2, gotRun.Summary.Match)

	mock.ExpectQuery(`SELECT\s+COUNT\(\*\)\s+FROM\s+modelfp_runs`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_runs\s+ORDER\s+BY\s+created_at\s+DESC.*LIMIT\s+\$1\s+OFFSET\s+\$2`).
		WithArgs(100, 0).
		WillReturnRows(sqlmock.NewRows(runCols).AddRow(int64(10), "adhoc", nil, "api.example.com", "openai_chat", int64(1), "completed", 2, 2, []byte(`{"match":2}`), "", int64(1), now, now, now))
	runPage, err := store.ListRuns(ctx, 0, 500)
	require.NoError(t, err)
	require.Equal(t, 1, runPage.Page)
	require.Equal(t, 100, runPage.PageSize)
	require.Equal(t, int64(1), runPage.Total)
	require.Len(t, runPage.Items, 1)

	itemCols := []string{"id", "run_id", "claimed_model", "upstream_model", "canonical_model", "verdict", "detector_used", "confidence", "distance", "prompt_injection_suspected", "observed_prompt_tokens", "used_stale_baseline", "top_candidates_json", "evidence_json", "latency_ms", "error_code", "error_message", "checked_at"}
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_run_items\s+WHERE\s+run_id\s*=\s*\$1`).
		WithArgs(int64(10)).
		WillReturnRows(sqlmock.NewRows(itemCols).AddRow(
			int64(100), int64(10), "gpt-4o", "gpt-4o", "gpt-4o", "match", "logprobs", 0.95, 0.01, false, 20, false,
			[]byte(`[]`), []byte(`[]`), 50, "", "", now,
		))
	items, err := store.ListRunItems(ctx, 10)
	require.NoError(t, err)
	require.Len(t, items, 1)

	mock.ExpectExec(`DELETE\s+FROM\s+modelfp_runs\s+WHERE\s+id\s*=\s*\$1`).
		WithArgs(int64(10)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, store.DeleteRun(ctx, 10))

	// GetCaptureJob
	jobCols := []string{"id", "status", "protocol", "suite_id", "source_type", "sample_rounds", "total_models", "completed_models", "results_json", "error_message", "created_by", "created_at", "finished_at"}
	mock.ExpectQuery(`(?s)SELECT\s+.*FROM\s+modelfp_capture_jobs\s+WHERE\s+id\s*=\s*\$1`).
		WithArgs(int64(21)).
		WillReturnRows(sqlmock.NewRows(jobCols).AddRow(int64(21), "completed", "openai_chat", int64(1), "official_direct", 3, 1, 1, []byte(`[{"model":"gpt-4o","canonical_model":"gpt-4o"}]`), "", int64(1), now, now))
	gotJob, err := store.GetCaptureJob(ctx, 21)
	require.NoError(t, err)
	require.Equal(t, RunStatusCompleted, gotJob.Status)
	require.Len(t, gotJob.Results, 1)

	require.NoError(t, mock.ExpectationsWereMet())
}
