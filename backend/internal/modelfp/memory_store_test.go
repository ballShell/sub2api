package modelfp

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryStore is a thread-safe in-memory Store implementation for unit tests.
type MemoryStore struct {
	mu          sync.RWMutex
	nextSuiteID int64
	nextBaseID  int64
	nextRunID   int64
	nextItemID  int64
	nextJobID   int64

	suites     map[int64]ProbeSuite
	baselines  map[int64]Baseline
	familyMaps map[string]FamilyMap
	runs       map[int64]Run
	runItems   map[int64][]RunItem
	jobs       map[int64]CaptureJob
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore constructs an empty thread-safe in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		suites:     make(map[int64]ProbeSuite),
		baselines:  make(map[int64]Baseline),
		familyMaps: make(map[string]FamilyMap),
		runs:       make(map[int64]Run),
		runItems:   make(map[int64][]RunItem),
		jobs:       make(map[int64]CaptureJob),
	}
}

func (m *MemoryStore) UpsertSeedSuite(_ context.Context, suite ProbeSuite) (*ProbeSuite, error) {
	norm, _, err := normalizeSuiteForWrite(suite)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for id, existing := range m.suites {
		if existing.SuiteKey == norm.SuiteKey && existing.Version == norm.Version {
			existing.Name = norm.Name
			existing.Visibility = norm.Visibility
			existing.Probes = cloneProbeDefinitions(norm.Probes)
			existing.ContentHash = norm.ContentHash
			existing.UpdatedAt = now
			m.suites[id] = existing
			out := cloneSuite(existing)
			return &out, nil
		}
	}

	hasActiveDefault := false
	for _, existing := range m.suites {
		if existing.IsDefault && existing.Status == StatusActive {
			hasActiveDefault = true
			break
		}
	}

	m.nextSuiteID++
	norm.ID = m.nextSuiteID
	norm.IsDefault = norm.IsDefault && !hasActiveDefault
	norm.Probes = cloneProbeDefinitions(norm.Probes)
	norm.CreatedAt = now
	norm.UpdatedAt = now
	m.suites[norm.ID] = norm
	out := cloneSuite(norm)
	return &out, nil
}

func (m *MemoryStore) CreateSuite(_ context.Context, suite ProbeSuite) (*ProbeSuite, error) {
	norm, _, err := normalizeSuiteForWrite(suite)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.suites {
		if existing.SuiteKey == norm.SuiteKey && existing.Version == norm.Version {
			return nil, ErrSuiteImmutable
		}
	}

	now := time.Now().UTC()
	if norm.IsDefault {
		for id, existing := range m.suites {
			if existing.IsDefault {
				existing.IsDefault = false
				existing.UpdatedAt = now
				m.suites[id] = existing
			}
		}
	}

	m.nextSuiteID++
	norm.ID = m.nextSuiteID
	norm.Probes = cloneProbeDefinitions(norm.Probes)
	norm.CreatedAt = now
	norm.UpdatedAt = now
	m.suites[norm.ID] = norm
	out := cloneSuite(norm)
	return &out, nil
}

func (m *MemoryStore) GetSuite(_ context.Context, id int64) (*ProbeSuite, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	suite, ok := m.suites[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneSuite(suite)
	return &out, nil
}

func (m *MemoryStore) GetDefaultSuite(_ context.Context) (*ProbeSuite, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var best *ProbeSuite
	for _, suite := range m.suites {
		if !suite.IsDefault || suite.Status != StatusActive {
			continue
		}
		if best == nil || suite.ID > best.ID {
			cp := cloneSuite(suite)
			best = &cp
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return best, nil
}

func (m *MemoryStore) ListSuites(_ context.Context) ([]ProbeSuite, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]ProbeSuite, 0, len(m.suites))
	for _, suite := range m.suites {
		out = append(out, cloneSuite(suite))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDefault != out[j].IsDefault {
			return out[i].IsDefault
		}
		if out[i].SuiteKey != out[j].SuiteKey {
			return out[i].SuiteKey < out[j].SuiteKey
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *MemoryStore) UpdateSuiteStatus(_ context.Context, id int64, status Status, isDefault bool) (*ProbeSuite, error) {
	if status == "" {
		status = StatusActive
	}
	if status == StatusArchived {
		isDefault = false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	target, ok := m.suites[id]
	if !ok {
		return nil, ErrNotFound
	}

	now := time.Now().UTC()
	if isDefault {
		for otherID, existing := range m.suites {
			if otherID != id && existing.IsDefault {
				existing.IsDefault = false
				existing.UpdatedAt = now
				m.suites[otherID] = existing
			}
		}
	}

	target.Status = status
	target.IsDefault = isDefault
	target.UpdatedAt = now
	m.suites[id] = target
	out := cloneSuite(target)
	return &out, nil
}

func (m *MemoryStore) UpsertActiveBaseline(_ context.Context, baseline Baseline) (*Baseline, error) {
	norm, _, err := normalizeBaselineForWrite(baseline)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for id, existing := range m.baselines {
		if existing.Status == StatusActive &&
			existing.CanonicalModel == norm.CanonicalModel &&
			existing.Protocol == norm.Protocol &&
			existing.SuiteID == norm.SuiteID &&
			existing.DetectorKind == norm.DetectorKind {
			existing.Status = StatusArchived
			existing.UpdatedAt = now
			m.baselines[id] = existing
		}
	}

	m.nextBaseID++
	norm.ID = m.nextBaseID
	norm.CreatedAt = now
	norm.UpdatedAt = now
	if suite, ok := m.suites[norm.SuiteID]; ok {
		norm.SuiteKey = suite.SuiteKey
		norm.SuiteVersion = suite.Version
	}
	stored := cloneBaseline(norm)
	m.baselines[stored.ID] = stored
	out := cloneBaseline(stored)
	return &out, nil
}

func (m *MemoryStore) ListBaselines(_ context.Context, filter BaselineFilter) ([]Baseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	modelFilter := strings.TrimSpace(filter.CanonicalModel)
	out := make([]Baseline, 0, len(m.baselines))
	for _, b := range m.baselines {
		if filter.Protocol != "" && b.Protocol != filter.Protocol {
			continue
		}
		if filter.SuiteID > 0 && b.SuiteID != filter.SuiteID {
			continue
		}
		if modelFilter != "" && !strings.EqualFold(b.CanonicalModel, modelFilter) {
			continue
		}
		if filter.DetectorKind != "" && b.DetectorKind != filter.DetectorKind {
			continue
		}
		if filter.Status != "" && b.Status != filter.Status {
			continue
		}
		if filter.Visibility != "" {
			suite, ok := m.suites[b.SuiteID]
			if !ok || suite.Visibility != filter.Visibility {
				continue
			}
		}
		cp := cloneBaseline(b)
		if suite, ok := m.suites[cp.SuiteID]; ok {
			cp.SuiteKey = suite.SuiteKey
			cp.SuiteVersion = suite.Version
		}
		out = append(out, cp)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CanonicalModel != out[j].CanonicalModel {
			return out[i].CanonicalModel < out[j].CanonicalModel
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].DetectorKind != out[j].DetectorKind {
			return out[i].DetectorKind < out[j].DetectorKind
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (m *MemoryStore) GetBaseline(_ context.Context, id int64) (*Baseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b, ok := m.baselines[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneBaseline(b)
	if suite, ok := m.suites[out.SuiteID]; ok {
		out.SuiteKey = suite.SuiteKey
		out.SuiteVersion = suite.Version
	}
	return &out, nil
}

func (m *MemoryStore) UpdateBaseline(_ context.Context, id int64, update BaselineUpdate) (*Baseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.baselines[id]
	if !ok {
		return nil, ErrNotFound
	}

	if update.MatchThreshold != nil {
		existing.MatchThreshold = *update.MatchThreshold
	}
	if update.SuspectThreshold != nil {
		existing.SuspectThreshold = *update.SuspectThreshold
	}
	if update.TTLDays != nil {
		existing.TTLDays = *update.TTLDays
	}
	if update.Notes != nil {
		existing.Notes = *update.Notes
	}

	now := time.Now().UTC()
	if update.Status != nil {
		if *update.Status == StatusActive && existing.Status != StatusActive {
			for otherID, other := range m.baselines {
				if otherID != id &&
					other.Status == StatusActive &&
					other.CanonicalModel == existing.CanonicalModel &&
					other.Protocol == existing.Protocol &&
					other.SuiteID == existing.SuiteID &&
					other.DetectorKind == existing.DetectorKind {
					other.Status = StatusArchived
					other.UpdatedAt = now
					m.baselines[otherID] = other
				}
			}
		}
		existing.Status = *update.Status
	}

	existing.UpdatedAt = now
	m.baselines[id] = existing
	out := cloneBaseline(existing)
	if suite, ok := m.suites[out.SuiteID]; ok {
		out.SuiteKey = suite.SuiteKey
		out.SuiteVersion = suite.Version
	}
	return &out, nil
}

func (m *MemoryStore) DeleteBaseline(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.baselines[id]; !ok {
		return ErrNotFound
	}
	delete(m.baselines, id)
	return nil
}

func (m *MemoryStore) UpsertFamilyMap(_ context.Context, fm FamilyMap) (*FamilyMap, error) {
	canon := strings.TrimSpace(fm.CanonicalModel)
	if canon == "" {
		return nil, errors.New("canonical_model is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	stored := FamilyMap{
		CanonicalModel: canon,
		Family:         strings.TrimSpace(fm.Family),
		Aliases:        cloneStringSlice(fm.Aliases),
		ConfusionPeers: cloneStringSlice(fm.ConfusionPeers),
		UpdatedAt:      time.Now().UTC(),
	}
	m.familyMaps[canon] = stored
	out := cloneFamilyMap(stored)
	return &out, nil
}

func (m *MemoryStore) ListFamilyMaps(_ context.Context) ([]FamilyMap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]FamilyMap, 0, len(m.familyMaps))
	for _, fm := range m.familyMaps {
		out = append(out, cloneFamilyMap(fm))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].CanonicalModel < out[j].CanonicalModel
	})
	return out, nil
}

func (m *MemoryStore) DeleteFamilyMap(_ context.Context, canonicalModel string) error {
	canon := strings.TrimSpace(canonicalModel)
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.familyMaps[canon]; !ok {
		return ErrNotFound
	}
	delete(m.familyMaps, canon)
	return nil
}

func (m *MemoryStore) CreateRun(_ context.Context, run Run) (*Run, error) {
	if run.Status == "" {
		run.Status = RunStatusQueued
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextRunID++
	stored := cloneRun(run)
	stored.ID = m.nextRunID
	stored.CreatedAt = time.Now().UTC()
	m.runs[stored.ID] = stored
	out := cloneRun(stored)
	return &out, nil
}

func (m *MemoryStore) UpdateRunProgress(_ context.Context, run Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.runs[run.ID]
	if !ok {
		return ErrNotFound
	}
	existing.Status = run.Status
	existing.CompletedModels = run.CompletedModels
	existing.Summary = run.Summary
	existing.ErrorMessage = run.ErrorMessage
	if run.StartedAt != nil {
		existing.StartedAt = cloneTimePtr(run.StartedAt)
	}
	if run.FinishedAt != nil {
		existing.FinishedAt = cloneTimePtr(run.FinishedAt)
	}
	m.runs[run.ID] = existing
	return nil
}

func (m *MemoryStore) GetRun(_ context.Context, id int64) (*Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	run, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneRun(run)
	return &out, nil
}

func (m *MemoryStore) ListRuns(_ context.Context, page, pageSize int) (*RunPage, error) {
	page, pageSize = normalizePagination(page, pageSize)

	m.mu.RLock()
	defer m.mu.RUnlock()

	all := make([]Run, 0, len(m.runs))
	for _, r := range m.runs {
		all = append(all, cloneRun(r))
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID > all[j].ID
	})

	total := int64(len(all))
	start := (page - 1) * pageSize
	if start >= len(all) {
		return &RunPage{Items: []Run{}, Total: total, Page: page, PageSize: pageSize}, nil
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	return &RunPage{
		Items:    all[start:end],
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func (m *MemoryStore) DeleteRun(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.runs[id]; !ok {
		return ErrNotFound
	}
	delete(m.runs, id)
	delete(m.runItems, id)
	return nil
}

func (m *MemoryStore) InsertRunItem(_ context.Context, item RunItem) (*RunItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.runs[item.RunID]; !ok {
		return nil, ErrNotFound
	}
	m.nextItemID++
	stored := cloneRunItem(item)
	stored.ID = m.nextItemID
	if stored.CheckedAt.IsZero() {
		stored.CheckedAt = time.Now().UTC()
	}
	m.runItems[stored.RunID] = append(m.runItems[stored.RunID], stored)
	out := cloneRunItem(stored)
	return &out, nil
}

func (m *MemoryStore) ListRunItems(_ context.Context, runID int64) ([]RunItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := m.runItems[runID]
	out := make([]RunItem, len(items))
	for i, it := range items {
		out[i] = cloneRunItem(it)
	}
	return out, nil
}

func (m *MemoryStore) CreateCaptureJob(_ context.Context, job CaptureJob) (*CaptureJob, error) {
	if job.Status == "" {
		job.Status = RunStatusQueued
	}
	if job.SourceType == "" {
		job.SourceType = SourceOfficialDirect
	}
	if job.SampleRounds <= 0 {
		job.SampleRounds = defaultCaptureJobRound
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextJobID++
	stored := cloneCaptureJob(job)
	stored.ID = m.nextJobID
	stored.CreatedAt = time.Now().UTC()
	m.jobs[stored.ID] = stored
	out := cloneCaptureJob(stored)
	return &out, nil
}

func (m *MemoryStore) UpdateCaptureJob(_ context.Context, job CaptureJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.jobs[job.ID]
	if !ok {
		return ErrNotFound
	}
	existing.Status = job.Status
	existing.CompletedModels = job.CompletedModels
	existing.Results = cloneCaptureResults(job.Results)
	existing.ErrorMessage = job.ErrorMessage
	if job.FinishedAt != nil {
		existing.FinishedAt = cloneTimePtr(job.FinishedAt)
	}
	m.jobs[job.ID] = existing
	return nil
}

func (m *MemoryStore) GetCaptureJob(_ context.Context, id int64) (*CaptureJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	job, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneCaptureJob(job)
	return &out, nil
}

func (m *MemoryStore) MarkStaleRunningJobsFailed(_ context.Context, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = defaultRestartReason
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for id, r := range m.runs {
		if r.Status == RunStatusQueued || r.Status == RunStatusRunning {
			r.Status = RunStatusFailed
			r.ErrorMessage = reason
			t := now
			r.FinishedAt = &t
			m.runs[id] = r
		}
	}
	for id, j := range m.jobs {
		if j.Status == RunStatusQueued || j.Status == RunStatusRunning {
			j.Status = RunStatusFailed
			j.ErrorMessage = reason
			t := now
			j.FinishedAt = &t
			m.jobs[id] = j
		}
	}
	return nil
}

func cloneSuite(s ProbeSuite) ProbeSuite {
	s.Probes = cloneProbeDefinitions(s.Probes)
	return s
}

func cloneProbeDefinitions(in []ProbeDefinition) []ProbeDefinition {
	if in == nil {
		return []ProbeDefinition{}
	}
	out := make([]ProbeDefinition, len(in))
	for i, p := range in {
		if p.Seed != nil {
			seed := *p.Seed
			p.Seed = &seed
		}
		out[i] = p
	}
	return out
}

func cloneBaseline(b Baseline) Baseline {
	if b.Logprobs != nil {
		lp := LogprobsSignature{
			Probes: make(map[string]LogprobsProbeSignature, len(b.Logprobs.Probes)),
		}
		for k, v := range b.Logprobs.Probes {
			dist := make(map[string]float64, len(v.Distribution))
			for dk, dv := range v.Distribution {
				dist[dk] = dv
			}
			var top []TokenProb
			if v.TopTokens != nil {
				top = append([]TokenProb(nil), v.TopTokens...)
			}
			lp.Probes[k] = LogprobsProbeSignature{
				ProbeID:      v.ProbeID,
				Distribution: dist,
				TopTokens:    top,
				SampleCount:  v.SampleCount,
			}
		}
		b.Logprobs = &lp
	}
	if b.Behavior != nil {
		bh := BehaviorSignature{
			Probes:             make(map[string]BehaviorProbeSignature, len(b.Behavior.Probes)),
			ResponseModels:     cloneStringSliceIfNonNil(b.Behavior.ResponseModels),
			SystemFingerprints: cloneStringSliceIfNonNil(b.Behavior.SystemFingerprints),
		}
		if b.Behavior.HasReasoningField != nil {
			v := *b.Behavior.HasReasoningField
			bh.HasReasoningField = &v
		}
		for k, v := range b.Behavior.Probes {
			bh.Probes[k] = BehaviorProbeSignature{
				ProbeID:         v.ProbeID,
				Samples:         cloneStringSlice(v.Samples),
				ExpectedFormat:  v.ExpectedFormat,
				FormatMatchRate: v.FormatMatchRate,
			}
		}
		b.Behavior = &bh
	}
	return b
}

func cloneFamilyMap(fm FamilyMap) FamilyMap {
	fm.Aliases = cloneStringSlice(fm.Aliases)
	fm.ConfusionPeers = cloneStringSlice(fm.ConfusionPeers)
	return fm
}

func cloneRun(r Run) Run {
	if r.AccountID != nil {
		v := *r.AccountID
		r.AccountID = &v
	}
	r.StartedAt = cloneTimePtr(r.StartedAt)
	r.FinishedAt = cloneTimePtr(r.FinishedAt)
	return r
}

func cloneRunItem(item RunItem) RunItem {
	if item.TopCandidates == nil {
		item.TopCandidates = []CandidateScore{}
	} else {
		item.TopCandidates = append([]CandidateScore(nil), item.TopCandidates...)
	}
	if item.Evidence == nil {
		item.Evidence = []ProbeEvidence{}
	} else {
		ev := make([]ProbeEvidence, len(item.Evidence))
		for i, e := range item.Evidence {
			if e.ObservedTopTokens != nil {
				e.ObservedTopTokens = append([]TokenProb(nil), e.ObservedTopTokens...)
			}
			if e.BaselineTopTokens != nil {
				e.BaselineTopTokens = append([]TokenProb(nil), e.BaselineTopTokens...)
			}
			ev[i] = e
		}
		item.Evidence = ev
	}
	return item
}

func cloneCaptureJob(job CaptureJob) CaptureJob {
	job.Results = cloneCaptureResults(job.Results)
	job.FinishedAt = cloneTimePtr(job.FinishedAt)
	return job
}

func cloneCaptureResults(in []CaptureModelResult) []CaptureModelResult {
	if in == nil {
		return []CaptureModelResult{}
	}
	out := make([]CaptureModelResult, len(in))
	for i, r := range in {
		if r.LogprobsBaselineID != nil {
			v := *r.LogprobsBaselineID
			r.LogprobsBaselineID = &v
		}
		if r.BehaviorBaselineID != nil {
			v := *r.BehaviorBaselineID
			r.BehaviorBaselineID = &v
		}
		if r.LogprobsSelfDivP95 != nil {
			v := *r.LogprobsSelfDivP95
			r.LogprobsSelfDivP95 = &v
		}
		if r.LogprobsNearestDist != nil {
			v := *r.LogprobsNearestDist
			r.LogprobsNearestDist = &v
		}
		if r.BehaviorSelfDivP95 != nil {
			v := *r.BehaviorSelfDivP95
			r.BehaviorSelfDivP95 = &v
		}
		if r.BehaviorNearestDist != nil {
			v := *r.BehaviorNearestDist
			r.BehaviorNearestDist = &v
		}
		r.OverlapDetails = cloneStringSliceIfNonNil(r.OverlapDetails)
		out[i] = r
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return append([]string(nil), in...)
}

func cloneStringSliceIfNonNil(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}
