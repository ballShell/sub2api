export type Protocol = 'openai_chat' | 'openai_responses' | 'anthropic' | 'gemini'

export type DetectorKind = 'logprobs' | 'behavior'

export type Verdict = 'match' | 'suspect' | 'mismatch' | 'unverified' | 'error'

export type Visibility = 'public' | 'private'

export type Status = 'active' | 'archived'

export type Freshness = 'fresh' | 'stale'

export type TargetSource = 'adhoc' | 'account'

export type SourceType =
  | 'official_direct'
  | 'trusted_cloud'
  | 'cross_verified'
  | 'community_seed'

export type RunStatus = 'queued' | 'running' | 'completed' | 'cancelled' | 'failed'

export type ImportConflictMode = 'skip' | 'overwrite'

export type WhitelistFormat = 'lines' | 'comma' | 'json'

export interface ProbeDefinition {
  id: string
  kind: DetectorKind
  prompt: string
  system_prompt?: string
  max_tokens: number
  temperature: number
  top_logprobs?: number
  seed?: number | null
  weight: number
  expected_max_prompt_tokens: number
  expected_format?: string
  description?: string
}

export interface CreateSuiteProbeInput {
  id: string
  kind: DetectorKind
  prompt: string
  system_prompt?: string
  max_tokens?: number
  temperature?: number
  top_logprobs?: number
  seed?: number | null
  weight?: number
  expected_max_prompt_tokens?: number
  expected_format?: string
  description?: string
}

export interface ProbeSuite {
  id: number
  suite_key: string
  version: string
  name: string
  visibility: Visibility
  status: Status
  is_default: boolean
  probes: ProbeDefinition[]
  content_hash: string
  created_by?: number
  created_at: string
  updated_at: string
}

export interface TokenProb {
  token: string
  prob: number
  logprob?: number
}

export interface LogprobsProbeSignature {
  probe_id: string
  distribution: Record<string, number>
  top_tokens?: TokenProb[]
  sample_count?: number
}

export interface LogprobsSignature {
  probes: Record<string, LogprobsProbeSignature>
}

export interface BehaviorProbeSignature {
  probe_id: string
  samples: string[]
  expected_format?: string
  format_match_rate?: number
}

export interface BehaviorSignature {
  probes: Record<string, BehaviorProbeSignature>
  response_models?: string[]
  system_fingerprints?: string[]
  has_reasoning_field?: boolean | null
}

export interface Baseline {
  id: number
  canonical_model: string
  protocol: Protocol
  suite_id: number
  suite_key?: string
  suite_version?: string
  detector_kind: DetectorKind
  source_type: SourceType
  source_label: string
  upstream_snapshot?: string
  sample_count: number
  logprobs?: LogprobsSignature | null
  behavior?: BehaviorSignature | null
  self_divergence_p95: number
  match_threshold: number
  suspect_threshold: number
  ttl_days: number
  status: Status
  notes?: string
  collected_at: string
  created_at: string
  updated_at: string
}

export interface BaselineView extends Baseline {
  freshness: Freshness
  expires_at: string
}

export interface FamilyMap {
  canonical_model: string
  family: string
  aliases: string[]
  confusion_peers: string[]
  updated_at?: string
}

export interface UpsertFamilyMapRequest {
  canonical_model?: string
  family: string
  aliases: string[]
  confusion_peers: string[]
}

export interface AdHocTargetInput {
  protocol: Protocol
  base_url: string
  api_key: string
  auth_mode?: string
  proxy_id?: number | null
  extra_headers?: Record<string, string>
}

export interface CandidateScore {
  canonical_model: string
  baseline_id?: number
  distance: number
  similarity: number
  match_threshold?: number
  suspect_threshold?: number
  within_match: boolean
  is_confusion_peer?: boolean
  freshness?: Freshness
}

export interface ProbeEvidence {
  probe_id: string
  detector_kind: DetectorKind
  distance: number
  weight: number
  response_model?: string
  system_fingerprint?: string
  has_reasoning_field?: boolean
  prompt_tokens?: number
  cached_prompt_tokens?: number
  output_tokens?: number
  prompt_injection_suspected?: boolean
  logprobs_supported?: boolean
  top_k_overlap?: number
  observed_top_tokens?: TokenProb[]
  baseline_top_tokens?: TokenProb[]
  observed_text?: string
  baseline_sample_text?: string
  latency_ms?: number
  http_status?: number
  error_code?: string
  error_message?: string
}

export interface RunSummary {
  match: number
  suspect: number
  mismatch: number
  unverified: number
  error: number
  injection_suspected: number
}

export interface Run {
  id: number
  target_source: TargetSource
  account_id?: number | null
  target_label: string
  protocol: Protocol
  suite_id: number
  status: RunStatus
  total_models: number
  completed_models: number
  summary: RunSummary
  error_message?: string
  created_by?: number
  started_at?: string | null
  finished_at?: string | null
  created_at: string
}

export interface RunItem {
  id: number
  run_id: number
  claimed_model: string
  upstream_model: string
  canonical_model: string
  verdict: Verdict
  detector_used?: DetectorKind
  confidence: number
  distance: number
  prompt_injection_suspected: boolean
  observed_prompt_tokens: number
  used_stale_baseline?: boolean
  top_candidates: CandidateScore[]
  evidence: ProbeEvidence[]
  latency_ms: number
  error_code?: string
  error_message?: string
  checked_at: string
}

export interface RunDetail extends Run {
  items: RunItem[]
}

export interface RunPage {
  items: Run[]
  total: number
  page: number
  page_size: number
}

export interface CaptureModelResult {
  model: string
  canonical_model: string
  logprobs_baseline_id?: number | null
  behavior_baseline_id?: number | null
  logprobs_self_div_p95?: number | null
  logprobs_nearest_dist?: number | null
  behavior_self_div_p95?: number | null
  behavior_nearest_dist?: number | null
  overlap_warning: boolean
  overlap_details?: string[]
  error?: string
}

export interface CaptureJob {
  id: number
  status: RunStatus
  protocol: Protocol
  suite_id: number
  source_type: SourceType
  sample_rounds: number
  total_models: number
  completed_models: number
  results: CaptureModelResult[]
  error_message?: string
  created_by?: number
  created_at: string
  finished_at?: string | null
}

export interface Bundle {
  schema_version: string
  exported_at: string
  include_private: boolean
  suites: ProbeSuite[]
  family_maps: FamilyMap[]
  baselines: Baseline[]
  sha256: string
}

export interface ConfusionPair {
  model_a: string
  model_b: string
  distance: number
  overlap_warning: boolean
}

export interface ConfusionMatrixResult {
  protocol?: Protocol
  suite_id?: number
  detector_kind?: DetectorKind
  models: string[]
  matrix: number[][]
  close_pairs: ConfusionPair[]
  min_off_diagonal: number
}

export interface DiscoverModelsRequest {
  target_source: TargetSource
  account_id?: number | null
  adhoc?: AdHocTargetInput | null
  protocol?: Protocol
  base_url?: string
  api_key?: string
  auth_mode?: string
  proxy_id?: number | null
  extra_headers?: Record<string, string>
}

export interface DiscoverModelsResponse {
  target_source: TargetSource
  account_id?: number | null
  target_label: string
  protocol: Protocol
  models: string[]
  default_models?: string[]
}

export interface CreateRunRequest {
  target_source: TargetSource
  account_id?: number | null
  adhoc?: AdHocTargetInput | null
  protocol?: Protocol
  base_url?: string
  api_key?: string
  auth_mode?: string
  proxy_id?: number | null
  extra_headers?: Record<string, string>
  suite_id?: number
  models: string[]
  concurrency?: number
}

export interface CancelRunResult {
  cancelled: boolean
}

export interface DeleteResult {
  deleted: boolean
}

export interface BaselineFilter {
  protocol?: Protocol | ''
  suite_id?: number | null
  canonical_model?: string
  detector_kind?: DetectorKind | ''
  status?: Status | ''
  visibility?: Visibility | ''
}

export interface CaptureRequest {
  target_source: TargetSource
  account_id?: number | null
  adhoc?: AdHocTargetInput | null
  protocol?: Protocol
  base_url?: string
  api_key?: string
  auth_mode?: string
  proxy_id?: number | null
  extra_headers?: Record<string, string>
  suite_id?: number
  models: string[]
  source_type?: SourceType
  source_label?: string
  upstream_snapshot?: string
  sample_rounds?: number
  ttl_days?: number
  notes?: string
}

export interface UpdateBaselineRequest {
  match_threshold?: number | null
  suspect_threshold?: number | null
  ttl_days?: number | null
  status?: Status | null
  notes?: string | null
}

export interface ConfusionMatrixRequest {
  protocol: Protocol
  suite_id?: number
  detector_kind?: DetectorKind
}

export interface ImportBundleRequest {
  bundle: Bundle
  conflict_mode?: ImportConflictMode
}

export interface ImportBundleResult {
  suites_imported: number
  suites_skipped: number
  family_maps_imported: number
  family_maps_skipped: number
  baselines_imported: number
  baselines_skipped: number
}

export interface CreateSuiteRequest {
  suite_key: string
  version: string
  name: string
  visibility?: Visibility
  is_default?: boolean
  probes: CreateSuiteProbeInput[]
}

export interface UpdateSuiteStatusRequest {
  status?: Status
  is_default?: boolean | null
}
