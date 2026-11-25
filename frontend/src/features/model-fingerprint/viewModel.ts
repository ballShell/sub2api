import type {
  BaselineFilter,
  ConfusionMatrixResult,
  Freshness,
  Protocol,
  RunItem,
  RunStatus,
  Verdict,
  WhitelistFormat,
} from './types'

export const SUPPORTED_PROTOCOLS: readonly Protocol[] = [
  'openai_chat',
  'openai_responses',
  'anthropic',
  'gemini',
]

export const SUPPORTED_APIKEY_PLATFORMS: readonly string[] = [
  'openai',
  'anthropic',
  'gemini',
  'kimi',
  'zhipu',
  'deepseek',
  'minimax',
]

const TERMINAL_RUN_STATUSES: ReadonlySet<string> = new Set([
  'completed',
  'cancelled',
  'failed',
])

export interface BadgeMeta {
  labelKey: string
  tone: string
  badgeClass: string
}

const VERDICT_BADGE_MAP: Record<Verdict, BadgeMeta> = {
  match: {
    labelKey: 'admin.modelFingerprint.verdicts.match',
    tone: 'success',
    badgeClass:
      'border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800/60 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
  suspect: {
    labelKey: 'admin.modelFingerprint.verdicts.suspect',
    tone: 'warning',
    badgeClass:
      'border border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800/60 dark:bg-amber-950/40 dark:text-amber-300',
  },
  mismatch: {
    labelKey: 'admin.modelFingerprint.verdicts.mismatch',
    tone: 'danger',
    badgeClass:
      'border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300',
  },
  unverified: {
    labelKey: 'admin.modelFingerprint.verdicts.unverified',
    tone: 'neutral',
    badgeClass:
      'border border-slate-200 bg-slate-100 text-slate-700 dark:border-dark-600 dark:bg-dark-800 dark:text-dark-300',
  },
  error: {
    labelKey: 'admin.modelFingerprint.verdicts.error',
    tone: 'error',
    badgeClass:
      'border border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-800/60 dark:bg-rose-950/40 dark:text-rose-300',
  },
}

const RUN_STATUS_BADGE_MAP: Record<RunStatus, BadgeMeta> = {
  queued: {
    labelKey: 'admin.modelFingerprint.runStatus.queued',
    tone: 'neutral',
    badgeClass:
      'border border-slate-200 bg-slate-100 text-slate-700 dark:border-dark-600 dark:bg-dark-800 dark:text-dark-300',
  },
  running: {
    labelKey: 'admin.modelFingerprint.runStatus.running',
    tone: 'info',
    badgeClass:
      'border border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-800/60 dark:bg-sky-950/40 dark:text-sky-300',
  },
  completed: {
    labelKey: 'admin.modelFingerprint.runStatus.completed',
    tone: 'success',
    badgeClass:
      'border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800/60 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
  cancelled: {
    labelKey: 'admin.modelFingerprint.runStatus.cancelled',
    tone: 'warning',
    badgeClass:
      'border border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800/60 dark:bg-amber-950/40 dark:text-amber-300',
  },
  failed: {
    labelKey: 'admin.modelFingerprint.runStatus.failed',
    tone: 'danger',
    badgeClass:
      'border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300',
  },
}

const FRESHNESS_BADGE_MAP: Record<Freshness, BadgeMeta> = {
  fresh: {
    labelKey: 'admin.modelFingerprint.freshness.fresh',
    tone: 'success',
    badgeClass:
      'border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800/60 dark:bg-emerald-950/40 dark:text-emerald-300',
  },
  stale: {
    labelKey: 'admin.modelFingerprint.freshness.stale',
    tone: 'warning',
    badgeClass:
      'border border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800/60 dark:bg-amber-950/40 dark:text-amber-300',
  },
}

/**
 * Splits raw model list input on newlines, commas, or semicolons, trims tokens,
 * drops empty segments, and deduplicates preserving first-seen order.
 */
export function parseModelInput(raw: string): string[] {
  if (!raw) return []
  const seen = new Set<string>()
  const out: string[] = []
  for (const segment of raw.split(/[\r\n,;]+/)) {
    const trimmed = segment.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    out.push(trimmed)
  }
  return out
}

/**
 * Extracts deduplicated claimed model names from run items.
 * Defaults to selecting ONLY `verdict === 'match'`, optionally including `'unverified'`.
 */
export function extractVerifiedModels(
  items: readonly RunItem[],
  includeUnverified = false,
): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const item of items) {
    const eligible =
      item.verdict === 'match' || (includeUnverified && item.verdict === 'unverified')
    if (!eligible) continue
    const model = item.claimed_model?.trim()
    if (!model || seen.has(model)) continue
    seen.add(model)
    out.push(model)
  }
  return out
}

/**
 * Formats verified models for clipboard export in newline, comma, or JSON object form.
 */
export function formatVerifiedWhitelist(
  items: readonly RunItem[],
  format: WhitelistFormat,
  includeUnverified = false,
): string {
  const models = extractVerifiedModels(items, includeUnverified)
  switch (format) {
    case 'lines':
      return models.join('\n')
    case 'comma':
      return models.join(',')
    case 'json':
      return JSON.stringify(Object.fromEntries(models.map((m) => [m, m])), null, 2)
  }
}

export function verdictBadgeMeta(verdict: Verdict): BadgeMeta {
  return VERDICT_BADGE_MAP[verdict] ?? VERDICT_BADGE_MAP.unverified
}

export function runStatusBadgeMeta(status: RunStatus | string): BadgeMeta {
  if (status in RUN_STATUS_BADGE_MAP) {
    return RUN_STATUS_BADGE_MAP[status as RunStatus]
  }
  return RUN_STATUS_BADGE_MAP.queued
}

export function freshnessBadgeMeta(freshness: Freshness | string): BadgeMeta {
  if (freshness === 'stale') {
    return FRESHNESS_BADGE_MAP.stale
  }
  return FRESHNESS_BADGE_MAP.fresh
}

export function isTerminalRunStatus(status: string): boolean {
  return TERMINAL_RUN_STATUSES.has(status)
}

export function baselineQueryParams(filter: BaselineFilter = {}): Record<string, string | number> {
  const params: Record<string, string | number> = {}
  if (filter.protocol) {
    params.protocol = filter.protocol
  }
  if (
    typeof filter.suite_id === 'number' &&
    Number.isInteger(filter.suite_id) &&
    filter.suite_id > 0
  ) {
    params.suite_id = filter.suite_id
  }
  const canonicalModel = filter.canonical_model?.trim()
  if (canonicalModel) {
    params.canonical_model = canonicalModel
  }
  if (filter.detector_kind) {
    params.detector_kind = filter.detector_kind
  }
  if (filter.status) {
    params.status = filter.status
  }
  if (filter.visibility) {
    params.visibility = filter.visibility
  }
  return params
}

/**
 * Mirrors backend account_resolver.go eligibility: standalone REST API-key accounts only
 * (excludes OAuth, setup-token, shadow accounts, and unsupported non-REST platforms).
 */
export function isEligibleFingerprintAccount(account: {
  type?: string | null
  platform?: string | null
  parent_account_id?: number | null
}): boolean {
  if (account.parent_account_id != null) {
    return false
  }
  const accountType = (account.type ?? '').trim().toLowerCase()
  if (accountType !== 'apikey' && accountType !== 'upstream') {
    return false
  }
  const platform = (account.platform ?? '').trim().toLowerCase()
  return SUPPORTED_APIKEY_PLATFORMS.includes(platform)
}

export function isCloseConfusionPair(
  result: ConfusionMatrixResult,
  modelA: string,
  modelB: string,
): boolean {
  if (!result?.close_pairs?.length || modelA === modelB) {
    return false
  }
  return result.close_pairs.some(
    (pair) =>
      (pair.model_a === modelA && pair.model_b === modelB) ||
      (pair.model_a === modelB && pair.model_b === modelA),
  )
}

export interface ConfusionCellMeta {
  tone: 'diagonal' | 'overlap' | 'caution' | 'clear'
  cellClass: string
}

export function confusionCellMeta(
  distance: number,
  isDiagonal: boolean,
  isClosePair: boolean,
): ConfusionCellMeta {
  if (isDiagonal) {
    return {
      tone: 'diagonal',
      cellClass: 'bg-gray-100 text-gray-500 dark:bg-dark-800 dark:text-dark-400',
    }
  }
  if (isClosePair) {
    return {
      tone: 'overlap',
      cellClass:
        'bg-red-50 font-semibold text-red-700 ring-1 ring-inset ring-red-300 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-800/70',
    }
  }
  if (distance < 0.2) {
    return {
      tone: 'caution',
      cellClass:
        'bg-amber-50 text-amber-800 dark:bg-amber-950/30 dark:text-amber-300',
    }
  }
  return {
    tone: 'clear',
    cellClass:
      'bg-emerald-50/70 text-emerald-800 dark:bg-emerald-950/25 dark:text-emerald-300',
  }
}
