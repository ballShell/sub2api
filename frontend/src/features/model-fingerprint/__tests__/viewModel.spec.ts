import { describe, expect, it } from 'vitest'
import type { ConfusionMatrixResult, RunItem } from '../types'
import {
  baselineQueryParams,
  buildTargetPayload,
  confusionCellMeta,
  extractVerifiedModels,
  formatVerifiedWhitelist,
  freshnessBadgeMeta,
  isCloseConfusionPair,
  isEligibleFingerprintAccount,
  isTerminalRunStatus,
  parseModelInput,
  runStatusBadgeMeta,
  verdictBadgeMeta,
} from '../viewModel'

const makeItem = (claimedModel: string, verdict: RunItem['verdict']): RunItem => ({
  id: 1,
  run_id: 10,
  claimed_model: claimedModel,
  upstream_model: claimedModel,
  canonical_model: claimedModel,
  verdict,
  confidence: verdict === 'match' ? 0.96 : 0.2,
  distance: verdict === 'match' ? 0.02 : 0.7,
  prompt_injection_suspected: false,
  observed_prompt_tokens: 18,
  top_candidates: [],
  evidence: [],
  latency_ms: 120,
  checked_at: '2026-11-25T00:00:00Z',
})

describe('Model Fingerprint viewModel helpers', () => {
  describe('parseModelInput', () => {
    it('splits on newlines, commas, and semicolons, trims, and deduplicates preserving first-seen order', () => {
      const raw = `
        gpt-4o, gpt-4o-mini;
        claude-opus-4-6
        gpt-4o; ; claude-sonnet-4-6,
        gemini-2.5-pro\r\n  gpt-4o-mini  ,
      `
      expect(parseModelInput(raw)).toEqual([
        'gpt-4o',
        'gpt-4o-mini',
        'claude-opus-4-6',
        'claude-sonnet-4-6',
        'gemini-2.5-pro',
      ])
    })

    it('returns an empty array for empty or delimiter-only input', () => {
      expect(parseModelInput('')).toEqual([])
      expect(parseModelInput('  \n , ; \r\n ')).toEqual([])
    })
  })

  describe('formatVerifiedWhitelist', () => {
    const items: RunItem[] = [
      makeItem('gpt-4o', 'match'),
      makeItem('claude-opus-4-6', 'suspect'),
      makeItem('gpt-5', 'mismatch'),
      makeItem('custom-preview', 'unverified'),
      makeItem('broken-model', 'error'),
      makeItem(' gpt-4o ', 'match'),
      makeItem('claude-sonnet-4-6', 'match'),
    ]

    it('selects ONLY verdict === match by default', () => {
      expect(extractVerifiedModels(items)).toEqual(['gpt-4o', 'claude-sonnet-4-6'])
      expect(formatVerifiedWhitelist(items, 'lines')).toBe('gpt-4o\nclaude-sonnet-4-6')
      expect(formatVerifiedWhitelist(items, 'comma')).toBe('gpt-4o,claude-sonnet-4-6')
      expect(JSON.parse(formatVerifiedWhitelist(items, 'json'))).toEqual({
        'gpt-4o': 'gpt-4o',
        'claude-sonnet-4-6': 'claude-sonnet-4-6',
      })
    })

    it('optionally includes unverified items when includeUnverified is true while still excluding suspect/mismatch/error', () => {
      expect(extractVerifiedModels(items, true)).toEqual([
        'gpt-4o',
        'custom-preview',
        'claude-sonnet-4-6',
      ])
      expect(formatVerifiedWhitelist(items, 'lines', true)).toBe(
        'gpt-4o\ncustom-preview\nclaude-sonnet-4-6',
      )
      expect(formatVerifiedWhitelist(items, 'comma', true)).toBe(
        'gpt-4o,custom-preview,claude-sonnet-4-6',
      )
      expect(JSON.parse(formatVerifiedWhitelist(items, 'json', true))).toEqual({
        'gpt-4o': 'gpt-4o',
        'custom-preview': 'custom-preview',
        'claude-sonnet-4-6': 'claude-sonnet-4-6',
      })
    })

    it('handles empty verified sets gracefully across all formats', () => {
      const onlyFailures = [makeItem('bad', 'mismatch'), makeItem('err', 'error')]
      expect(formatVerifiedWhitelist(onlyFailures, 'lines')).toBe('')
      expect(formatVerifiedWhitelist(onlyFailures, 'comma')).toBe('')
      expect(JSON.parse(formatVerifiedWhitelist(onlyFailures, 'json'))).toEqual({})
    })
  })

  describe('verdictBadgeMeta and status helpers', () => {
    it('returns distinct badge metadata for all five verdicts', () => {
      const verdicts = ['match', 'suspect', 'mismatch', 'unverified', 'error'] as const
      const metas = verdicts.map((verdict) => verdictBadgeMeta(verdict))
      const labelKeys = new Set(metas.map((m) => m.labelKey))
      const tones = new Set(metas.map((m) => m.tone))

      expect(labelKeys.size).toBe(5)
      expect(tones.size).toBe(5)
      for (const meta of metas) {
        expect(meta.labelKey).toMatch(/^admin\.modelFingerprint\.verdicts\./)
        expect(meta.badgeClass.length).toBeGreaterThan(0)
      }
    })

    it('identifies terminal vs active run statuses accurately', () => {
      expect(isTerminalRunStatus('queued')).toBe(false)
      expect(isTerminalRunStatus('running')).toBe(false)
      expect(isTerminalRunStatus('completed')).toBe(true)
      expect(isTerminalRunStatus('cancelled')).toBe(true)
      expect(isTerminalRunStatus('failed')).toBe(true)
      expect(isTerminalRunStatus('unknown')).toBe(false)
    })

    it('provides badge metadata for run statuses and baseline freshness', () => {
      expect(runStatusBadgeMeta('running').labelKey).toBe('admin.modelFingerprint.runStatus.running')
      expect(runStatusBadgeMeta('completed').labelKey).toBe('admin.modelFingerprint.runStatus.completed')
      expect(freshnessBadgeMeta('fresh').labelKey).toBe('admin.modelFingerprint.freshness.fresh')
      expect(freshnessBadgeMeta('stale').labelKey).toBe('admin.modelFingerprint.freshness.stale')
    })
  })

  describe('baselineQueryParams, account eligibility, and confusion matrix helpers', () => {
    it('strips empty or invalid baseline filter properties', () => {
      expect(
        baselineQueryParams({
          protocol: '',
          suite_id: 0,
          canonical_model: '   ',
          detector_kind: '',
          status: undefined,
          visibility: 'private',
        }),
      ).toEqual({ visibility: 'private' })
    })

    it('filters eligible standalone REST API key accounts and rejects OAuth/shadow/non-REST accounts', () => {
      expect(isEligibleFingerprintAccount({ type: 'apikey', platform: 'openai', parent_account_id: null })).toBe(true)
      expect(isEligibleFingerprintAccount({ type: 'upstream', platform: 'anthropic', parent_account_id: null })).toBe(true)
      expect(isEligibleFingerprintAccount({ type: 'apikey', platform: 'deepseek' })).toBe(true)
      expect(isEligibleFingerprintAccount({ type: 'oauth', platform: 'anthropic', parent_account_id: null })).toBe(false)
      expect(isEligibleFingerprintAccount({ type: 'setup-token', platform: 'anthropic', parent_account_id: null })).toBe(false)
      expect(isEligibleFingerprintAccount({ type: 'apikey', platform: 'openai', parent_account_id: 99 })).toBe(false)
      expect(isEligibleFingerprintAccount({ type: 'apikey', platform: 'antigravity', parent_account_id: null })).toBe(false)
    })

    it('maps confusion matrix close pairs and cell styling', () => {
      const result: ConfusionMatrixResult = {
        models: ['claude-opus-4-6', 'claude-sonnet-4-6', 'gpt-4o'],
        matrix: [
          [0, 0.04, 0.72],
          [0.04, 0, 0.75],
          [0.72, 0.75, 0],
        ],
        close_pairs: [
          {
            model_a: 'claude-opus-4-6',
            model_b: 'claude-sonnet-4-6',
            distance: 0.04,
            overlap_warning: true,
          },
        ],
        min_off_diagonal: 0.04,
      }

      expect(isCloseConfusionPair(result, 'claude-opus-4-6', 'claude-sonnet-4-6')).toBe(true)
      expect(isCloseConfusionPair(result, 'claude-sonnet-4-6', 'claude-opus-4-6')).toBe(true)
      expect(isCloseConfusionPair(result, 'claude-opus-4-6', 'gpt-4o')).toBe(false)

      expect(confusionCellMeta(0, true, false).tone).toBe('diagonal')
      expect(confusionCellMeta(0.04, false, true).tone).toBe('overlap')
      expect(confusionCellMeta(0.72, false, false).tone).toBe('clear')
    })

    it('buildTargetPayload omits protocol for account auto mode and includes explicit overrides', () => {
      const autoPayload = buildTargetPayload({
        targetSource: 'account',
        accountId: 12,
        accountProtocol: '',
        adhocProtocol: 'openai_chat',
        baseUrl: '',
        apiKey: '',
        authMode: '',
        proxyId: null,
      })
      expect(autoPayload).toEqual({ target_source: 'account', account_id: 12 })
      expect('protocol' in autoPayload).toBe(false)

      const overridePayload = buildTargetPayload({
        targetSource: 'account',
        accountId: 12,
        accountProtocol: 'openai_responses',
        adhocProtocol: 'openai_chat',
        baseUrl: '',
        apiKey: '',
        authMode: '',
        proxyId: null,
      })
      expect(overridePayload).toEqual({
        target_source: 'account',
        account_id: 12,
        protocol: 'openai_responses',
      })
    })
  })
})
