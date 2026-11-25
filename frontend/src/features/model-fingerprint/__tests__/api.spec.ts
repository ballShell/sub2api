import { beforeEach, describe, expect, it, vi } from 'vitest'

const client = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
}))

vi.mock('@/api/client', () => ({ apiClient: client }))

import modelFingerprintAPI, {
  cancelRun,
  createRun,
  createSuite,
  deleteBaseline,
  deleteFamily,
  deleteRun,
  discoverModels,
  exportBaselines,
  getCaptureJob,
  getConfusionMatrix,
  getRun,
  importBaselines,
  listBaselines,
  listFamilies,
  listRuns,
  listSuites,
  startCapture,
  updateBaseline,
  updateSuiteStatus,
  upsertFamily,
} from '../api'
import type { Bundle } from '../types'

describe('Model Fingerprint API client', () => {
  beforeEach(() => {
    client.get.mockReset()
    client.post.mockReset()
    client.put.mockReset()
    client.delete.mockReset()
  })

  it('exposes all 20 endpoint methods on both named exports and default export', () => {
    expect(modelFingerprintAPI).toMatchObject({
      discoverModels,
      createRun,
      listRuns,
      getRun,
      cancelRun,
      deleteRun,
      listBaselines,
      startCapture,
      getCaptureJob,
      getConfusionMatrix,
      updateBaseline,
      deleteBaseline,
      exportBaselines,
      importBaselines,
      listSuites,
      createSuite,
      updateSuiteStatus,
      listFamilies,
      upsertFamily,
      deleteFamily,
    })
  })

  it('discovers models via POST /admin/model-fingerprint/discover-models', async () => {
    const response = {
      target_source: 'adhoc',
      target_label: 'adhoc https://api.example.com (sk-ab...yz)',
      protocol: 'openai_chat',
      models: ['gpt-4o', 'gpt-4o-mini'],
    }
    client.post.mockResolvedValue({ data: response })

    const payload = {
      target_source: 'adhoc' as const,
      protocol: 'openai_chat' as const,
      base_url: 'https://api.example.com/v1',
      api_key: 'sk-canary-secret-123',
      proxy_id: 7,
    }
    const result = await discoverModels(payload)

    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/discover-models', payload)
    expect(result).toEqual(response)
    expect(JSON.stringify(result)).not.toContain('sk-canary-secret-123')
  })

  it('creates, lists, gets, cancels, and deletes verification runs', async () => {
    const runDetail = { id: 101, status: 'queued', items: [] }
    client.post.mockResolvedValueOnce({ data: runDetail })

    const createPayload = {
      target_source: 'account' as const,
      account_id: 12,
      protocol: 'anthropic' as const,
      suite_id: 3,
      models: ['claude-opus-4-6', 'claude-sonnet-4-6'],
      concurrency: 3,
    }
    const created = await createRun(createPayload)
    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/runs', createPayload)
    expect(created).toEqual(runDetail)

    client.get.mockResolvedValueOnce({ data: { items: [], total: 0, page: 1, page_size: 20 } })
    await listRuns()
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/runs', {
      params: { page: 1, page_size: 20 },
    })

    client.get.mockResolvedValueOnce({ data: { items: [], total: 1, page: 2, page_size: 50 } })
    await listRuns(2, 50)
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/runs', {
      params: { page: 2, page_size: 50 },
    })

    client.get.mockResolvedValueOnce({ data: runDetail })
    const fetched = await getRun(101)
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/runs/101')
    expect(fetched).toEqual(runDetail)

    client.post.mockResolvedValueOnce({ data: { cancelled: true } })
    const cancelRes = await cancelRun(101)
    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/runs/101/cancel')
    expect(cancelRes).toEqual({ cancelled: true })

    client.delete.mockResolvedValueOnce({ data: { deleted: true } })
    const delRes = await deleteRun(101)
    expect(client.delete).toHaveBeenCalledWith('/admin/model-fingerprint/runs/101')
    expect(delRes).toEqual({ deleted: true })
  })

  it('lists baselines with clean optional filters and handles empty filter safely', async () => {
    client.get.mockResolvedValueOnce({ data: [] })
    const emptyRes = await listBaselines()
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/baselines')
    expect(emptyRes).toEqual([])

    client.get.mockResolvedValueOnce({ data: [{ id: 1 }] })
    const filtered = await listBaselines({
      protocol: 'openai_chat',
      suite_id: 2,
      canonical_model: ' gpt-4o ',
      detector_kind: 'logprobs',
      status: 'active',
      visibility: 'public',
    })
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/baselines', {
      params: {
        protocol: 'openai_chat',
        suite_id: 2,
        canonical_model: 'gpt-4o',
        detector_kind: 'logprobs',
        status: 'active',
        visibility: 'public',
      },
    })
    expect(filtered).toEqual([{ id: 1 }])

    client.get.mockResolvedValueOnce({ data: null })
    const invalidSuiteSkipped = await listBaselines({ suite_id: 0, canonical_model: '   ', protocol: '' })
    expect(client.get).toHaveBeenLastCalledWith('/admin/model-fingerprint/baselines')
    expect(invalidSuiteSkipped).toEqual([])
  })

  it('starts and polls capture jobs, computes confusion matrix, and updates/deletes baselines', async () => {
    const capturePayload = {
      target_source: 'adhoc' as const,
      protocol: 'openai_chat' as const,
      base_url: 'https://api.openai.com/v1',
      api_key: 'sk-test',
      models: ['gpt-4o'],
      sample_rounds: 3,
      source_type: 'official_direct' as const,
    }
    client.post.mockResolvedValueOnce({ data: { id: 77, status: 'queued' } })
    await startCapture(capturePayload)
    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/capture', capturePayload)

    client.get.mockResolvedValueOnce({ data: { id: 77, status: 'completed' } })
    await getCaptureJob(77)
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/capture/77')

    const cmPayload = { protocol: 'openai_chat' as const, suite_id: 1, detector_kind: 'logprobs' as const }
    client.post.mockResolvedValueOnce({ data: { models: [], matrix: [], close_pairs: [], min_off_diagonal: 0 } })
    await getConfusionMatrix(cmPayload)
    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/confusion-matrix', cmPayload)

    const updatePayload = { match_threshold: 0.08, suspect_threshold: 0.16, ttl_days: 90, status: 'active' as const, notes: 'ok' }
    client.put.mockResolvedValueOnce({ data: { id: 5, ...updatePayload } })
    await updateBaseline(5, updatePayload)
    expect(client.put).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/5', updatePayload)

    client.delete.mockResolvedValueOnce({ data: { deleted: true } })
    await deleteBaseline(5)
    expect(client.delete).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/5')
  })

  it('exports baselines with include_private=false by default and imports bundles', async () => {
    const sampleBundle: Bundle = {
      schema_version: 'v1',
      exported_at: '2026-11-25T00:00:00Z',
      include_private: false,
      suites: [],
      family_maps: [],
      baselines: [],
      sha256: 'a'.repeat(64),
    }

    client.get.mockResolvedValueOnce({ data: sampleBundle })
    await exportBaselines()
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/export', {
      params: { include_private: false },
    })

    client.get.mockResolvedValueOnce({ data: { ...sampleBundle, include_private: true } })
    await exportBaselines(true)
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/export', {
      params: { include_private: true },
    })

    client.post.mockResolvedValueOnce({
      data: {
        suites_imported: 1,
        suites_skipped: 0,
        family_maps_imported: 1,
        family_maps_skipped: 0,
        baselines_imported: 2,
        baselines_skipped: 0,
      },
    })
    await importBaselines({ bundle: sampleBundle })
    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/baselines/import', {
      bundle: sampleBundle,
      conflict_mode: 'skip',
    })

    client.post.mockResolvedValueOnce({
      data: {
        suites_imported: 0,
        suites_skipped: 1,
        family_maps_imported: 1,
        family_maps_skipped: 0,
        baselines_imported: 2,
        baselines_skipped: 0,
      },
    })
    await importBaselines({ bundle: sampleBundle, conflict_mode: 'overwrite' })
    expect(client.post).toHaveBeenLastCalledWith('/admin/model-fingerprint/baselines/import', {
      bundle: sampleBundle,
      conflict_mode: 'overwrite',
    })
  })

  it('manages probe suites and family maps', async () => {
    client.get.mockResolvedValueOnce({ data: [] })
    await listSuites()
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/suites')

    const suitePayload = {
      suite_key: 'private-canary',
      version: 'v1',
      name: 'Private Canary',
      visibility: 'private' as const,
      probes: [{ id: 'p1', kind: 'behavior' as const, prompt: 'test prompt' }],
    }
    client.post.mockResolvedValueOnce({ data: { id: 9, ...suitePayload } })
    await createSuite(suitePayload)
    expect(client.post).toHaveBeenCalledWith('/admin/model-fingerprint/suites', suitePayload)

    client.put.mockResolvedValueOnce({ data: { id: 9, status: 'archived', is_default: false } })
    await updateSuiteStatus(9, { status: 'archived', is_default: false })
    expect(client.put).toHaveBeenCalledWith('/admin/model-fingerprint/suites/9/status', {
      status: 'archived',
      is_default: false,
    })

    client.get.mockResolvedValueOnce({ data: [] })
    await listFamilies()
    expect(client.get).toHaveBeenCalledWith('/admin/model-fingerprint/families')

    client.put.mockResolvedValueOnce({
      data: { canonical_model: 'openai/gpt-4o', family: 'gpt-4o', aliases: ['gpt-4o'], confusion_peers: [] },
    })
    await upsertFamily('openai/gpt-4o', {
      family: 'gpt-4o',
      aliases: ['gpt-4o'],
      confusion_peers: [],
    })
    expect(client.put).toHaveBeenCalledWith('/admin/model-fingerprint/families/openai%2Fgpt-4o', {
      canonical_model: 'openai/gpt-4o',
      family: 'gpt-4o',
      aliases: ['gpt-4o'],
      confusion_peers: [],
    })

    client.delete.mockResolvedValueOnce({ data: { deleted: true } })
    await deleteFamily('openai/gpt-4o')
    expect(client.delete).toHaveBeenCalledWith('/admin/model-fingerprint/families/openai%2Fgpt-4o')
  })
})
