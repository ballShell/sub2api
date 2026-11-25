import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import en from '@/i18n/locales/en'
import zh from '@/i18n/locales/zh'
import BaselineManager from '../components/BaselineManager.vue'
import ProbeSuiteManager from '../components/ProbeSuiteManager.vue'
import RunHistoryPanel from '../components/RunHistoryPanel.vue'
import ModelFingerprintView from '../ModelFingerprintView.vue'
import type { BaselineView, Bundle, FamilyMap, ProbeSuite, RunDetail } from '../types'
import { formatModelFpError, inferAccountProtocol, parseExtraHeadersJson } from '../viewModel'

const mocks = vi.hoisted(() => ({
  listAccounts: vi.fn(),
  getAllProxies: vi.fn(),
  listBaselines: vi.fn(),
  startCapture: vi.fn(),
  getCaptureJob: vi.fn(),
  getConfusionMatrix: vi.fn(),
  updateBaseline: vi.fn(),
  deleteBaseline: vi.fn(),
  exportBaselines: vi.fn(),
  importBaselines: vi.fn(),
  listSuites: vi.fn(),
  createSuite: vi.fn(),
  updateSuiteStatus: vi.fn(),
  listFamilies: vi.fn(),
  upsertFamily: vi.fn(),
  deleteFamily: vi.fn(),
  listRuns: vi.fn(),
  getRun: vi.fn(),
  cancelRun: vi.fn(),
  deleteRun: vi.fn(),
  showSuccess: vi.fn(),
  showError: vi.fn(),
  showWarning: vi.fn(),
}))

vi.mock('@/api/admin/accounts', () => ({
  list: mocks.listAccounts,
  default: { list: mocks.listAccounts },
}))

vi.mock('@/api/admin/proxies', () => ({
  getAll: mocks.getAllProxies,
  default: { getAll: mocks.getAllProxies },
}))

vi.mock('../api', () => ({
  default: {
    listBaselines: mocks.listBaselines,
    startCapture: mocks.startCapture,
    getCaptureJob: mocks.getCaptureJob,
    getConfusionMatrix: mocks.getConfusionMatrix,
    updateBaseline: mocks.updateBaseline,
    deleteBaseline: mocks.deleteBaseline,
    exportBaselines: mocks.exportBaselines,
    importBaselines: mocks.importBaselines,
    listSuites: mocks.listSuites,
    createSuite: mocks.createSuite,
    updateSuiteStatus: mocks.updateSuiteStatus,
    listFamilies: mocks.listFamilies,
    upsertFamily: mocks.upsertFamily,
    deleteFamily: mocks.deleteFamily,
    listRuns: mocks.listRuns,
    getRun: mocks.getRun,
    cancelRun: mocks.cancelRun,
    deleteRun: mocks.deleteRun,
    discoverModels: vi.fn(),
    createRun: vi.fn(),
  },
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showSuccess: mocks.showSuccess,
    showError: mocks.showError,
    showWarning: mocks.showWarning,
  }),
}))

vi.mock('@/i18n', () => ({
  i18n: {
    global: {
      t: (key: string) => key,
    },
  },
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      locale: { value: 'en' },
      t: (key: string, params?: Record<string, unknown>) =>
        key.replace(/\{(\w+)\}/g, (_, token) => String(params?.[token] ?? `{${token}}`)),
    }),
  }
})

const AppLayoutStub = { template: '<div><slot /></div>' }
const BaseDialogStub = defineComponent({
  name: 'BaseDialog',
  props: ['show', 'title', 'width'],
  emits: ['close'],
  template: '<div v-if="show" data-test="base-dialog"><slot /><slot name="footer" /></div>',
})
const ConfirmDialogStub = defineComponent({
  name: 'ConfirmDialog',
  props: ['show', 'title', 'message', 'confirmText', 'danger'],
  emits: ['confirm', 'cancel'],
  template:
    '<div v-if="show" data-test="confirm-dialog"><button data-test="confirm-yes" @click="$emit(\'confirm\')">confirm</button></div>',
})
const PaginationStub = defineComponent({
  name: 'Pagination',
  props: ['total', 'page', 'pageSize'],
  emits: ['update:page', 'update:pageSize'],
  template: '<div data-test="pagination">{{ page }}/{{ total }}</div>',
})
const IconStub = { template: '<span />' }

const sampleSuite: ProbeSuite = {
  id: 1,
  suite_key: 'default-core',
  version: 'v1',
  name: 'Default Core',
  visibility: 'public',
  status: 'active',
  is_default: true,
  probes: [
    {
      id: 'p1',
      kind: 'behavior',
      prompt: 'Reply with OK',
      max_tokens: 16,
      temperature: 0,
      weight: 1,
      expected_max_prompt_tokens: 500,
    },
  ],
  content_hash: 'abcdef1234567890',
  created_at: '2026-11-25T00:00:00Z',
  updated_at: '2026-11-25T00:00:00Z',
}

const sampleBaseline: BaselineView = {
  id: 11,
  canonical_model: 'gpt-4o',
  protocol: 'openai_chat',
  suite_id: 1,
  suite_key: 'default-core',
  suite_version: 'v1',
  detector_kind: 'logprobs',
  source_type: 'official_direct',
  source_label: 'OpenAI Official',
  upstream_snapshot: 'gpt-4o-2024-08-06',
  sample_count: 3,
  self_divergence_p95: 0.021,
  match_threshold: 0.06,
  suspect_threshold: 0.14,
  ttl_days: 90,
  status: 'active',
  collected_at: '2026-11-25T00:00:00Z',
  created_at: '2026-11-25T00:00:00Z',
  updated_at: '2026-11-25T00:00:00Z',
  freshness: 'fresh',
  expires_at: '2027-02-23T00:00:00Z',
}

const sampleFamily: FamilyMap = {
  canonical_model: 'claude-opus-4-6',
  family: 'claude-4.6',
  aliases: ['opus-4-6'],
  confusion_peers: ['claude-sonnet-4-6'],
}

const here = dirname(fileURLToPath(import.meta.url))
const read = (path: string) => readFileSync(resolve(here, path), 'utf8')

describe('Model Fingerprint Workbench & Integration Surface', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    Object.values(mocks).forEach((m) => m.mockReset())

    mocks.listAccounts.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 500, pages: 1 })
    mocks.getAllProxies.mockResolvedValue([])
    mocks.listSuites.mockResolvedValue([sampleSuite])
    mocks.listBaselines.mockResolvedValue([sampleBaseline])
    mocks.listFamilies.mockResolvedValue([sampleFamily])
    mocks.listRuns.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('registers route in router/index.ts and sidebar entry under Channels in AppSidebar.vue', () => {
    const router = read('../../../router/index.ts')
    expect(router).toContain("path: '/admin/model-fingerprint'")
    expect(router).toContain("name: 'AdminModelFingerprint'")
    expect(router).toContain("titleKey: 'admin.modelFingerprint.title'")
    expect(router).toContain("descriptionKey: 'admin.modelFingerprint.description'")

    const sidebar = read('../../../components/layout/AppSidebar.vue')
    const channelsSlice = sidebar.slice(
      sidebar.indexOf("path: '/admin/channels'"),
      sidebar.indexOf("path: '/admin/subscriptions'"),
    )
    expect(channelsSlice).toContain("path: '/admin/channels/monitor'")
    expect(channelsSlice).toContain("path: '/admin/model-fingerprint'")
    expect(channelsSlice).toContain("t('nav.modelFingerprint')")

    expect(Object.keys(zh.admin.modelFingerprint)).toEqual(Object.keys(en.admin.modelFingerprint))
    expect(zh.nav.modelFingerprint).toBeTruthy()
    expect(en.nav.modelFingerprint).toBeTruthy()
  })

  it('switches across all 4 tabs in ModelFingerprintView', async () => {
    const wrapper = mount(ModelFingerprintView, {
      global: {
        stubs: {
          AppLayout: AppLayoutStub,
          VerifyWorkbench: { template: '<div data-test="verify-stub" />' },
          BaselineManager: { template: '<div data-test="baselines-stub" />' },
          ProbeSuiteManager: { template: '<div data-test="suites-stub" />' },
          RunHistoryPanel: { template: '<div data-test="runs-stub" />' },
        },
      },
    })
    await flushPromises()

    expect(wrapper.get('[data-test="tab-verify"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.get('[data-test="tab-panel-verify"]').attributes('style') || '').not.toContain('display: none')

    await wrapper.get('[data-test="tab-baselines"]').trigger('click')
    expect(wrapper.get('[data-test="tab-baselines"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.get('[data-test="tab-panel-baselines"]').attributes('style') || '').not.toContain('display: none')

    await wrapper.get('[data-test="tab-suites"]').trigger('click')
    expect(wrapper.get('[data-test="tab-suites"]').attributes('aria-selected')).toBe('true')

    await wrapper.get('[data-test="tab-runs"]').trigger('click')
    expect(wrapper.get('[data-test="tab-runs"]').attributes('aria-selected')).toBe('true')
  })

  it('BaselineManager supports export with include_private=false by default, confusion matrix, and family upsert/delete', async () => {
    const bundle: Bundle = {
      schema_version: 'v1',
      exported_at: '2026-11-25T00:00:00Z',
      include_private: false,
      suites: [sampleSuite],
      family_maps: [sampleFamily],
      baselines: [],
      sha256: 'a'.repeat(64),
    }
    mocks.exportBaselines.mockResolvedValue(bundle)
    mocks.getConfusionMatrix.mockResolvedValue({
      protocol: 'openai_chat',
      suite_id: 1,
      detector_kind: 'logprobs',
      models: ['gpt-4o', 'gpt-4o-mini'],
      matrix: [
        [0, 0.04],
        [0.04, 0],
      ],
      close_pairs: [{ model_a: 'gpt-4o', model_b: 'gpt-4o-mini', distance: 0.04, overlap_warning: true }],
      min_off_diagonal: 0.04,
    })
    mocks.upsertFamily.mockResolvedValue(sampleFamily)
    mocks.deleteFamily.mockResolvedValue({ deleted: true })

    const wrapper = mount(BaselineManager, {
      global: {
        stubs: {
          BaseDialog: BaseDialogStub,
          ConfirmDialog: ConfirmDialogStub,
          Icon: IconStub,
        },
      },
    })
    await flushPromises()

    expect(wrapper.get('[data-test="baselines-table"]').text()).toContain('gpt-4o')

    // Export modal defaults include_private to false
    await wrapper.get('[data-test="open-export-btn"]').trigger('click')
    const checkbox = wrapper.get<HTMLInputElement>('[data-test="export-include-private"]')
    expect(checkbox.element.checked).toBe(false)
    await wrapper.get('[data-test="run-export-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.exportBaselines).toHaveBeenCalledWith(false)
    expect(wrapper.text()).toContain('a'.repeat(64))

    // Confusion matrix modal
    await wrapper.get('[data-test="open-confusion-btn"]').trigger('click')
    await wrapper.get('[data-test="compute-confusion-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.getConfusionMatrix).toHaveBeenCalledWith(
      expect.objectContaining({ protocol: 'openai_chat', detector_kind: 'logprobs' }),
    )
    expect(wrapper.text()).toContain('gpt-4o-mini')

    // Family maps modal
    await wrapper.get('[data-test="open-families-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.listFamilies).toHaveBeenCalled()
    await wrapper.get('[data-test="family-canonical-input"]').setValue('deepseek-v3')
    await wrapper.get('[data-test="family-name-input"]').setValue('deepseek')
    await wrapper.get('[data-test="family-aliases-input"]').setValue('deepseek-chat')
    await wrapper.get('[data-test="family-peers-input"]').setValue('deepseek-r1')
    await wrapper.get('[data-test="save-family-btn"]').trigger('submit')
    await flushPromises()
    expect(mocks.upsertFamily).toHaveBeenCalledWith('deepseek-v3', {
      family: 'deepseek',
      aliases: ['deepseek-chat'],
      confusion_peers: ['deepseek-r1'],
    })
  })

  it('ProbeSuiteManager supports cloning a suite into a new private canary version and updating suite status', async () => {
    mocks.createSuite.mockResolvedValue({ ...sampleSuite, id: 2, version: 'v2', visibility: 'private' })
    mocks.updateSuiteStatus.mockResolvedValue({ ...sampleSuite, status: 'archived', is_default: false })

    const wrapper = mount(ProbeSuiteManager, {
      global: { stubs: { BaseDialog: BaseDialogStub, Icon: IconStub } },
    })
    await flushPromises()

    await wrapper.get('[data-test="clone-suite-btn"]').trigger('click')
    await wrapper.get('[data-test="suite-visibility-select"]').setValue('private')
    expect(wrapper.find('[data-test="private-suite-hint"]').exists()).toBe(true)

    await wrapper.get('[data-test="submit-suite-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.createSuite).toHaveBeenCalledWith(
      expect.objectContaining({
        suite_key: 'default-core',
        version: 'v2',
        visibility: 'private',
      }),
    )
    expect(wrapper.emitted('suites-changed')).toBeTruthy()

    await wrapper.get('[data-test="toggle-status-suite-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.updateSuiteStatus).toHaveBeenCalledWith(1, {
      status: 'archived',
      is_default: false,
    })
  })

  it('RunHistoryPanel lists runs, views details, and deletes a run', async () => {
    const runDetail: RunDetail = {
      id: 7,
      target_source: 'adhoc',
      target_label: 'adhoc https://api.example.com (sk-12...34)',
      protocol: 'openai_chat',
      suite_id: 1,
      status: 'completed',
      total_models: 1,
      completed_models: 1,
      summary: { match: 1, suspect: 0, mismatch: 0, unverified: 0, error: 0, injection_suspected: 0 },
      created_at: '2026-11-25T00:00:00Z',
      items: [],
    }
    mocks.listRuns.mockResolvedValue({ items: [runDetail], total: 1, page: 1, page_size: 20 })
    mocks.getRun.mockResolvedValue(runDetail)
    mocks.deleteRun.mockResolvedValue({ deleted: true })

    const wrapper = mount(RunHistoryPanel, {
      global: {
        stubs: {
          BaseDialog: BaseDialogStub,
          ConfirmDialog: ConfirmDialogStub,
          Pagination: PaginationStub,
          Icon: IconStub,
        },
      },
    })
    await flushPromises()

    expect(wrapper.get('[data-test="runs-table"]').text()).toContain('#7')
    await wrapper.get('[data-test="view-run-detail-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.getRun).toHaveBeenCalledWith(7)

    await wrapper.get('[data-test="delete-run-btn"]').trigger('click')
    await wrapper.get('[data-test="confirm-yes"]').trigger('click')
    await flushPromises()
    expect(mocks.deleteRun).toHaveBeenCalledWith(7)
  })

  it('covers new viewModel helper functions', () => {
    expect(inferAccountProtocol({ platform: 'anthropic' })).toBe('anthropic')
    expect(inferAccountProtocol({ platform: 'gemini' })).toBe('gemini')
    expect(inferAccountProtocol({ platform: 'openai', extra: { openai_responses_enabled: true } })).toBe(
      'openai_responses',
    )
    expect(inferAccountProtocol({ platform: 'openai' })).toBe('openai_chat')

    expect(parseExtraHeadersJson('')).toEqual({ headers: undefined, valid: true })
    expect(parseExtraHeadersJson('{"X-Test": "ok"}')).toEqual({ headers: { 'X-Test': 'ok' }, valid: true })
    expect(parseExtraHeadersJson('[1,2]')).toEqual({ headers: undefined, valid: false })
    expect(parseExtraHeadersJson('{"X-Num": 123}')).toEqual({ headers: undefined, valid: false })

    const t = (k: string) =>
      k === 'admin.modelFingerprint.errors.MODELFP_SSRF_BLOCKED' ? 'SSRF blocked' : k
    expect(formatModelFpError({ reason: 'MODELFP_SSRF_BLOCKED' }, t, 'fallback')).toBe(
      'SSRF blocked',
    )
    expect(formatModelFpError({ reason: 'UNKNOWN_CODE' }, t, 'fallback')).toBe('fallback')
  })

  it('BaselineManager uses Auto protocol in account capture and binds export warning strictly to returned bundle', async () => {
    mocks.listAccounts.mockResolvedValue({
      items: [{ id: 101, name: 'OpenAI Key', type: 'apikey', platform: 'openai', status: 'active', parent_account_id: null }],
      total: 1,
      page: 1,
      page_size: 500,
      pages: 1,
    })
    mocks.startCapture.mockResolvedValue({
      id: 91,
      status: 'completed',
      protocol: 'openai_responses',
      suite_id: 1,
      source_type: 'official_direct',
      sample_rounds: 3,
      total_models: 1,
      completed_models: 1,
      results: [],
      created_at: '2026-11-25T00:00:00Z',
    })
    const privBundle: Bundle = {
      schema_version: 'v1',
      exported_at: '2026-11-25T00:00:00Z',
      include_private: true,
      suites: [sampleSuite],
      family_maps: [sampleFamily],
      baselines: [],
      sha256: 'b'.repeat(64),
    }
    mocks.exportBaselines.mockResolvedValue(privBundle)

    const wrapper = mount(BaselineManager, {
      global: {
        stubs: {
          BaseDialog: BaseDialogStub,
          ConfirmDialog: ConfirmDialogStub,
          Icon: IconStub,
        },
      },
    })
    await flushPromises()

    // Account capture defaults protocol to "" (Auto) and omits protocol from request unless overridden
    await wrapper.get('[data-test="open-capture-btn"]').trigger('click')
    await wrapper.get('[data-test="capture-mode-account"]').trigger('click')
    await wrapper.get('[data-test="capture-account-select"]').setValue('101')
    expect(
      (wrapper.get('[data-test="capture-account-protocol"]').element as HTMLSelectElement).value,
    ).toBe('')
    await wrapper.get('#cap-models').setValue('gpt-4o')
    await wrapper.get('[data-test="start-capture-btn"]').trigger('click')
    await flushPromises()

    const capArg = mocks.startCapture.mock.calls[0][0]
    expect(capArg).toEqual(expect.objectContaining({ target_source: 'account', account_id: 101 }))
    expect('protocol' in capArg).toBe(false)

    // Close capture modal and open export modal
    await wrapper.findAll('button').find((b) => b.text().includes('closeButton'))?.trigger('click')
    await wrapper.get('[data-test="open-export-btn"]').trigger('click')
    const includeCheckbox = wrapper.get<HTMLInputElement>('[data-test="export-include-private"]')
    await includeCheckbox.setValue(true)
    // Before exporting, private warning banner is NOT shown
    expect(wrapper.find('[data-test="export-private-warning"]').exists()).toBe(false)

    await wrapper.get('[data-test="run-export-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.exportBaselines).toHaveBeenCalledWith(true)
    expect(wrapper.find('[data-test="export-private-warning"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('b'.repeat(64))

    // Unchecking includePrivate clears exportedBundle and hides warning
    await includeCheckbox.setValue(false)
    await flushPromises()
    expect(wrapper.find('[data-test="export-private-warning"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('b'.repeat(64))
  })
})
