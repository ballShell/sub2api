import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import type { RunDetail, RunItem } from '../types'
import VerifyWorkbench from '../components/VerifyWorkbench.vue'

const mocks = vi.hoisted(() => ({
  listAccounts: vi.fn(),
  getAllProxies: vi.fn(),
  listSuites: vi.fn(),
  discoverModels: vi.fn(),
  createRun: vi.fn(),
  getRun: vi.fn(),
  cancelRun: vi.fn(),
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
  listSuites: mocks.listSuites,
  discoverModels: mocks.discoverModels,
  createRun: mocks.createRun,
  getRun: mocks.getRun,
  cancelRun: mocks.cancelRun,
  default: {
    listSuites: mocks.listSuites,
    discoverModels: mocks.discoverModels,
    createRun: mocks.createRun,
    getRun: mocks.getRun,
    cancelRun: mocks.cancelRun,
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

const BaseDialogStub = defineComponent({
  name: 'BaseDialog',
  props: ['show', 'title', 'width'],
  emits: ['close'],
  template: '<div v-if="show" data-test="base-dialog"><slot /><slot name="footer" /></div>',
})

const IconStub = defineComponent({
  name: 'Icon',
  props: ['name', 'size'],
  template: '<span data-test="icon" />',
})

const sampleItems: RunItem[] = [
  {
    id: 1,
    run_id: 42,
    claimed_model: 'gpt-4o',
    upstream_model: 'gpt-4o',
    canonical_model: 'gpt-4o',
    verdict: 'match',
    detector_used: 'logprobs',
    confidence: 0.97,
    distance: 0.015,
    prompt_injection_suspected: false,
    observed_prompt_tokens: 18,
    used_stale_baseline: false,
    top_candidates: [
      {
        canonical_model: 'gpt-4o',
        baseline_id: 10,
        distance: 0.015,
        similarity: 0.985,
        match_threshold: 0.08,
        suspect_threshold: 0.16,
        within_match: true,
      },
    ],
    evidence: [
      {
        probe_id: 'lp_1',
        detector_kind: 'logprobs',
        distance: 0.015,
        weight: 1,
        prompt_tokens: 18,
        output_tokens: 1,
        logprobs_supported: true,
        top_k_overlap: 1,
        observed_top_tokens: [{ token: 'Paris', prob: 0.94, logprob: -0.06 }],
        baseline_top_tokens: [{ token: 'Paris', prob: 0.93, logprob: -0.07 }],
        latency_ms: 85,
        http_status: 200,
      },
    ],
    latency_ms: 92,
    checked_at: '2026-11-25T09:00:00Z',
  },
  {
    id: 2,
    run_id: 42,
    claimed_model: 'claude-opus-4-6',
    upstream_model: 'claude-sonnet-4-6-mapped',
    canonical_model: 'claude-opus-4-6',
    verdict: 'mismatch',
    detector_used: 'behavior',
    confidence: 0.91,
    distance: 0.72,
    prompt_injection_suspected: true,
    observed_prompt_tokens: 812,
    used_stale_baseline: false,
    top_candidates: [
      {
        canonical_model: 'claude-sonnet-4-6',
        baseline_id: 11,
        distance: 0.04,
        similarity: 0.96,
        match_threshold: 0.15,
        suspect_threshold: 0.3,
        within_match: true,
        is_confusion_peer: true,
      },
    ],
    evidence: [
      {
        probe_id: 'bh_1',
        detector_kind: 'behavior',
        distance: 0.72,
        weight: 1,
        response_model: 'claude-sonnet-4-6-20250514',
        prompt_tokens: 812,
        output_tokens: 24,
        prompt_injection_suspected: true,
        observed_text: '{"answer":42}',
        baseline_sample_text: '{"answer":42,"style":"opus"}',
        latency_ms: 140,
        http_status: 200,
      },
    ],
    latency_ms: 150,
    checked_at: '2026-11-25T09:00:01Z',
  },
  {
    id: 3,
    run_id: 42,
    claimed_model: 'custom-preview-x',
    upstream_model: 'custom-preview-x',
    canonical_model: 'custom-preview-x',
    verdict: 'unverified',
    detector_used: 'behavior',
    confidence: 0,
    distance: 1,
    prompt_injection_suspected: false,
    observed_prompt_tokens: 22,
    top_candidates: [],
    evidence: [],
    latency_ms: 110,
    checked_at: '2026-11-25T09:00:02Z',
  },
]

function makeRun(status: RunDetail['status'], items: RunItem[] = []): RunDetail {
  return {
    id: 42,
    target_source: 'account',
    account_id: 101,
    target_label: 'account #101 (OpenAI Key)',
    protocol: 'openai_chat',
    suite_id: 1,
    status,
    total_models: 3,
    completed_models: status === 'completed' ? 3 : items.length,
    summary: {
      match: items.filter((i) => i.verdict === 'match').length,
      suspect: items.filter((i) => i.verdict === 'suspect').length,
      mismatch: items.filter((i) => i.verdict === 'mismatch').length,
      unverified: items.filter((i) => i.verdict === 'unverified').length,
      error: items.filter((i) => i.verdict === 'error').length,
      injection_suspected: items.filter((i) => i.prompt_injection_suspected).length,
    },
    created_at: '2026-11-25T09:00:00Z',
    items,
  }
}

function mountWorkbench() {
  return mount(VerifyWorkbench, {
    global: {
      stubs: {
        BaseDialog: BaseDialogStub,
        Icon: IconStub,
      },
    },
  })
}

describe('VerifyWorkbench', () => {
  let writeTextMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.useFakeTimers()
    Object.values(mocks).forEach((mock) => mock.mockReset())

    writeTextMock = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(window, 'isSecureContext', {
      value: true,
      configurable: true,
      writable: true,
    })
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: writeTextMock },
      configurable: true,
      writable: true,
    })

    mocks.listAccounts.mockResolvedValue({
      items: [
        { id: 101, name: 'OpenAI Key', type: 'apikey', platform: 'openai', status: 'active', parent_account_id: null },
        { id: 102, name: 'Claude Key', type: 'upstream', platform: 'anthropic', status: 'active', parent_account_id: null },
        { id: 201, name: 'Claude OAuth', type: 'oauth', platform: 'anthropic', status: 'active', parent_account_id: null },
        { id: 202, name: 'Setup Token', type: 'setup-token', platform: 'anthropic', status: 'active', parent_account_id: null },
        { id: 203, name: 'Shadow Key', type: 'apikey', platform: 'openai', status: 'active', parent_account_id: 101 },
        { id: 204, name: 'Antigravity Key', type: 'apikey', platform: 'antigravity', status: 'active', parent_account_id: null },
      ],
      total: 6,
      page: 1,
      page_size: 500,
      pages: 1,
    })

    mocks.getAllProxies.mockResolvedValue([
      { id: 7, name: 'Tokyo Proxy', protocol: 'socks5', host: '10.0.0.2', port: 1080, status: 'active' },
      { id: 8, name: 'Frankfurt Proxy', protocol: 'http', host: '10.0.0.3', port: 8080, status: 'active' },
    ])

    mocks.listSuites.mockResolvedValue([
      {
        id: 1,
        suite_key: 'default-core',
        version: 'v1',
        name: 'Default Core Suite',
        visibility: 'public',
        status: 'active',
        is_default: true,
        probes: [],
        content_hash: 'abc',
        created_at: '2026-11-25T00:00:00Z',
        updated_at: '2026-11-25T00:00:00Z',
      },
    ])

    mocks.discoverModels.mockResolvedValue({
      target_source: 'account',
      account_id: 101,
      target_label: 'account #101 (OpenAI Key)',
      protocol: 'openai_chat',
      models: ['gpt-4o', 'claude-opus-4-6', 'custom-preview-x'],
      default_models: ['gpt-4o'],
    })

    mocks.createRun.mockResolvedValue(makeRun('running', []))
    mocks.getRun.mockResolvedValue(makeRun('completed', sampleItems))
    mocks.cancelRun.mockResolvedValue({ cancelled: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('switches between adhoc and account modes and filters out non-eligible OAuth/shadow accounts', async () => {
    const wrapper = mountWorkbench()
    await flushPromises()

    expect(mocks.getAllProxies).toHaveBeenCalledOnce()
    expect(mocks.listAccounts).toHaveBeenCalled()

    // Default ad-hoc mode shows proxy dropdown populated from adminProxies.getAll()
    const proxySelect = wrapper.get('[data-test="adhoc-proxy"]')
    expect(proxySelect.text()).toContain('Tokyo Proxy')
    expect(proxySelect.text()).toContain('Frankfurt Proxy')
    expect(wrapper.find('[data-test="account-select"]').exists()).toBe(false)

    // Switch to existing account mode
    await wrapper.get('[data-test="target-mode-account"]').trigger('click')
    expect(wrapper.find('[data-test="adhoc-proxy"]').exists()).toBe(false)

    const accountSelect = wrapper.get('[data-test="account-select"]')
    const optionTexts = accountSelect.findAll('option').map((o) => o.text())
    expect(optionTexts.some((t) => t.includes('OpenAI Key'))).toBe(true)
    expect(optionTexts.some((t) => t.includes('Claude Key'))).toBe(true)
    expect(optionTexts.some((t) => t.includes('Claude OAuth'))).toBe(false)
    expect(optionTexts.some((t) => t.includes('Setup Token'))).toBe(false)
    expect(optionTexts.some((t) => t.includes('Shadow Key'))).toBe(false)
    expect(optionTexts.some((t) => t.includes('Antigravity Key'))).toBe(false)
  })

  it('starts a verification run, polls every 2s until terminal status, and stops polling after completion', async () => {
    mocks.getRun
      .mockResolvedValueOnce(makeRun('running', [sampleItems[0]]))
      .mockResolvedValueOnce(makeRun('completed', sampleItems))

    const wrapper = mountWorkbench()
    await flushPromises()

    await wrapper.get('[data-test="target-mode-account"]').trigger('click')
    await wrapper.get('[data-test="account-select"]').setValue('101')
    await wrapper.get('[data-test="discover-models-btn"]').trigger('click')
    await flushPromises()

    expect(mocks.discoverModels).toHaveBeenCalledWith(
      expect.objectContaining({ target_source: 'account', account_id: 101 }),
    )
    expect((wrapper.get('[data-test="models-input"]').element as HTMLTextAreaElement).value).toContain('gpt-4o')

    await wrapper.get('[data-test="start-verify-btn"]').trigger('click')
    await flushPromises()

    expect(mocks.createRun).toHaveBeenCalledWith(
      expect.objectContaining({
        target_source: 'account',
        account_id: 101,
        models: ['gpt-4o', 'claude-opus-4-6', 'custom-preview-x'],
      }),
    )
    expect(mocks.getRun).not.toHaveBeenCalled()

    // First 2s poll returns running
    await vi.advanceTimersByTimeAsync(2000)
    await flushPromises()
    expect(mocks.getRun).toHaveBeenCalledTimes(1)
    expect(mocks.getRun).toHaveBeenCalledWith(42)

    // Second 2s poll returns completed -> polling stops
    await vi.advanceTimersByTimeAsync(2000)
    await flushPromises()
    expect(mocks.getRun).toHaveBeenCalledTimes(2)

    // Further timer ticks must not trigger extra polls
    await vi.advanceTimersByTimeAsync(10000)
    await flushPromises()
    expect(mocks.getRun).toHaveBeenCalledTimes(2)

    // Verdict badges & prompt injection warning badge rendered
    expect(wrapper.text()).toContain('admin.modelFingerprint.verdicts.match')
    expect(wrapper.text()).toContain('admin.modelFingerprint.verdicts.mismatch')
    expect(wrapper.get('[data-test="injection-badge"]').text()).toContain(
      'admin.modelFingerprint.verify.results.injectionBadge',
    )
  })

  it('cleans up active polling timer on unmount and supports cancelling an active run', async () => {
    mocks.getRun.mockResolvedValue(makeRun('running', [sampleItems[0]]))

    const wrapper = mountWorkbench()
    await flushPromises()

    await wrapper.get('[data-test="adhoc-base-url"]').setValue('https://api.example.com/v1')
    await wrapper.get('[data-test="adhoc-api-key"]').setValue('sk-test-secret')
    await wrapper.get('[data-test="adhoc-proxy"]').setValue('7')
    await wrapper.get('[data-test="models-input"]').setValue('gpt-4o')
    await wrapper.get('[data-test="start-verify-btn"]').trigger('click')
    await flushPromises()

    expect(mocks.createRun).toHaveBeenCalledWith(
      expect.objectContaining({
        target_source: 'adhoc',
        adhoc: expect.objectContaining({
          protocol: 'openai_chat',
          base_url: 'https://api.example.com/v1',
          api_key: 'sk-test-secret',
          proxy_id: 7,
        }),
      }),
    )

    await wrapper.get('[data-test="cancel-run-btn"]').trigger('click')
    await flushPromises()
    expect(mocks.cancelRun).toHaveBeenCalledWith(42)

    const callsBeforeUnmount = mocks.getRun.mock.calls.length
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(10000)
    await flushPromises()
    expect(mocks.getRun).toHaveBeenCalledTimes(callsBeforeUnmount)
  })

  it('opens EvidenceDrawer with claimed_model, upstream_model, injection banner, and probe telemetry', async () => {
    mocks.createRun.mockResolvedValue(makeRun('completed', sampleItems))

    const wrapper = mountWorkbench()
    await flushPromises()

    await wrapper.get('[data-test="target-mode-account"]').trigger('click')
    await wrapper.get('[data-test="account-select"]').setValue('101')
    await wrapper.get('[data-test="models-input"]').setValue('gpt-4o\nclaude-opus-4-6\ncustom-preview-x')
    await wrapper.get('[data-test="start-verify-btn"]').trigger('click')
    await flushPromises()

    // Click evidence button on the second row (claude-opus-4-6 mapped to claude-sonnet-4-6-mapped)
    const viewButtons = wrapper.findAll('[data-test="view-evidence-btn"]')
    expect(viewButtons).toHaveLength(3)
    await viewButtons[1].trigger('click')
    await flushPromises()

    const dialog = wrapper.get('[data-test="base-dialog"]')
    expect(dialog.text()).toContain('claude-opus-4-6')
    expect(dialog.text()).toContain('claude-sonnet-4-6-mapped')
    expect(dialog.get('[data-test="evidence-injection-alert"]').text()).toContain('812')
    expect(dialog.get('[data-test="evidence-top-candidates"]').text()).toContain('claude-sonnet-4-6')
    expect(dialog.get('[data-test="evidence-probes"]').text()).toContain('bh_1')
  })

  it('copies verified whitelist in selected format via clipboard without modifying ModelWhitelistSelector', async () => {
    mocks.createRun.mockResolvedValue(makeRun('completed', sampleItems))

    const wrapper = mountWorkbench()
    await flushPromises()

    await wrapper.get('[data-test="target-mode-account"]').trigger('click')
    await wrapper.get('[data-test="account-select"]').setValue('101')
    await wrapper.get('[data-test="models-input"]').setValue('gpt-4o\nclaude-opus-4-6\ncustom-preview-x')
    await wrapper.get('[data-test="start-verify-btn"]').trigger('click')
    await flushPromises()

    // Default format: lines, only verdict === 'match' (gpt-4o)
    await wrapper.get('[data-test="copy-whitelist-btn"]').trigger('click')
    await flushPromises()
    expect(writeTextMock).toHaveBeenLastCalledWith('gpt-4o')

    // Toggle includeUnverified and switch to JSON format
    await wrapper.get('[data-test="include-unverified-checkbox"]').setValue(true)
    await wrapper.get('[data-test="whitelist-format-json"]').trigger('click')
    await wrapper.get('[data-test="copy-whitelist-btn"]').trigger('click')
    await flushPromises()

    const copiedPayload = writeTextMock.mock.calls.at(-1)?.[0]
    expect(JSON.parse(copiedPayload)).toEqual({
      'gpt-4o': 'gpt-4o',
      'custom-preview-x': 'custom-preview-x',
    })
  })
})
