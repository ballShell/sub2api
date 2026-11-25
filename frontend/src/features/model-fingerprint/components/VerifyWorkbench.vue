<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
        {{ t('admin.modelFingerprint.verify.title') }}
      </h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
        {{ t('admin.modelFingerprint.verify.description') }}
      </p>
    </div>

    <!-- Configuration Grid -->
    <div class="grid gap-6 lg:grid-cols-2">
      <!-- Target Upstream Panel -->
      <section class="space-y-4 rounded-xl border border-gray-200 bg-gray-50/50 p-4 dark:border-dark-700 dark:bg-dark-900/40">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white">
            {{ t('admin.modelFingerprint.verify.targetSectionTitle') }}
          </h3>

          <div
            class="tabs inline-flex"
            role="radiogroup"
            :aria-label="t('admin.modelFingerprint.verify.targetSourceLabel')"
          >
            <button
              type="button"
              role="radio"
              :aria-checked="targetSource === 'adhoc'"
              data-test="target-mode-adhoc"
              class="tab"
              :class="{ 'tab-active': targetSource === 'adhoc' }"
              @click="targetSource = 'adhoc'"
            >
              {{ t('admin.modelFingerprint.verify.adhocMode') }}
            </button>
            <button
              type="button"
              role="radio"
              :aria-checked="targetSource === 'account'"
              data-test="target-mode-account"
              class="tab"
              :class="{ 'tab-active': targetSource === 'account' }"
              @click="targetSource = 'account'"
            >
              {{ t('admin.modelFingerprint.verify.accountMode') }}
            </button>
          </div>
        </div>

        <!-- Ad-hoc credentials -->
        <template v-if="targetSource === 'adhoc'">
          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="input-label" for="modelfp-adhoc-protocol">
                {{ t('admin.modelFingerprint.verify.protocolLabel') }}
              </label>
              <select
                id="modelfp-adhoc-protocol"
                v-model="adhocProtocol"
                data-test="adhoc-protocol"
                :aria-label="t('admin.modelFingerprint.verify.protocolLabel')"
                class="input"
              >
                <option v-for="proto in SUPPORTED_PROTOCOLS" :key="proto" :value="proto">
                  {{ t(`admin.modelFingerprint.protocols.${proto}`) }}
                </option>
              </select>
            </div>

            <div>
              <label class="input-label" for="modelfp-adhoc-auth-mode">
                {{ t('admin.modelFingerprint.verify.authModeLabel') }}
              </label>
              <select
                id="modelfp-adhoc-auth-mode"
                v-model="authMode"
                data-test="adhoc-auth-mode"
                :aria-label="t('admin.modelFingerprint.verify.authModeLabel')"
                class="input"
              >
                <option value="">{{ t('admin.modelFingerprint.authModes.default') }}</option>
                <option value="bearer">{{ t('admin.modelFingerprint.authModes.bearer') }}</option>
                <option value="x-api-key">{{ t('admin.modelFingerprint.authModes.x-api-key') }}</option>
              </select>
            </div>
          </div>

          <div>
            <label class="input-label" for="modelfp-adhoc-base-url">
              {{ t('admin.modelFingerprint.verify.baseUrlLabel') }}
            </label>
            <input
              id="modelfp-adhoc-base-url"
              v-model="baseUrl"
              data-test="adhoc-base-url"
              type="url"
              class="input"
              :placeholder="t('admin.modelFingerprint.verify.baseUrlPlaceholder')"
            />
          </div>

          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="input-label" for="modelfp-adhoc-api-key">
                {{ t('admin.modelFingerprint.verify.apiKeyLabel') }}
              </label>
              <input
                id="modelfp-adhoc-api-key"
                v-model="apiKey"
                data-test="adhoc-api-key"
                type="password"
                autocomplete="off"
                class="input"
                :placeholder="t('admin.modelFingerprint.verify.apiKeyPlaceholder')"
              />
              <p class="input-hint">{{ t('admin.modelFingerprint.verify.apiKeyHint') }}</p>
            </div>

            <div>
              <label class="input-label" for="modelfp-adhoc-proxy">
                {{ t('admin.modelFingerprint.verify.proxyLabel') }}
              </label>
              <select
                id="modelfp-adhoc-proxy"
                v-model="proxyId"
                data-test="adhoc-proxy"
                :aria-label="t('admin.modelFingerprint.verify.proxyLabel')"
                class="input"
              >
                <option :value="null">{{ t('admin.modelFingerprint.verify.proxyNone') }}</option>
                <option v-for="proxy in proxies" :key="proxy.id" :value="proxy.id">
                  {{ proxy.name }} ({{ proxy.protocol }}://{{ proxy.host }}:{{ proxy.port }})
                </option>
              </select>
            </div>
          </div>

          <div>
            <label class="input-label" for="modelfp-adhoc-headers">
              {{ t('admin.modelFingerprint.verify.extraHeadersLabel') }}
            </label>
            <textarea
              id="modelfp-adhoc-headers"
              v-model="extraHeadersRaw"
              data-test="adhoc-extra-headers"
              rows="2"
              class="input font-mono text-xs"
              :class="{ 'input-error': !parsedExtraHeaders.valid }"
              :placeholder="t('admin.modelFingerprint.verify.extraHeadersPlaceholder')"
            />
            <p v-if="!parsedExtraHeaders.valid" class="input-error-text">
              {{ t('admin.modelFingerprint.verify.extraHeadersInvalid') }}
            </p>
            <p v-else class="input-hint">
              {{ t('admin.modelFingerprint.verify.extraHeadersHint') }}
            </p>
          </div>
        </template>

        <!-- Existing REST API-Key Account -->
        <template v-else>
          <div>
            <label class="input-label" for="modelfp-account-select">
              {{ t('admin.modelFingerprint.verify.accountLabel') }}
            </label>
            <select
              id="modelfp-account-select"
              v-model="selectedAccountId"
              data-test="account-select"
              :aria-label="t('admin.modelFingerprint.verify.accountLabel')"
              class="input"
            >
              <option :value="null" disabled>
                {{ t('admin.modelFingerprint.verify.accountPlaceholder') }}
              </option>
              <option v-for="account in eligibleAccounts" :key="account.id" :value="account.id">
                #{{ account.id }} · {{ account.name }} ({{ account.platform }} / {{ account.type }})
              </option>
            </select>
            <p
              v-if="eligibleAccounts.length === 0 && !loadingMeta"
              data-test="account-empty"
              class="mt-1.5 text-xs text-amber-600 dark:text-amber-400"
            >
              {{ t('admin.modelFingerprint.verify.accountEmpty') }}
            </p>
            <p class="input-hint">{{ t('admin.modelFingerprint.verify.accountHint') }}</p>
          </div>

          <div>
            <label class="input-label" for="modelfp-account-protocol">
              {{ t('admin.modelFingerprint.verify.protocolLabel') }}
            </label>
            <select
              id="modelfp-account-protocol"
              v-model="accountProtocol"
              data-test="account-protocol"
              :aria-label="t('admin.modelFingerprint.verify.protocolLabel')"
              class="input"
            >
              <option value="">{{ t('admin.modelFingerprint.verify.protocolAuto') }}</option>
              <option v-for="proto in SUPPORTED_PROTOCOLS" :key="proto" :value="proto">
                {{ t(`admin.modelFingerprint.protocols.${proto}`) }}
              </option>
            </select>
            <p class="input-hint">{{ t('admin.modelFingerprint.verify.protocolOverrideHint') }}</p>
          </div>
        </template>

        <!-- Shared Suite & Concurrency -->
        <div class="grid gap-3 border-t border-gray-200 pt-3 dark:border-dark-700 sm:grid-cols-2">
          <div>
            <label class="input-label" for="modelfp-verify-suite">
              {{ t('admin.modelFingerprint.verify.suiteLabel') }}
            </label>
            <select
              id="modelfp-verify-suite"
              v-model="selectedSuiteId"
              data-test="suite-select"
              class="input"
            >
              <option :value="0">{{ t('admin.modelFingerprint.verify.suiteDefaultOption') }}</option>
              <option v-for="suite in activeSuites" :key="suite.id" :value="suite.id">
                {{ suite.name }} ({{ suite.suite_key }} {{ suite.version }})
              </option>
            </select>
          </div>

          <div>
            <label class="input-label" for="modelfp-verify-concurrency">
              {{ t('admin.modelFingerprint.verify.concurrencyLabel') }}
            </label>
            <input
              id="modelfp-verify-concurrency"
              v-model.number="concurrency"
              data-test="concurrency-input"
              type="number"
              min="1"
              max="5"
              class="input"
            />
          </div>
        </div>
      </section>

      <!-- Models Input & Launch Panel -->
      <section class="flex flex-col justify-between space-y-4 rounded-xl border border-gray-200 bg-gray-50/50 p-4 dark:border-dark-700 dark:bg-dark-900/40">
        <div class="space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h3 class="text-sm font-semibold text-gray-900 dark:text-white">
              {{ t('admin.modelFingerprint.verify.modelsSectionTitle') }}
            </h3>
            <div class="flex flex-wrap items-center gap-2">
              <button
                v-if="defaultModels.length > 0"
                type="button"
                data-test="use-default-models-btn"
                class="btn btn-secondary btn-sm"
                @click="applyDefaultModels"
              >
                {{ t('admin.modelFingerprint.verify.useDefaultModels') }}
              </button>
              <button
                type="button"
                data-test="discover-models-btn"
                class="btn btn-secondary btn-sm"
                :disabled="!canDiscover || discovering"
                @click="handleDiscoverModels"
              >
                <span v-if="discovering" class="spinner h-3.5 w-3.5" />
                {{
                  discovering
                    ? t('admin.modelFingerprint.verify.discovering')
                    : t('admin.modelFingerprint.verify.discoverButton')
                }}
              </button>
            </div>
          </div>

          <div>
            <label class="input-label" for="modelfp-models-textarea">
              {{ t('admin.modelFingerprint.verify.modelsLabel') }}
            </label>
            <textarea
              id="modelfp-models-textarea"
              v-model="modelsRaw"
              data-test="models-input"
              :aria-label="t('admin.modelFingerprint.verify.modelsLabel')"
              rows="8"
              class="input font-mono text-xs"
              :class="{ 'input-error': parsedModels.length > 50 }"
              :placeholder="t('admin.modelFingerprint.verify.modelsPlaceholder')"
            />
            <p class="input-hint">
              {{
                t('admin.modelFingerprint.verify.modelsCountHint', {
                  count: parsedModels.length,
                })
              }}
            </p>
            <p
              v-if="parsedModels.length > 50"
              data-test="models-limit-warning"
              class="input-error-text"
            >
              {{ t('admin.modelFingerprint.verify.modelsLimitWarning') }}
            </p>
          </div>
        </div>

        <div class="flex flex-wrap items-center justify-end gap-3 border-t border-gray-200 pt-3 dark:border-dark-700">
          <button
            v-if="isRunActive"
            type="button"
            data-test="cancel-run-btn"
            class="btn btn-danger"
            :disabled="cancelling"
            @click="handleCancelRun"
          >
            {{
              cancelling
                ? t('admin.modelFingerprint.verify.cancellingRun')
                : t('admin.modelFingerprint.verify.cancelRunButton')
            }}
          </button>

          <button
            type="button"
            data-test="start-verify-btn"
            class="btn btn-primary"
            :disabled="!canStartVerify || starting"
            @click="handleStartVerify"
          >
            <span v-if="starting" class="spinner h-4 w-4" />
            {{
              starting
                ? t('admin.modelFingerprint.verify.startingVerify')
                : t('admin.modelFingerprint.verify.startVerifyButton')
            }}
          </button>
        </div>
      </section>
    </div>

    <!-- Active / Latest Run Progress & Summary -->
    <template v-if="activeRun">
      <section
        data-test="run-progress"
        class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-800/50"
      >
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div class="flex flex-wrap items-center gap-2.5">
            <h3 class="text-sm font-semibold text-gray-900 dark:text-white">
              {{ t('admin.modelFingerprint.verify.progressTitle') }}
            </h3>
            <span class="badge" :class="runStatusBadgeMeta(activeRun.status).badgeClass">
              {{ t(runStatusBadgeMeta(activeRun.status).labelKey) }}
            </span>
            <span class="text-xs font-medium text-gray-600 dark:text-dark-300">
              {{ activeRun.target_label }}
            </span>
            <span class="badge badge-gray">
              {{ t(`admin.modelFingerprint.protocols.${activeRun.protocol}`) }}
            </span>
          </div>

          <div class="flex items-center gap-3 text-xs text-gray-500 dark:text-dark-400">
            <span v-if="isRunActive">{{ t('admin.modelFingerprint.verify.pollingHint') }}</span>
            <span class="font-mono font-semibold text-gray-800 dark:text-dark-200">
              {{
                t('admin.modelFingerprint.verify.progressCounts', {
                  completed: activeRun.completed_models,
                  total: activeRun.total_models,
                })
              }}
            </span>
          </div>
        </div>

        <div class="progress mt-3">
          <div class="progress-bar" :style="{ width: `${progressPercent}%` }" />
        </div>

        <div
          v-if="activeRun.error_message"
          class="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/40 dark:text-red-300"
        >
          <span class="font-semibold">{{ t('admin.modelFingerprint.verify.runErrorLabel') }}: </span>
          {{ activeRun.error_message }}
        </div>
      </section>

      <!-- Summary Cards -->
      <section data-test="summary-cards" class="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <div
          v-for="card in summaryCards"
          :key="card.key"
          class="rounded-xl border border-gray-200 bg-white p-3.5 dark:border-dark-700 dark:bg-dark-800/50"
        >
          <p class="text-xs text-gray-500 dark:text-dark-400">{{ card.label }}</p>
          <p class="mt-1 font-mono text-xl font-bold" :class="card.valueClass">
            {{ card.value }}
          </p>
        </div>
      </section>

      <!-- 3-Format Whitelist Copy Bar -->
      <section
        v-if="activeRun.items.length > 0"
        data-test="whitelist-bar"
        class="space-y-3 rounded-xl border border-gray-200 bg-gray-50/70 p-4 dark:border-dark-700 dark:bg-dark-900/40"
      >
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 class="text-sm font-semibold text-gray-900 dark:text-white">
              {{ t('admin.modelFingerprint.verify.whitelist.title') }}
            </h3>
            <p class="mt-0.5 text-xs text-gray-500 dark:text-dark-400">
              {{ t('admin.modelFingerprint.verify.whitelist.description') }}
            </p>
          </div>

          <div class="flex flex-wrap items-center gap-3">
            <div class="tabs inline-flex">
              <button
                v-for="fmt in WHITELIST_FORMATS"
                :key="fmt"
                type="button"
                :data-test="`whitelist-format-${fmt}`"
                class="tab py-1.5 text-xs"
                :class="{ 'tab-active': whitelistFormat === fmt }"
                @click="whitelistFormat = fmt"
              >
                {{ t(`admin.modelFingerprint.verify.whitelist.formats.${fmt}`) }}
              </button>
            </div>

            <button
              type="button"
              data-test="copy-whitelist-btn"
              class="btn btn-primary btn-sm"
              @click="handleCopyWhitelist"
            >
              <Icon name="copy" size="xs" />
              {{ t('admin.modelFingerprint.verify.whitelist.copyButton') }}
            </button>
          </div>
        </div>

        <label class="inline-flex cursor-pointer items-center gap-2 text-xs text-gray-700 dark:text-dark-200">
          <input
            v-model="includeUnverified"
            data-test="include-unverified-checkbox"
            type="checkbox"
            class="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-600"
          />
          <span>{{ t('admin.modelFingerprint.verify.whitelist.includeUnverified') }}</span>
        </label>

        <div v-if="whitelistPreview">
          <p class="mb-1 text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.verify.whitelist.previewLabel') }}
          </p>
          <pre
            data-test="whitelist-preview"
            class="max-h-36 overflow-auto rounded-lg border border-gray-200 bg-white p-3 font-mono text-xs text-gray-800 dark:border-dark-700 dark:bg-dark-800 dark:text-dark-200"
          >{{ whitelistPreview }}</pre>
        </div>
      </section>
    </template>

    <!-- Results Table -->
    <section class="space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white">
          {{ t('admin.modelFingerprint.verify.results.title') }}
        </h3>

        <select
          v-if="activeRun && activeRun.items.length > 0"
          v-model="verdictFilter"
          data-test="verdict-filter"
          class="input w-auto py-1.5 text-xs"
        >
          <option value="all">{{ t('admin.modelFingerprint.verify.results.filterAll') }}</option>
          <option v-for="v in VERDICTS" :key="v" :value="v">
            {{ t(`admin.modelFingerprint.verdicts.${v}`) }}
          </option>
        </select>
      </div>

      <div
        v-if="!activeRun || filteredItems.length === 0"
        class="rounded-xl border border-dashed border-gray-200 p-8 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
      >
        {{ t('admin.modelFingerprint.verify.results.empty') }}
      </div>

      <div v-else class="table-container" data-test="results-table">
        <table class="table">
          <thead>
            <tr>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.claimedModel') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.upstreamModel') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.canonicalModel') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.verdict') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.detector') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.distance') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.confidence') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.promptTokens') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.latency') }}</th>
              <th>{{ t('admin.modelFingerprint.verify.results.columns.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="item in filteredItems"
              :key="`${item.id}-${item.claimed_model}`"
              class="cursor-pointer"
              @click="selectedEvidenceItem = item"
            >
              <td class="font-mono text-xs font-semibold text-gray-900 dark:text-white">
                {{ item.claimed_model }}
              </td>
              <td class="font-mono text-xs text-gray-700 dark:text-dark-300">
                {{ item.upstream_model || item.claimed_model }}
              </td>
              <td class="font-mono text-xs text-gray-700 dark:text-dark-300">
                {{ item.canonical_model || '—' }}
              </td>
              <td>
                <div class="flex flex-wrap items-center gap-1.5">
                  <span class="badge" :class="verdictBadgeMeta(item.verdict).badgeClass">
                    {{ t(verdictBadgeMeta(item.verdict).labelKey) }}
                  </span>
                  <span
                    v-if="item.prompt_injection_suspected"
                    data-test="injection-badge"
                    class="badge border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300"
                  >
                    {{ t('admin.modelFingerprint.verify.results.injectionBadge') }}
                  </span>
                  <span
                    v-if="item.used_stale_baseline"
                    class="badge border border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800/60 dark:bg-amber-950/40 dark:text-amber-300"
                  >
                    {{ t('admin.modelFingerprint.verify.results.staleBaselineBadge') }}
                  </span>
                  <span
                    v-if="suspectedCandidateModel(item)"
                    class="text-xs text-amber-700 dark:text-amber-300"
                  >
                    {{
                      t('admin.modelFingerprint.verify.results.suspectedActualModel', {
                        model: suspectedCandidateModel(item),
                      })
                    }}
                  </span>
                </div>
              </td>
              <td class="text-xs">
                {{
                  item.detector_used
                    ? t(`admin.modelFingerprint.detectors.${item.detector_used}`)
                    : '—'
                }}
              </td>
              <td class="font-mono text-xs">{{ item.distance.toFixed(4) }}</td>
              <td class="font-mono text-xs">{{ (item.confidence * 100).toFixed(1) }}%</td>
              <td class="font-mono text-xs">{{ item.observed_prompt_tokens }}</td>
              <td class="font-mono text-xs">{{ item.latency_ms }} ms</td>
              <td>
                <button
                  type="button"
                  data-test="view-evidence-btn"
                  class="btn btn-secondary btn-sm"
                  @click.stop="selectedEvidenceItem = item"
                >
                  {{ t('admin.modelFingerprint.verify.results.viewEvidence') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <EvidenceDrawer
      :show="Boolean(selectedEvidenceItem)"
      :item="selectedEvidenceItem"
      @close="selectedEvidenceItem = null"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import * as adminAccounts from '@/api/admin/accounts'
import * as adminProxies from '@/api/admin/proxies'
import Icon from '@/components/icons/Icon.vue'
import { useClipboard } from '@/composables/useClipboard'
import { useAppStore } from '@/stores/app'
import type { AccountListItem, Proxy } from '@/types'
import modelFingerprintAPI from '../api'
import type {
  ProbeSuite,
  Protocol,
  RunDetail,
  RunItem,
  TargetSource,
  Verdict,
  WhitelistFormat,
} from '../types'
import {
  buildTargetPayload,
  extractVerifiedModels,
  formatModelFpError,
  formatVerifiedWhitelist,
  isEligibleFingerprintAccount,
  isTerminalRunStatus,
  parseExtraHeadersJson,
  parseModelInput,
  runStatusBadgeMeta,
  SUPPORTED_PROTOCOLS,
  verdictBadgeMeta,
} from '../viewModel'
import EvidenceDrawer from './EvidenceDrawer.vue'

const props = withDefaults(
  defineProps<{
    suitesRefreshKey?: number
  }>(),
  { suitesRefreshKey: 0 },
)

const emit = defineEmits<{
  (e: 'run-completed', run: RunDetail): void
}>()

const { t } = useI18n()
const appStore = useAppStore()
const { copyToClipboard } = useClipboard()

const WHITELIST_FORMATS: readonly WhitelistFormat[] = ['lines', 'comma', 'json']
const VERDICTS: readonly Verdict[] = ['match', 'suspect', 'mismatch', 'unverified', 'error']

const accounts = ref<AccountListItem[]>([])
const proxies = ref<Proxy[]>([])
const suites = ref<ProbeSuite[]>([])
const loadingMeta = ref(false)

const targetSource = ref<TargetSource>('adhoc')
const selectedAccountId = ref<number | null>(null)
const accountProtocol = ref<Protocol | ''>('')

const adhocProtocol = ref<Protocol>('openai_chat')
const baseUrl = ref('')
const apiKey = ref('')
const authMode = ref('')
const proxyId = ref<number | null>(null)
const extraHeadersRaw = ref('')

const selectedSuiteId = ref(0)
const concurrency = ref(3)
const modelsRaw = ref('')
const defaultModels = ref<string[]>([])

const discovering = ref(false)
const starting = ref(false)
const cancelling = ref(false)

const activeRun = ref<RunDetail | null>(null)
const selectedEvidenceItem = ref<RunItem | null>(null)
const verdictFilter = ref<'all' | Verdict>('all')
const whitelistFormat = ref<WhitelistFormat>('lines')
const includeUnverified = ref(false)

let pollTimer: number | null = null
let isUnmounted = false
let discoverSeq = 0
let cancelSeq = 0

const eligibleAccounts = computed(() => accounts.value.filter(isEligibleFingerprintAccount))
const activeSuites = computed(() => suites.value.filter((s) => s.status === 'active'))

const parsedExtraHeaders = computed(() => parseExtraHeadersJson(extraHeadersRaw.value))
const parsedModels = computed(() => parseModelInput(modelsRaw.value))

const isTargetValid = computed(() => {
  if (targetSource.value === 'account') {
    return selectedAccountId.value !== null && selectedAccountId.value > 0
  }
  return Boolean(baseUrl.value.trim() && apiKey.value.trim() && parsedExtraHeaders.value.valid)
})

const canDiscover = computed(() => isTargetValid.value && !discovering.value)
const canStartVerify = computed(
  () => isTargetValid.value && parsedModels.value.length > 0 && parsedModels.value.length <= 50,
)

const isRunActive = computed(
  () => activeRun.value !== null && !isTerminalRunStatus(activeRun.value.status),
)

const progressPercent = computed(() => {
  if (!activeRun.value || activeRun.value.total_models <= 0) return 0
  return Math.min(
    100,
    Math.round((activeRun.value.completed_models / activeRun.value.total_models) * 100),
  )
})

const summaryCards = computed(() => {
  const run = activeRun.value
  if (!run) return []
  return [
    {
      key: 'total',
      label: t('admin.modelFingerprint.verify.summaryCards.total'),
      value: run.total_models,
      valueClass: 'text-gray-900 dark:text-white',
    },
    {
      key: 'match',
      label: t('admin.modelFingerprint.verify.summaryCards.match'),
      value: run.summary.match,
      valueClass: 'text-emerald-600 dark:text-emerald-400',
    },
    {
      key: 'suspect',
      label: t('admin.modelFingerprint.verify.summaryCards.suspect'),
      value: run.summary.suspect,
      valueClass: 'text-amber-600 dark:text-amber-400',
    },
    {
      key: 'mismatch',
      label: t('admin.modelFingerprint.verify.summaryCards.mismatch'),
      value: run.summary.mismatch,
      valueClass: 'text-red-600 dark:text-red-400',
    },
    {
      key: 'unverified',
      label: t('admin.modelFingerprint.verify.summaryCards.unverified'),
      value: run.summary.unverified,
      valueClass: 'text-slate-600 dark:text-dark-300',
    },
    {
      key: 'error',
      label: t('admin.modelFingerprint.verify.summaryCards.error'),
      value: run.summary.error,
      valueClass: 'text-rose-600 dark:text-rose-400',
    },
    {
      key: 'injection',
      label: t('admin.modelFingerprint.verify.summaryCards.injectionSuspected'),
      value: run.summary.injection_suspected,
      valueClass:
        run.summary.injection_suspected > 0
          ? 'text-red-600 dark:text-red-400'
          : 'text-gray-600 dark:text-dark-300',
    },
  ]
})

const filteredItems = computed(() => {
  const items = activeRun.value?.items ?? []
  if (verdictFilter.value === 'all') return items
  return items.filter((item) => item.verdict === verdictFilter.value)
})

const whitelistPreview = computed(() => {
  if (!activeRun.value) return ''
  return formatVerifiedWhitelist(
    activeRun.value.items,
    whitelistFormat.value,
    includeUnverified.value,
  )
})

watch([targetSource, selectedAccountId], () => {
  discoverSeq++
  discovering.value = false
  defaultModels.value = []
})

watch(selectedAccountId, () => {
  accountProtocol.value = ''
})

watch(
  () => props.suitesRefreshKey,
  () => {
    void loadSuites()
  },
)

function buildCurrentTarget() {
  return buildTargetPayload({
    targetSource: targetSource.value,
    accountId: selectedAccountId.value,
    accountProtocol: accountProtocol.value,
    adhocProtocol: adhocProtocol.value,
    baseUrl: baseUrl.value,
    apiKey: apiKey.value,
    authMode: authMode.value,
    proxyId: proxyId.value,
    extraHeaders: parsedExtraHeaders.value.headers,
  })
}

function stopPolling() {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer)
    pollTimer = null
  }
}

function scheduleNextPoll(runId: number) {
  stopPolling()
  if (isUnmounted) return
  pollTimer = window.setTimeout(() => {
    void pollRunStatus(runId)
  }, 2000)
}

async function pollRunStatus(runId: number) {
  if (isUnmounted || activeRun.value?.id !== runId) return
  try {
    const detail = await modelFingerprintAPI.getRun(runId)
    if (isUnmounted || activeRun.value?.id !== runId) return
    activeRun.value = detail
    if (isTerminalRunStatus(detail.status)) {
      stopPolling()
      emit('run-completed', detail)
    } else {
      scheduleNextPoll(runId)
    }
  } catch (error) {
    if (isUnmounted || activeRun.value?.id !== runId) return
    stopPolling()
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadRunFailed'))
  }
}

async function loadSuites() {
  try {
    suites.value = await modelFingerprintAPI.listSuites()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadSuitesFailed'))
  }
}

async function loadMetadata() {
  loadingMeta.value = true
  try {
    const [accountsRes, proxiesRes, suitesRes] = await Promise.allSettled([
      adminAccounts.list(1, 500),
      adminProxies.getAll(),
      modelFingerprintAPI.listSuites(),
    ])
    if (accountsRes.status === 'fulfilled') {
      accounts.value = accountsRes.value?.items ?? []
    } else {
      appStore.showError(
        formatModelFpError(accountsRes.reason, t, 'admin.modelFingerprint.errors.loadAccountsFailed'),
      )
    }
    if (proxiesRes.status === 'fulfilled') {
      proxies.value = proxiesRes.value ?? []
    } else {
      appStore.showError(
        formatModelFpError(proxiesRes.reason, t, 'admin.modelFingerprint.errors.loadProxiesFailed'),
      )
    }
    if (suitesRes.status === 'fulfilled') {
      suites.value = suitesRes.value ?? []
    } else {
      appStore.showError(
        formatModelFpError(suitesRes.reason, t, 'admin.modelFingerprint.errors.loadSuitesFailed'),
      )
    }
  } finally {
    loadingMeta.value = false
  }
}

async function handleDiscoverModels() {
  if (!canDiscover.value) return
  const seq = ++discoverSeq
  discovering.value = true
  try {
    const res = await modelFingerprintAPI.discoverModels(buildCurrentTarget())
    if (isUnmounted || seq !== discoverSeq) return
    defaultModels.value = res.default_models ?? []
    if (res.models?.length) {
      modelsRaw.value = res.models.join('\n')
    } else if (defaultModels.value.length) {
      modelsRaw.value = defaultModels.value.join('\n')
    }
    appStore.showSuccess(
      t('admin.modelFingerprint.verify.discoverSuccess', { count: res.models?.length ?? 0 }),
    )
  } catch (error) {
    if (isUnmounted || seq !== discoverSeq) return
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.discoverFailed'))
  } finally {
    if (!isUnmounted && seq === discoverSeq) {
      discovering.value = false
    }
  }
}

function applyDefaultModels() {
  if (!defaultModels.value.length) return
  const merged = parseModelInput([modelsRaw.value, ...defaultModels.value].join('\n'))
  modelsRaw.value = merged.join('\n')
}

async function handleStartVerify() {
  if (!canStartVerify.value || starting.value) return
  stopPolling()
  starting.value = true
  try {
    const clampedConcurrency = Math.min(5, Math.max(1, Number(concurrency.value) || 3))
    concurrency.value = clampedConcurrency
    const run = await modelFingerprintAPI.createRun({
      ...buildCurrentTarget(),
      suite_id: selectedSuiteId.value > 0 ? selectedSuiteId.value : undefined,
      models: parsedModels.value,
      concurrency: clampedConcurrency,
    })
    if (isUnmounted) return
    cancelSeq++
    cancelling.value = false
    activeRun.value = run
    verdictFilter.value = 'all'
    appStore.showSuccess(t('admin.modelFingerprint.messages.runCreated'))
    if (isTerminalRunStatus(run.status)) {
      emit('run-completed', run)
    } else {
      scheduleNextPoll(run.id)
    }
  } catch (error) {
    if (isUnmounted) return
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.createRunFailed'))
  } finally {
    if (!isUnmounted) {
      starting.value = false
    }
  }
}

async function handleCancelRun() {
  const runId = activeRun.value?.id
  if (!runId || cancelling.value) return
  const seq = ++cancelSeq
  cancelling.value = true
  try {
    await modelFingerprintAPI.cancelRun(runId)
    if (isUnmounted || activeRun.value?.id !== runId) return
    appStore.showSuccess(t('admin.modelFingerprint.messages.runCancelled'))
    const latest = await modelFingerprintAPI.getRun(runId)
    if (isUnmounted || activeRun.value?.id !== runId) return
    activeRun.value = latest
    if (isTerminalRunStatus(latest.status)) {
      stopPolling()
      emit('run-completed', latest)
    }
  } catch (error) {
    if (isUnmounted || activeRun.value?.id !== runId) return
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.cancelRunFailed'))
  } finally {
    if (!isUnmounted && seq === cancelSeq) {
      cancelling.value = false
    }
  }
}

async function handleCopyWhitelist() {
  if (!activeRun.value) return
  const models = extractVerifiedModels(activeRun.value.items, includeUnverified.value)
  if (models.length === 0) {
    appStore.showWarning(t('admin.modelFingerprint.verify.whitelist.emptyWarning'))
    return
  }
  const text = formatVerifiedWhitelist(
    activeRun.value.items,
    whitelistFormat.value,
    includeUnverified.value,
  )
  await copyToClipboard(
    text,
    t('admin.modelFingerprint.verify.whitelist.copiedCount', { count: models.length }),
  )
}

function suspectedCandidateModel(item: RunItem): string {
  if (item.verdict !== 'mismatch' && item.verdict !== 'suspect') return ''
  const top = item.top_candidates?.[0]?.canonical_model
  if (!top || top === item.canonical_model) return ''
  return top
}

onMounted(() => {
  void loadMetadata()
})

onUnmounted(() => {
  isUnmounted = true
  stopPolling()
})
</script>
