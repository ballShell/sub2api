<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
          {{ t('admin.modelFingerprint.suites.title') }}
        </h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.suites.description') }}
        </p>
      </div>

      <div class="flex items-center gap-2">
        <button
          type="button"
          data-test="open-create-suite-btn"
          class="btn btn-primary btn-sm"
          @click="openCreateModal()"
        >
          <Icon name="plus" size="xs" />
          {{ t('admin.modelFingerprint.suites.createButton') }}
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          :disabled="loading"
          @click="loadSuites"
        >
          <Icon name="refresh" size="xs" />
          {{ t('admin.modelFingerprint.common.refresh') }}
        </button>
      </div>
    </div>

    <!-- Suites Table -->
    <div v-if="loading" class="py-10 text-center text-sm text-gray-500 dark:text-dark-400">
      {{ t('admin.modelFingerprint.common.loading') }}
    </div>

    <div
      v-else-if="suites.length === 0"
      class="rounded-xl border border-dashed border-gray-200 p-8 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
    >
      {{ t('admin.modelFingerprint.suites.empty') }}
    </div>

    <div v-else class="table-container" data-test="suites-table">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('admin.modelFingerprint.suites.columns.name') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.suiteKey') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.version') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.visibility') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.status') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.default') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.probeCount') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.contentHash') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.updatedAt') }}</th>
            <th>{{ t('admin.modelFingerprint.suites.columns.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="suite in suites" :key="suite.id">
            <td class="font-medium text-gray-900 dark:text-white">{{ suite.name }}</td>
            <td class="font-mono text-xs">{{ suite.suite_key }}</td>
            <td class="font-mono text-xs">{{ suite.version }}</td>
            <td>
              <span
                class="badge"
                :class="
                  suite.visibility === 'private'
                    ? 'badge-purple'
                    : 'border border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-800/60 dark:bg-sky-950/40 dark:text-sky-300'
                "
              >
                {{ t(`admin.modelFingerprint.visibility.${suite.visibility}`) }}
              </span>
            </td>
            <td>
              <span
                class="badge"
                :class="suite.status === 'active' ? 'badge-success' : 'badge-gray'"
              >
                {{ t(`admin.modelFingerprint.baselineStatus.${suite.status}`) }}
              </span>
            </td>
            <td>
              <span v-if="suite.is_default" class="badge badge-primary">
                {{ t('admin.modelFingerprint.common.defaultBadge') }}
              </span>
              <span v-else class="text-xs text-gray-400 dark:text-dark-500">—</span>
            </td>
            <td class="font-mono text-xs">{{ suite.probes?.length ?? 0 }}</td>
            <td class="font-mono text-xs text-gray-500 dark:text-dark-400" :title="suite.content_hash">
              {{ suite.content_hash.slice(0, 12) }}
            </td>
            <td class="text-xs text-gray-600 dark:text-dark-300">
              {{ formatDateTime(suite.updated_at, locale) }}
            </td>
            <td>
              <div class="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  data-test="view-probes-btn"
                  class="btn btn-secondary btn-sm"
                  @click="viewingProbesSuite = suite"
                >
                  {{ t('admin.modelFingerprint.suites.viewProbes') }}
                </button>
                <button
                  type="button"
                  data-test="clone-suite-btn"
                  class="btn btn-secondary btn-sm"
                  @click="openCreateModal(suite)"
                >
                  {{ t('admin.modelFingerprint.suites.cloneButton') }}
                </button>
                <button
                  type="button"
                  data-test="toggle-default-suite-btn"
                  class="btn btn-secondary btn-sm"
                  :disabled="suite.status === 'archived' && !suite.is_default"
                  @click="toggleDefault(suite)"
                >
                  {{
                    suite.is_default
                      ? t('admin.modelFingerprint.suites.unsetDefault')
                      : t('admin.modelFingerprint.suites.setDefault')
                  }}
                </button>
                <button
                  type="button"
                  data-test="toggle-status-suite-btn"
                  class="btn btn-secondary btn-sm"
                  @click="toggleStatus(suite)"
                >
                  {{
                    suite.status === 'active'
                      ? t('admin.modelFingerprint.suites.archive')
                      : t('admin.modelFingerprint.suites.activate')
                  }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- View Probes Modal -->
    <BaseDialog
      :show="Boolean(viewingProbesSuite)"
      :title="t('admin.modelFingerprint.suites.probesModal.title')"
      width="wide"
      @close="viewingProbesSuite = null"
    >
      <div v-if="viewingProbesSuite" class="space-y-3">
        <div class="flex flex-wrap items-center gap-2 text-xs text-gray-600 dark:text-dark-300">
          <span class="font-semibold text-gray-900 dark:text-white">{{ viewingProbesSuite.name }}</span>
          <span class="font-mono">{{ viewingProbesSuite.suite_key }} {{ viewingProbesSuite.version }}</span>
          <span class="badge" :class="viewingProbesSuite.visibility === 'private' ? 'badge-purple' : 'badge-gray'">
            {{ t(`admin.modelFingerprint.visibility.${viewingProbesSuite.visibility}`) }}
          </span>
        </div>

        <article
          v-for="probe in viewingProbesSuite.probes"
          :key="probe.id"
          class="space-y-2 rounded-xl border border-gray-200 bg-gray-50 p-3.5 text-xs dark:border-dark-700 dark:bg-dark-900/50"
        >
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span class="font-mono font-semibold text-gray-900 dark:text-white">{{ probe.id }}</span>
              <span class="badge badge-gray">
                {{ t(`admin.modelFingerprint.detectors.${probe.kind}`) }}
              </span>
            </div>
            <div class="flex flex-wrap gap-3 font-mono text-gray-500 dark:text-dark-400">
              <span>{{ t('admin.modelFingerprint.suites.probesModal.maxTokens') }}: {{ probe.max_tokens }}</span>
              <span>{{ t('admin.modelFingerprint.suites.probesModal.temperature') }}: {{ probe.temperature }}</span>
              <span v-if="probe.top_logprobs">
                {{ t('admin.modelFingerprint.suites.probesModal.topLogprobs') }}: {{ probe.top_logprobs }}
              </span>
              <span v-if="probe.seed != null">
                {{ t('admin.modelFingerprint.suites.probesModal.seed') }}: {{ probe.seed }}
              </span>
              <span>{{ t('admin.modelFingerprint.suites.probesModal.weight') }}: {{ probe.weight }}</span>
              <span>
                {{ t('admin.modelFingerprint.suites.probesModal.expectedMaxPromptTokens') }}:
                {{ probe.expected_max_prompt_tokens }}
              </span>
            </div>
          </div>

          <p v-if="probe.description" class="text-gray-600 dark:text-dark-300">
            {{ probe.description }}
          </p>

          <div v-if="probe.system_prompt">
            <p class="font-medium text-gray-500 dark:text-dark-400">
              {{ t('admin.modelFingerprint.suites.probesModal.systemPrompt') }}
            </p>
            <pre class="mt-1 whitespace-pre-wrap rounded bg-white p-2 font-mono text-gray-800 dark:bg-dark-800 dark:text-dark-200">{{ probe.system_prompt }}</pre>
          </div>

          <div>
            <p class="font-medium text-gray-500 dark:text-dark-400">
              {{ t('admin.modelFingerprint.suites.probesModal.prompt') }}
            </p>
            <pre class="mt-1 whitespace-pre-wrap rounded bg-white p-2 font-mono text-gray-800 dark:bg-dark-800 dark:text-dark-200">{{ probe.prompt }}</pre>
          </div>

          <p v-if="probe.expected_format" class="text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.suites.probesModal.expectedFormat') }}:
            <code class="code">{{ probe.expected_format }}</code>
          </p>
        </article>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="viewingProbesSuite = null">
          {{ t('admin.modelFingerprint.common.close') }}
        </button>
      </template>
    </BaseDialog>

    <!-- Create / Clone Suite Modal -->
    <BaseDialog
      :show="showCreateModal"
      :title="
        isCloning
          ? t('admin.modelFingerprint.suites.createModal.cloneTitle')
          : t('admin.modelFingerprint.suites.createModal.title')
      "
      width="extra-wide"
      @close="showCreateModal = false"
    >
      <div class="space-y-4">
        <div class="grid gap-3 sm:grid-cols-4">
          <div>
            <label class="input-label" for="suite-key">
              {{ t('admin.modelFingerprint.suites.createModal.suiteKey') }}
            </label>
            <input
              id="suite-key"
              v-model="createForm.suiteKey"
              data-test="suite-key-input"
              type="text"
              class="input font-mono text-xs"
            />
          </div>
          <div>
            <label class="input-label" for="suite-version">
              {{ t('admin.modelFingerprint.suites.createModal.version') }}
            </label>
            <input
              id="suite-version"
              v-model="createForm.version"
              data-test="suite-version-input"
              type="text"
              class="input font-mono text-xs"
            />
          </div>
          <div>
            <label class="input-label" for="suite-name">
              {{ t('admin.modelFingerprint.suites.createModal.name') }}
            </label>
            <input
              id="suite-name"
              v-model="createForm.name"
              data-test="suite-name-input"
              type="text"
              class="input text-xs"
            />
          </div>
          <div>
            <label class="input-label" for="suite-visibility">
              {{ t('admin.modelFingerprint.suites.createModal.visibility') }}
            </label>
            <select
              id="suite-visibility"
              v-model="createForm.visibility"
              data-test="suite-visibility-select"
              class="input text-xs"
            >
              <option value="public">{{ t('admin.modelFingerprint.visibility.public') }}</option>
              <option value="private">{{ t('admin.modelFingerprint.visibility.private') }}</option>
            </select>
          </div>
        </div>

        <div
          v-if="createForm.visibility === 'private'"
          data-test="private-suite-hint"
          class="rounded-xl border border-purple-200 bg-purple-50 px-3.5 py-2.5 text-xs text-purple-800 dark:border-purple-800/60 dark:bg-purple-950/30 dark:text-purple-200"
        >
          {{ t('admin.modelFingerprint.suites.createModal.privateHint') }}
        </div>

        <label class="inline-flex cursor-pointer items-center gap-2 text-xs text-gray-700 dark:text-dark-200">
          <input
            v-model="createForm.isDefault"
            type="checkbox"
            class="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-600"
          />
          <span>{{ t('admin.modelFingerprint.suites.createModal.isDefault') }}</span>
        </label>

        <!-- Probes List Editor -->
        <div class="space-y-3 border-t border-gray-200 pt-3 dark:border-dark-700">
          <div class="flex items-center justify-between">
            <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
              {{ t('admin.modelFingerprint.suites.createModal.probesSectionTitle') }}
            </h4>
            <button
              type="button"
              data-test="add-probe-btn"
              class="btn btn-secondary btn-sm"
              @click="addProbeDraft"
            >
              <Icon name="plus" size="xs" />
              {{ t('admin.modelFingerprint.suites.createModal.addProbe') }}
            </button>
          </div>

          <div
            v-for="(probe, idx) in createForm.probes"
            :key="idx"
            class="space-y-3 rounded-xl border border-gray-200 bg-gray-50 p-3.5 dark:border-dark-700 dark:bg-dark-900/50"
          >
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span class="text-xs font-semibold text-gray-700 dark:text-dark-200">#{{ idx + 1 }}</span>
              <button
                v-if="createForm.probes.length > 1"
                type="button"
                class="btn btn-danger btn-sm"
                @click="createForm.probes.splice(idx, 1)"
              >
                {{ t('admin.modelFingerprint.suites.createModal.removeProbe') }}
              </button>
            </div>

            <div class="grid gap-3 sm:grid-cols-3">
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.id') }}
                </label>
                <input v-model="probe.id" type="text" class="input py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.kind') }}
                </label>
                <select v-model="probe.kind" class="input py-1.5 text-xs">
                  <option value="logprobs">{{ t('admin.modelFingerprint.detectors.logprobs') }}</option>
                  <option value="behavior">{{ t('admin.modelFingerprint.detectors.behavior') }}</option>
                </select>
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.expectedFormat') }}
                </label>
                <input v-model="probe.expected_format" type="text" class="input py-1.5 font-mono text-xs" />
              </div>
            </div>

            <div class="grid gap-3 sm:grid-cols-2">
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.prompt') }}
                </label>
                <textarea v-model="probe.prompt" rows="2" class="input font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.systemPrompt') }}
                </label>
                <textarea v-model="probe.system_prompt" rows="2" class="input font-mono text-xs" />
              </div>
            </div>

            <div class="grid gap-3 sm:grid-cols-6">
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.maxTokens') }}
                </label>
                <input v-model.number="probe.max_tokens" type="number" min="1" class="input py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.temperature') }}
                </label>
                <input v-model.number="probe.temperature" type="number" step="0.1" min="0" class="input py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.topLogprobs') }}
                </label>
                <input v-model.number="probe.top_logprobs" type="number" min="0" max="20" class="input py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.seed') }}
                </label>
                <input v-model="probe.seedRaw" type="text" class="input py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.weight') }}
                </label>
                <input v-model.number="probe.weight" type="number" step="0.1" min="0.1" class="input py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="input-label text-xs">
                  {{ t('admin.modelFingerprint.suites.probesModal.expectedMaxPromptTokens') }}
                </label>
                <input v-model.number="probe.expected_max_prompt_tokens" type="number" min="1" class="input py-1.5 font-mono text-xs" />
              </div>
            </div>

            <div>
              <label class="input-label text-xs">
                {{ t('admin.modelFingerprint.suites.probesModal.description') }}
              </label>
              <input v-model="probe.description" type="text" class="input py-1.5 text-xs" />
            </div>
          </div>

          <p
            v-if="!hasValidProbes || validProbeDrafts.length !== createForm.probes.length"
            class="input-error-text"
          >
            {{ t('admin.modelFingerprint.suites.createModal.validationEmptyProbes') }}
          </p>
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="showCreateModal = false">
          {{ t('admin.modelFingerprint.common.cancel') }}
        </button>
        <button
          type="button"
          data-test="submit-suite-btn"
          class="btn btn-primary"
          :disabled="!canSubmitSuite || submitting"
          @click="handleCreateSuite"
        >
          {{
            submitting
              ? t('admin.modelFingerprint.suites.createModal.submitting')
              : t('admin.modelFingerprint.suites.createModal.submitButton')
          }}
        </button>
      </template>
    </BaseDialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import { useAppStore } from '@/stores/app'
import modelFingerprintAPI from '../api'
import type {
  CreateSuiteProbeInput,
  DetectorKind,
  ProbeSuite,
  Status,
  Visibility,
} from '../types'
import { formatDateTime, formatModelFpError } from '../viewModel'

interface ProbeDraft {
  id: string
  kind: DetectorKind
  prompt: string
  system_prompt: string
  max_tokens: number
  temperature: number
  top_logprobs: number
  seedRaw: string
  weight: number
  expected_max_prompt_tokens: number
  expected_format: string
  description: string
}

const emit = defineEmits<{
  (e: 'suites-changed'): void
}>()

const { t, locale } = useI18n()
const appStore = useAppStore()

const suites = ref<ProbeSuite[]>([])
const loading = ref(false)
const viewingProbesSuite = ref<ProbeSuite | null>(null)
const showCreateModal = ref(false)
const isCloning = ref(false)
const submitting = ref(false)

const createForm = reactive<{
  suiteKey: string
  version: string
  name: string
  visibility: Visibility
  isDefault: boolean
  probes: ProbeDraft[]
}>({
  suiteKey: '',
  version: 'v1',
  name: '',
  visibility: 'private',
  isDefault: false,
  probes: [],
})

function emptyProbeDraft(index = 1): ProbeDraft {
  return {
    id: `probe_${index}`,
    kind: 'behavior',
    prompt: '',
    system_prompt: '',
    max_tokens: 64,
    temperature: 0,
    top_logprobs: 5,
    seedRaw: '',
    weight: 1,
    expected_max_prompt_tokens: 500,
    expected_format: '',
    description: '',
  }
}

function suggestNextVersion(version: string): string {
  const match = /^v(\d+)$/i.exec(version.trim())
  if (match) {
    return `v${Number(match[1]) + 1}`
  }
  return `${version.trim()}-v2`
}

const validProbeDrafts = computed(() =>
  createForm.probes.filter((p) => p.id.trim().length > 0 && p.prompt.trim().length > 0),
)
const hasValidProbes = computed(() => validProbeDrafts.value.length > 0)
const canSubmitSuite = computed(
  () =>
    Boolean(createForm.suiteKey.trim() && createForm.version.trim()) &&
    hasValidProbes.value &&
    validProbeDrafts.value.length === createForm.probes.length,
)

function addProbeDraft() {
  createForm.probes.push(emptyProbeDraft(createForm.probes.length + 1))
}

function openCreateModal(sourceSuite?: ProbeSuite) {
  if (sourceSuite) {
    isCloning.value = true
    const nextVersion = suggestNextVersion(sourceSuite.version)
    createForm.suiteKey = sourceSuite.suite_key
    createForm.version = nextVersion
    createForm.name = `${sourceSuite.name} (${nextVersion})`
    createForm.visibility = sourceSuite.visibility
    createForm.isDefault = false
    createForm.probes = sourceSuite.probes.map((p) => ({
      id: p.id,
      kind: p.kind,
      prompt: p.prompt,
      system_prompt: p.system_prompt ?? '',
      max_tokens: p.max_tokens,
      temperature: p.temperature,
      top_logprobs: p.top_logprobs ?? 5,
      seedRaw: p.seed != null ? String(p.seed) : '',
      weight: p.weight,
      expected_max_prompt_tokens: p.expected_max_prompt_tokens,
      expected_format: p.expected_format ?? '',
      description: p.description ?? '',
    }))
  } else {
    isCloning.value = false
    createForm.suiteKey = 'private-canary'
    createForm.version = 'v1'
    createForm.name = 'Private Canary Suite'
    createForm.visibility = 'private'
    createForm.isDefault = false
    createForm.probes = [emptyProbeDraft(1)]
  }
  showCreateModal.value = true
}

async function loadSuites() {
  loading.value = true
  try {
    suites.value = await modelFingerprintAPI.listSuites()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadSuitesFailed'))
  } finally {
    loading.value = false
  }
}

async function handleCreateSuite() {
  if (!canSubmitSuite.value || submitting.value) return
  submitting.value = true
  try {
    const probes: CreateSuiteProbeInput[] = createForm.probes.map((p) => {
      const parsedSeed = p.seedRaw.trim() !== '' ? Number(p.seedRaw.trim()) : null
      return {
        id: p.id.trim(),
        kind: p.kind,
        prompt: p.prompt.trim(),
        system_prompt: p.system_prompt.trim() || undefined,
        max_tokens: Number(p.max_tokens) > 0 ? Number(p.max_tokens) : undefined,
        temperature: Number.isFinite(p.temperature) ? Number(p.temperature) : 0,
        top_logprobs: p.kind === 'logprobs' ? Number(p.top_logprobs) || 5 : undefined,
        seed: parsedSeed !== null && Number.isInteger(parsedSeed) ? parsedSeed : null,
        weight: Number(p.weight) > 0 ? Number(p.weight) : 1,
        expected_max_prompt_tokens:
          Number(p.expected_max_prompt_tokens) > 0 ? Number(p.expected_max_prompt_tokens) : 500,
        expected_format: p.expected_format.trim() || undefined,
        description: p.description.trim() || undefined,
      }
    })

    await modelFingerprintAPI.createSuite({
      suite_key: createForm.suiteKey.trim(),
      version: createForm.version.trim(),
      name: createForm.name.trim() || `${createForm.suiteKey.trim()} ${createForm.version.trim()}`,
      visibility: createForm.visibility,
      is_default: createForm.isDefault,
      probes,
    })

    appStore.showSuccess(t('admin.modelFingerprint.messages.suiteCreated'))
    showCreateModal.value = false
    await loadSuites()
    emit('suites-changed')
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.createSuiteFailed'))
  } finally {
    submitting.value = false
  }
}

async function toggleDefault(suite: ProbeSuite) {
  try {
    await modelFingerprintAPI.updateSuiteStatus(suite.id, {
      status: suite.status,
      is_default: !suite.is_default,
    })
    appStore.showSuccess(t('admin.modelFingerprint.messages.suiteUpdated'))
    await loadSuites()
    emit('suites-changed')
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.updateSuiteFailed'))
  }
}

async function toggleStatus(suite: ProbeSuite) {
  const nextStatus: Status = suite.status === 'active' ? 'archived' : 'active'
  try {
    await modelFingerprintAPI.updateSuiteStatus(suite.id, {
      status: nextStatus,
      is_default: nextStatus === 'archived' ? false : undefined,
    })
    appStore.showSuccess(t('admin.modelFingerprint.messages.suiteUpdated'))
    await loadSuites()
    emit('suites-changed')
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.updateSuiteFailed'))
  }
}

onMounted(() => {
  void loadSuites()
})
</script>
