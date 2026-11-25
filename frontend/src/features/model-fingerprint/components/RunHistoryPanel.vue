<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
          {{ t('admin.modelFingerprint.runs.title') }}
        </h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.runs.description') }}
        </p>
      </div>

      <button
        type="button"
        data-test="refresh-runs-btn"
        class="btn btn-secondary btn-sm"
        :disabled="loading"
        @click="loadRuns"
      >
        <Icon name="refresh" size="xs" />
        {{ t('admin.modelFingerprint.common.refresh') }}
      </button>
    </div>

    <!-- Runs Table -->
    <div v-if="loading" class="py-10 text-center text-sm text-gray-500 dark:text-dark-400">
      {{ t('admin.modelFingerprint.common.loading') }}
    </div>

    <div
      v-else-if="runPage.items.length === 0"
      class="rounded-xl border border-dashed border-gray-200 p-8 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
    >
      {{ t('admin.modelFingerprint.runs.empty') }}
    </div>

    <div v-else class="overflow-hidden rounded-xl border border-gray-200 dark:border-dark-700">
      <div class="overflow-x-auto" data-test="runs-table">
        <table class="table">
          <thead>
            <tr>
              <th>{{ t('admin.modelFingerprint.runs.columns.id') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.target') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.protocol') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.status') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.progress') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.summary') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.createdAt') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.finishedAt') }}</th>
              <th>{{ t('admin.modelFingerprint.runs.columns.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="run in runPage.items" :key="run.id">
              <td class="font-mono text-xs font-semibold text-gray-900 dark:text-white">
                #{{ run.id }}
              </td>
              <td class="text-xs">
                <div class="font-medium text-gray-900 dark:text-white">{{ run.target_label }}</div>
                <div class="text-gray-500 dark:text-dark-400">
                  {{ t(`admin.modelFingerprint.targetSources.${run.target_source}`) }}
                </div>
              </td>
              <td class="text-xs">{{ t(`admin.modelFingerprint.protocols.${run.protocol}`) }}</td>
              <td>
                <span class="badge" :class="runStatusBadgeMeta(run.status).badgeClass">
                  {{ t(runStatusBadgeMeta(run.status).labelKey) }}
                </span>
              </td>
              <td class="font-mono text-xs">{{ run.completed_models }} / {{ run.total_models }}</td>
              <td>
                <div class="flex flex-wrap items-center gap-1.5 text-xs">
                  <span class="badge" :class="verdictBadgeMeta('match').badgeClass">
                    {{ t('admin.modelFingerprint.verdicts.match') }}: {{ run.summary.match }}
                  </span>
                  <span
                    v-if="run.summary.suspect > 0"
                    class="badge"
                    :class="verdictBadgeMeta('suspect').badgeClass"
                  >
                    {{ t('admin.modelFingerprint.verdicts.suspect') }}: {{ run.summary.suspect }}
                  </span>
                  <span
                    v-if="run.summary.mismatch > 0"
                    class="badge"
                    :class="verdictBadgeMeta('mismatch').badgeClass"
                  >
                    {{ t('admin.modelFingerprint.verdicts.mismatch') }}: {{ run.summary.mismatch }}
                  </span>
                  <span
                    v-if="run.summary.unverified > 0"
                    class="badge"
                    :class="verdictBadgeMeta('unverified').badgeClass"
                  >
                    {{ t('admin.modelFingerprint.verdicts.unverified') }}: {{ run.summary.unverified }}
                  </span>
                  <span
                    v-if="run.summary.error > 0"
                    class="badge"
                    :class="verdictBadgeMeta('error').badgeClass"
                  >
                    {{ t('admin.modelFingerprint.verdicts.error') }}: {{ run.summary.error }}
                  </span>
                  <span
                    v-if="run.summary.injection_suspected > 0"
                    class="badge border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300"
                  >
                    {{ t('admin.modelFingerprint.verify.results.injectionBadge') }}:
                    {{ run.summary.injection_suspected }}
                  </span>
                </div>
              </td>
              <td class="text-xs text-gray-600 dark:text-dark-300">
                {{ formatDateTime(run.created_at, locale) }}
              </td>
              <td class="text-xs text-gray-600 dark:text-dark-300">
                {{ formatDateTime(run.finished_at, locale) }}
              </td>
              <td>
                <div class="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    data-test="view-run-detail-btn"
                    class="btn btn-secondary btn-sm"
                    @click="openRunDetail(run.id)"
                  >
                    {{ t('admin.modelFingerprint.runs.viewDetail') }}
                  </button>
                  <button
                    v-if="!isTerminalRunStatus(run.status)"
                    type="button"
                    data-test="cancel-history-run-btn"
                    class="btn btn-secondary btn-sm"
                    @click="handleCancelRun(run.id)"
                  >
                    {{ t('admin.modelFingerprint.runs.cancel') }}
                  </button>
                  <button
                    type="button"
                    data-test="delete-run-btn"
                    class="btn btn-danger btn-sm"
                    @click="deleteTarget = run"
                  >
                    {{ t('admin.modelFingerprint.runs.delete') }}
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <Pagination
        v-if="runPage.total > 0"
        :total="runPage.total"
        :page="page"
        :page-size="pageSize"
        @update:page="changePage"
        @update:page-size="changePageSize"
      />
    </div>

    <!-- Run Detail Modal -->
    <BaseDialog
      :show="showDetailModal"
      :title="t('admin.modelFingerprint.runs.detailTitle', { id: activeRunDetail?.id ?? '' })"
      width="extra-wide"
      @close="showDetailModal = false"
    >
      <div v-if="loadingDetail" class="py-10 text-center text-sm text-gray-500">
        {{ t('admin.modelFingerprint.common.loading') }}
      </div>

      <div v-else-if="activeRunDetail" class="space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-200 bg-gray-50 p-3.5 text-xs dark:border-dark-700 dark:bg-dark-900/50">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-semibold text-gray-900 dark:text-white">{{ activeRunDetail.target_label }}</span>
            <span class="badge badge-gray">
              {{ t(`admin.modelFingerprint.protocols.${activeRunDetail.protocol}`) }}
            </span>
            <span class="badge" :class="runStatusBadgeMeta(activeRunDetail.status).badgeClass">
              {{ t(runStatusBadgeMeta(activeRunDetail.status).labelKey) }}
            </span>
          </div>
          <span class="font-mono text-gray-600 dark:text-dark-300">
            {{ activeRunDetail.completed_models }} / {{ activeRunDetail.total_models }}
          </span>
        </div>

        <div
          v-if="!activeRunDetail.items?.length"
          class="rounded-xl border border-dashed border-gray-200 p-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
        >
          {{ t('admin.modelFingerprint.common.empty') }}
        </div>

        <div v-else class="table-container">
          <table class="table text-xs">
            <thead>
              <tr>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.claimedModel') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.upstreamModel') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.verdict') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.detector') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.distance') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.confidence') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.promptTokens') }}</th>
                <th>{{ t('admin.modelFingerprint.verify.results.columns.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="item in activeRunDetail.items"
                :key="item.id"
                class="cursor-pointer"
                @click="selectedEvidenceItem = item"
              >
                <td class="font-mono font-semibold text-gray-900 dark:text-white">
                  {{ item.claimed_model }}
                </td>
                <td class="font-mono text-gray-600 dark:text-dark-300">
                  {{ item.upstream_model || item.claimed_model }}
                </td>
                <td>
                  <div class="flex flex-wrap items-center gap-1.5">
                    <span class="badge" :class="verdictBadgeMeta(item.verdict).badgeClass">
                      {{ t(verdictBadgeMeta(item.verdict).labelKey) }}
                    </span>
                    <span
                      v-if="item.prompt_injection_suspected"
                      class="badge border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300"
                    >
                      {{ t('admin.modelFingerprint.verify.results.injectionBadge') }}
                    </span>
                  </div>
                </td>
                <td>
                  {{
                    item.detector_used
                      ? t(`admin.modelFingerprint.detectors.${item.detector_used}`)
                      : '—'
                  }}
                </td>
                <td class="font-mono">{{ item.distance.toFixed(4) }}</td>
                <td class="font-mono">{{ (item.confidence * 100).toFixed(1) }}%</td>
                <td class="font-mono">{{ item.observed_prompt_tokens }}</td>
                <td>
                  <button
                    type="button"
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
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="showDetailModal = false">
          {{ t('admin.modelFingerprint.common.close') }}
        </button>
      </template>
    </BaseDialog>

    <EvidenceDrawer
      :show="Boolean(selectedEvidenceItem)"
      :item="selectedEvidenceItem"
      @close="selectedEvidenceItem = null"
    />

    <ConfirmDialog
      :show="Boolean(deleteTarget)"
      :title="t('admin.modelFingerprint.runs.deleteConfirmTitle')"
      :message="
        t('admin.modelFingerprint.runs.deleteConfirmMessage', {
          id: deleteTarget?.id ?? '',
        })
      "
      :confirm-text="t('admin.modelFingerprint.runs.delete')"
      danger
      @confirm="confirmDeleteRun"
      @cancel="deleteTarget = null"
    />
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Pagination from '@/components/common/Pagination.vue'
import Icon from '@/components/icons/Icon.vue'
import { useAppStore } from '@/stores/app'
import modelFingerprintAPI from '../api'
import type { Run, RunDetail, RunItem, RunPage } from '../types'
import {
  formatDateTime,
  formatModelFpError,
  isTerminalRunStatus,
  runStatusBadgeMeta,
  verdictBadgeMeta,
} from '../viewModel'
import EvidenceDrawer from './EvidenceDrawer.vue'

const props = withDefaults(
  defineProps<{
    refreshKey?: number
  }>(),
  { refreshKey: 0 },
)

const { t, locale } = useI18n()
const appStore = useAppStore()

const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const runPage = ref<RunPage>({ items: [], total: 0, page: 1, page_size: 20 })

const showDetailModal = ref(false)
const loadingDetail = ref(false)
const activeRunDetail = ref<RunDetail | null>(null)
const selectedEvidenceItem = ref<RunItem | null>(null)
const deleteTarget = ref<Run | null>(null)

watch(
  () => props.refreshKey,
  () => {
    void loadRuns()
  },
)

async function loadRuns() {
  loading.value = true
  try {
    runPage.value = await modelFingerprintAPI.listRuns(page.value, pageSize.value)
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadRunsFailed'))
  } finally {
    loading.value = false
  }
}

function changePage(nextPage: number) {
  page.value = nextPage
  void loadRuns()
}

function changePageSize(nextSize: number) {
  pageSize.value = nextSize
  page.value = 1
  void loadRuns()
}

async function openRunDetail(runId: number) {
  showDetailModal.value = true
  loadingDetail.value = true
  activeRunDetail.value = null
  try {
    activeRunDetail.value = await modelFingerprintAPI.getRun(runId)
  } catch (error) {
    showDetailModal.value = false
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadRunFailed'))
  } finally {
    loadingDetail.value = false
  }
}

async function handleCancelRun(runId: number) {
  try {
    await modelFingerprintAPI.cancelRun(runId)
    appStore.showSuccess(t('admin.modelFingerprint.messages.runCancelled'))
    await loadRuns()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.cancelRunFailed'))
  }
}

async function confirmDeleteRun() {
  if (!deleteTarget.value) return
  const target = deleteTarget.value
  deleteTarget.value = null
  try {
    await modelFingerprintAPI.deleteRun(target.id)
    appStore.showSuccess(t('admin.modelFingerprint.messages.runDeleted'))
    if (runPage.value.items.length === 1 && page.value > 1) {
      page.value -= 1
    }
    await loadRuns()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.deleteRunFailed'))
  }
}

onMounted(() => {
  void loadRuns()
})
</script>
