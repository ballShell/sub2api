<template>
  <BaseDialog
    :show="show"
    :title="t('admin.modelFingerprint.evidence.title')"
    width="extra-wide"
    @close="$emit('close')"
  >
    <div v-if="item" class="space-y-6" data-test="evidence-drawer">
      <p class="text-sm text-gray-500 dark:text-dark-400">
        {{ t('admin.modelFingerprint.evidence.subtitle') }}
      </p>

      <!-- Prompt injection & stale baseline alerts -->
      <div
        v-if="item.prompt_injection_suspected"
        data-test="evidence-injection-alert"
        role="alert"
        class="rounded-xl border border-red-200 bg-red-50 p-4 dark:border-red-800/70 dark:bg-red-950/40"
      >
        <div class="flex items-start gap-3">
          <Icon name="exclamationTriangle" size="md" class="mt-0.5 shrink-0 text-red-600 dark:text-red-400" />
          <div class="space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <h4 class="text-sm font-semibold text-red-800 dark:text-red-200">
                {{ t('admin.modelFingerprint.evidence.injectionAlertTitle') }}
              </h4>
              <span class="rounded bg-red-100 px-1.5 py-0.5 font-mono text-xs font-semibold text-red-800 dark:bg-red-900/60 dark:text-red-200">
                {{ item.observed_prompt_tokens }}
              </span>
            </div>
            <p class="text-sm text-red-700 dark:text-red-300">
              {{
                t('admin.modelFingerprint.evidence.injectionAlertMessage', {
                  tokens: item.observed_prompt_tokens,
                })
              }}
            </p>
          </div>
        </div>
      </div>

      <div
        v-if="item.used_stale_baseline"
        data-test="evidence-stale-warning"
        role="status"
        class="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800 dark:border-amber-800/70 dark:bg-amber-950/30 dark:text-amber-200"
      >
        {{ t('admin.modelFingerprint.evidence.staleBaselineWarning') }}
      </div>

      <!-- Claimed vs Upstream & Summary Metadata -->
      <section class="grid grid-cols-1 gap-4 rounded-xl border border-gray-200 bg-gray-50/70 p-4 dark:border-dark-700 dark:bg-dark-900/50 sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.claimedModel') }}
          </p>
          <p class="mt-1 break-all font-mono text-sm font-semibold text-gray-900 dark:text-white">
            {{ item.claimed_model }}
          </p>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.upstreamModel') }}
          </p>
          <p class="mt-1 break-all font-mono text-sm font-semibold text-gray-900 dark:text-white">
            {{ item.upstream_model || item.claimed_model }}
          </p>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.canonicalModel') }}
          </p>
          <p class="mt-1 break-all font-mono text-sm text-gray-800 dark:text-dark-200">
            {{ item.canonical_model || '—' }}
          </p>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.verdict') }}
          </p>
          <div class="mt-1">
            <span class="badge" :class="verdictBadgeMeta(item.verdict).badgeClass">
              {{ t(verdictBadgeMeta(item.verdict).labelKey) }}
            </span>
          </div>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.detectorUsed') }}
          </p>
          <p class="mt-1 text-sm text-gray-900 dark:text-white">
            {{
              item.detector_used
                ? t(`admin.modelFingerprint.detectors.${item.detector_used}`)
                : t('admin.modelFingerprint.common.none')
            }}
          </p>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.distance') }} / {{ t('admin.modelFingerprint.evidence.confidence') }}
          </p>
          <p class="mt-1 font-mono text-sm text-gray-900 dark:text-white">
            {{ item.distance.toFixed(4) }} · {{ (item.confidence * 100).toFixed(1) }}%
          </p>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.latency') }}
          </p>
          <p class="mt-1 text-sm text-gray-900 dark:text-white">{{ item.latency_ms }} ms</p>
        </div>

        <div>
          <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t('admin.modelFingerprint.evidence.checkedAt') }}
          </p>
          <p class="mt-1 text-sm text-gray-900 dark:text-white">
            {{ formatDateTime(item.checked_at, locale) }}
          </p>
        </div>

        <div v-if="item.error_code || item.error_message" class="sm:col-span-2 lg:col-span-3">
          <p class="text-xs font-medium text-red-600 dark:text-red-400">
            {{ t('admin.modelFingerprint.evidence.errorCode') }} / {{ t('admin.modelFingerprint.evidence.errorMessage') }}
          </p>
          <p class="mt-1 break-words font-mono text-xs text-red-700 dark:text-red-300">
            {{ [item.error_code, item.error_message].filter(Boolean).join(': ') }}
          </p>
        </div>
      </section>

      <!-- Top-3 Closest Baseline Candidates -->
      <section data-test="evidence-top-candidates" class="space-y-3">
        <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
          {{ t('admin.modelFingerprint.evidence.topCandidatesTitle') }}
        </h4>

        <p
          v-if="!item.top_candidates?.length"
          class="rounded-xl border border-dashed border-gray-200 p-4 text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
        >
          {{ t('admin.modelFingerprint.evidence.topCandidatesEmpty') }}
        </p>

        <div v-else class="space-y-2.5">
          <div
            v-for="(cand, idx) in item.top_candidates.slice(0, 3)"
            :key="`${cand.canonical_model}-${idx}`"
            class="rounded-xl border border-gray-200 bg-white p-3.5 dark:border-dark-700 dark:bg-dark-800/60"
          >
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-mono text-sm font-semibold text-gray-900 dark:text-white">
                  #{{ idx + 1 }} {{ cand.canonical_model }}
                </span>
                <span
                  v-if="cand.within_match"
                  class="badge border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800/60 dark:bg-emerald-950/40 dark:text-emerald-300"
                >
                  {{ t('admin.modelFingerprint.evidence.withinMatch') }}
                </span>
                <span
                  v-if="cand.is_confusion_peer"
                  class="badge border border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800/60 dark:bg-purple-950/40 dark:text-purple-300"
                >
                  {{ t('admin.modelFingerprint.evidence.confusionPeer') }}
                </span>
                <span
                  v-if="cand.freshness"
                  class="badge"
                  :class="freshnessBadgeMeta(cand.freshness).badgeClass"
                >
                  {{ t(freshnessBadgeMeta(cand.freshness).labelKey) }}
                </span>
              </div>

              <div class="flex flex-wrap items-center gap-3 text-xs text-gray-600 dark:text-dark-300">
                <span>
                  {{ t('admin.modelFingerprint.evidence.candidateSimilarity') }}:
                  <strong class="font-mono text-gray-900 dark:text-white">{{
                    (cand.similarity * 100).toFixed(1)
                  }}%</strong>
                </span>
                <span>
                  {{ t('admin.modelFingerprint.evidence.candidateDistance') }}:
                  <strong class="font-mono text-gray-900 dark:text-white">{{
                    cand.distance.toFixed(4)
                  }}</strong>
                </span>
                <span v-if="cand.match_threshold != null">
                  {{ t('admin.modelFingerprint.evidence.candidateThreshold') }}:
                  <strong class="font-mono text-gray-900 dark:text-white">{{
                    cand.match_threshold.toFixed(4)
                  }}</strong>
                </span>
              </div>
            </div>

            <div class="progress mt-2.5">
              <div
                class="progress-bar"
                :style="{ width: `${Math.max(0, Math.min(100, cand.similarity * 100))}%` }"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Per-Probe Raw Evidence -->
      <section data-test="evidence-probes" class="space-y-3">
        <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
          {{ t('admin.modelFingerprint.evidence.probesTitle') }}
        </h4>

        <p
          v-if="!item.evidence?.length"
          class="rounded-xl border border-dashed border-gray-200 p-4 text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
        >
          {{ t('admin.modelFingerprint.evidence.probesEmpty') }}
        </p>

        <div v-else class="space-y-3">
          <article
            v-for="probe in item.evidence"
            :key="probe.probe_id"
            class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-800/60"
          >
            <div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-100 pb-2.5 dark:border-dark-700">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-mono text-sm font-semibold text-gray-900 dark:text-white">
                  {{ probe.probe_id }}
                </span>
                <span class="badge badge-gray">
                  {{ t(`admin.modelFingerprint.detectors.${probe.detector_kind}`) }}
                </span>
                <span
                  v-if="probe.prompt_injection_suspected"
                  class="badge border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300"
                >
                  {{ t('admin.modelFingerprint.verify.results.injectionBadge') }}
                </span>
              </div>
              <div class="flex flex-wrap items-center gap-3 text-xs text-gray-500 dark:text-dark-400">
                <span>
                  {{ t('admin.modelFingerprint.evidence.probeDistance') }}:
                  <strong class="font-mono text-gray-800 dark:text-dark-200">{{
                    probe.distance.toFixed(4)
                  }}</strong>
                </span>
                <span>
                  {{ t('admin.modelFingerprint.evidence.probeWeight') }}:
                  <strong class="font-mono text-gray-800 dark:text-dark-200">{{
                    probe.weight.toFixed(2)
                  }}</strong>
                </span>
                <span v-if="probe.http_status">
                  {{ t('admin.modelFingerprint.evidence.probeHttpStatus', { status: probe.http_status }) }}
                </span>
                <span v-if="probe.latency_ms != null">
                  {{ t('admin.modelFingerprint.evidence.probeLatency', { ms: probe.latency_ms }) }}
                </span>
              </div>
            </div>

            <div class="mt-2.5 flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-600 dark:text-dark-300">
              <span>
                {{
                  t('admin.modelFingerprint.evidence.probeTokens', {
                    prompt: probe.prompt_tokens ?? 0,
                    cached: probe.cached_prompt_tokens ?? 0,
                    output: probe.output_tokens ?? 0,
                  })
                }}
              </span>
              <span v-if="probe.response_model">
                {{ t('admin.modelFingerprint.evidence.probeResponseModel') }}:
                <code class="code">{{ probe.response_model }}</code>
              </span>
              <span v-if="probe.system_fingerprint">
                {{ t('admin.modelFingerprint.evidence.probeSystemFingerprint') }}:
                <code class="code">{{ probe.system_fingerprint }}</code>
              </span>
              <span v-if="probe.has_reasoning_field != null">
                {{ t('admin.modelFingerprint.evidence.probeReasoningField') }}:
                {{
                  probe.has_reasoning_field
                    ? t('admin.modelFingerprint.common.yes')
                    : t('admin.modelFingerprint.common.no')
                }}
              </span>
              <span v-if="probe.logprobs_supported != null">
                {{ t('admin.modelFingerprint.evidence.probeLogprobsSupported') }}:
                {{
                  probe.logprobs_supported
                    ? t('admin.modelFingerprint.common.yes')
                    : t('admin.modelFingerprint.common.no')
                }}
              </span>
              <span v-if="probe.top_k_overlap != null">
                {{ t('admin.modelFingerprint.evidence.probeTopKOverlap') }}:
                <strong class="font-mono">{{ (probe.top_k_overlap * 100).toFixed(1) }}%</strong>
              </span>
            </div>

            <div
              v-if="probe.error_code || probe.error_message"
              class="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/30 dark:text-red-300"
            >
              <span class="font-semibold">{{ t('admin.modelFingerprint.evidence.probeError') }}: </span>
              <span class="font-mono">{{ [probe.error_code, probe.error_message].filter(Boolean).join(': ') }}</span>
            </div>

            <!-- Logprobs Top-K comparison -->
            <div
              v-if="probe.observed_top_tokens?.length || probe.baseline_top_tokens?.length"
              class="mt-3 grid gap-3 sm:grid-cols-2"
            >
              <div class="rounded-lg border border-gray-100 bg-gray-50 p-3 dark:border-dark-700 dark:bg-dark-900/60">
                <p class="mb-2 text-xs font-medium text-gray-600 dark:text-dark-300">
                  {{ t('admin.modelFingerprint.evidence.observedTopTokens') }}
                </p>
                <div class="space-y-1.5">
                  <div
                    v-for="(tp, idx) in probe.observed_top_tokens ?? []"
                    :key="`obs-${idx}`"
                    class="flex items-center justify-between gap-2 text-xs"
                  >
                    <code class="whitespace-pre rounded bg-white px-1.5 py-0.5 font-mono text-gray-900 dark:bg-dark-800 dark:text-gray-100">{{ formatToken(tp.token) }}</code>
                    <span class="font-mono text-gray-600 dark:text-dark-300">
                      {{ (tp.prob * 100).toFixed(1) }}%
                      <span v-if="tp.logprob != null" class="text-gray-400">({{ tp.logprob.toFixed(3) }})</span>
                    </span>
                  </div>
                </div>
              </div>

              <div class="rounded-lg border border-gray-100 bg-gray-50 p-3 dark:border-dark-700 dark:bg-dark-900/60">
                <p class="mb-2 text-xs font-medium text-gray-600 dark:text-dark-300">
                  {{ t('admin.modelFingerprint.evidence.baselineTopTokens') }}
                </p>
                <div class="space-y-1.5">
                  <div
                    v-for="(tp, idx) in probe.baseline_top_tokens ?? []"
                    :key="`base-${idx}`"
                    class="flex items-center justify-between gap-2 text-xs"
                  >
                    <code class="whitespace-pre rounded bg-white px-1.5 py-0.5 font-mono text-gray-900 dark:bg-dark-800 dark:text-gray-100">{{ formatToken(tp.token) }}</code>
                    <span class="font-mono text-gray-600 dark:text-dark-300">
                      {{ (tp.prob * 100).toFixed(1) }}%
                      <span v-if="tp.logprob != null" class="text-gray-400">({{ tp.logprob.toFixed(3) }})</span>
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Behavior text comparison -->
            <div
              v-if="probe.observed_text || probe.baseline_sample_text"
              class="mt-3 grid gap-3 sm:grid-cols-2"
            >
              <div class="rounded-lg border border-gray-100 bg-gray-50 p-3 dark:border-dark-700 dark:bg-dark-900/60">
                <p class="mb-1.5 text-xs font-medium text-gray-600 dark:text-dark-300">
                  {{ t('admin.modelFingerprint.evidence.observedText') }}
                </p>
                <pre class="max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-gray-800 dark:text-dark-200">{{ probe.observed_text || '—' }}</pre>
              </div>
              <div class="rounded-lg border border-gray-100 bg-gray-50 p-3 dark:border-dark-700 dark:bg-dark-900/60">
                <p class="mb-1.5 text-xs font-medium text-gray-600 dark:text-dark-300">
                  {{ t('admin.modelFingerprint.evidence.baselineSampleText') }}
                </p>
                <pre class="max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-gray-800 dark:text-dark-200">{{ probe.baseline_sample_text || '—' }}</pre>
              </div>
            </div>
          </article>
        </div>
      </section>
    </div>

    <template #footer>
      <button type="button" class="btn btn-secondary" @click="$emit('close')">
        {{ t('admin.modelFingerprint.common.close') }}
      </button>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import type { RunItem } from '../types'
import { formatDateTime, freshnessBadgeMeta, verdictBadgeMeta } from '../viewModel'

defineProps<{
  show: boolean
  item: RunItem | null
}>()

defineEmits<{
  (e: 'close'): void
}>()

const { t, locale } = useI18n()

function formatToken(token: string): string {
  return JSON.stringify(token)
}
</script>
