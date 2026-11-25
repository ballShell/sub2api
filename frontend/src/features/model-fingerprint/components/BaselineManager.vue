<template>
  <div class="space-y-6">
    <!-- Header & Toolbar -->
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
          {{ t('admin.modelFingerprint.baselines.title') }}
        </h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.baselines.description') }}
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          data-test="open-capture-btn"
          class="btn btn-primary btn-sm"
          @click="openCaptureModal"
        >
          <Icon name="plus" size="xs" />
          {{ t('admin.modelFingerprint.baselines.actions.capture') }}
        </button>
        <button
          type="button"
          data-test="open-confusion-btn"
          class="btn btn-secondary btn-sm"
          @click="openConfusionModal"
        >
          {{ t('admin.modelFingerprint.baselines.actions.confusionMatrix') }}
        </button>
        <button
          type="button"
          data-test="open-families-btn"
          class="btn btn-secondary btn-sm"
          @click="openFamiliesModal"
        >
          {{ t('admin.modelFingerprint.baselines.families.manageButton') }}
        </button>
        <button
          type="button"
          data-test="open-export-btn"
          class="btn btn-secondary btn-sm"
          @click="openExportModal"
        >
          <Icon name="download" size="xs" />
          {{ t('admin.modelFingerprint.baselines.actions.exportJson') }}
        </button>
        <button
          type="button"
          data-test="open-import-btn"
          class="btn btn-secondary btn-sm"
          @click="openImportModal"
        >
          <Icon name="upload" size="xs" />
          {{ t('admin.modelFingerprint.baselines.actions.importJson') }}
        </button>
        <button
          type="button"
          data-test="refresh-baselines-btn"
          class="btn btn-ghost btn-sm"
          :disabled="loading"
          @click="loadBaselines"
        >
          <Icon name="refresh" size="xs" />
          {{ t('admin.modelFingerprint.common.refresh') }}
        </button>
      </div>
    </div>

    <!-- Filters Bar -->
    <section class="grid gap-3 rounded-xl border border-gray-200 bg-gray-50/60 p-4 dark:border-dark-700 dark:bg-dark-900/40 sm:grid-cols-2 lg:grid-cols-7">
      <div>
        <label class="input-label text-xs" for="fp-filter-protocol">
          {{ t('admin.modelFingerprint.baselines.filters.protocol') }}
        </label>
        <select id="fp-filter-protocol" v-model="filters.protocol" class="input py-1.5 text-xs">
          <option value="">{{ t('admin.modelFingerprint.common.all') }}</option>
          <option v-for="proto in SUPPORTED_PROTOCOLS" :key="proto" :value="proto">
            {{ t(`admin.modelFingerprint.protocols.${proto}`) }}
          </option>
        </select>
      </div>

      <div>
        <label class="input-label text-xs" for="fp-filter-suite">
          {{ t('admin.modelFingerprint.baselines.filters.suite') }}
        </label>
        <select id="fp-filter-suite" v-model="filters.suite_id" class="input py-1.5 text-xs">
          <option :value="null">{{ t('admin.modelFingerprint.common.all') }}</option>
          <option v-for="s in suites" :key="s.id" :value="s.id">
            {{ s.name }} ({{ s.version }})
          </option>
        </select>
      </div>

      <div>
        <label class="input-label text-xs" for="fp-filter-model">
          {{ t('admin.modelFingerprint.baselines.filters.canonicalModel') }}
        </label>
        <input
          id="fp-filter-model"
          v-model="filters.canonical_model"
          type="text"
          class="input py-1.5 text-xs"
          :placeholder="t('admin.modelFingerprint.baselines.filters.canonicalModelPlaceholder')"
        />
      </div>

      <div>
        <label class="input-label text-xs" for="fp-filter-detector">
          {{ t('admin.modelFingerprint.baselines.filters.detectorKind') }}
        </label>
        <select id="fp-filter-detector" v-model="filters.detector_kind" class="input py-1.5 text-xs">
          <option value="">{{ t('admin.modelFingerprint.common.all') }}</option>
          <option value="logprobs">{{ t('admin.modelFingerprint.detectors.logprobs') }}</option>
          <option value="behavior">{{ t('admin.modelFingerprint.detectors.behavior') }}</option>
        </select>
      </div>

      <div>
        <label class="input-label text-xs" for="fp-filter-status">
          {{ t('admin.modelFingerprint.baselines.filters.status') }}
        </label>
        <select id="fp-filter-status" v-model="filters.status" class="input py-1.5 text-xs">
          <option value="">{{ t('admin.modelFingerprint.common.all') }}</option>
          <option value="active">{{ t('admin.modelFingerprint.baselineStatus.active') }}</option>
          <option value="archived">{{ t('admin.modelFingerprint.baselineStatus.archived') }}</option>
        </select>
      </div>

      <div>
        <label class="input-label text-xs" for="fp-filter-visibility">
          {{ t('admin.modelFingerprint.baselines.filters.visibility') }}
        </label>
        <select id="fp-filter-visibility" v-model="filters.visibility" class="input py-1.5 text-xs">
          <option value="">{{ t('admin.modelFingerprint.common.all') }}</option>
          <option value="public">{{ t('admin.modelFingerprint.visibility.public') }}</option>
          <option value="private">{{ t('admin.modelFingerprint.visibility.private') }}</option>
        </select>
      </div>

      <div class="flex items-end">
        <button type="button" class="btn btn-secondary btn-sm w-full" @click="resetFilters">
          {{ t('admin.modelFingerprint.baselines.filters.reset') }}
        </button>
      </div>
    </section>

    <!-- Baselines Table -->
    <div v-if="loading" class="py-10 text-center text-sm text-gray-500 dark:text-dark-400">
      {{ t('admin.modelFingerprint.common.loading') }}
    </div>

    <div
      v-else-if="baselines.length === 0"
      class="rounded-xl border border-dashed border-gray-200 p-8 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
    >
      {{ t('admin.modelFingerprint.baselines.empty') }}
    </div>

    <div v-else class="table-container" data-test="baselines-table">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('admin.modelFingerprint.baselines.columns.canonicalModel') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.protocol') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.suite') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.detectorKind') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.source') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.snapshot') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.selfDivergence') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.thresholds') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.freshness') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.status') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.collectedAt') }}</th>
            <th>{{ t('admin.modelFingerprint.baselines.columns.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in baselines" :key="b.id">
            <td class="font-mono text-xs font-semibold text-gray-900 dark:text-white">
              {{ b.canonical_model }}
            </td>
            <td class="text-xs">{{ t(`admin.modelFingerprint.protocols.${b.protocol}`) }}</td>
            <td class="font-mono text-xs">
              {{ b.suite_key ? `${b.suite_key} ${b.suite_version ?? ''}`.trim() : `#${b.suite_id}` }}
            </td>
            <td>
              <span class="badge badge-gray">
                {{ t(`admin.modelFingerprint.detectors.${b.detector_kind}`) }}
              </span>
            </td>
            <td class="text-xs">
              <div class="font-medium text-gray-900 dark:text-white">
                {{ t(`admin.modelFingerprint.sourceTypes.${b.source_type}`) }}
              </div>
              <div class="max-w-[180px] truncate text-gray-500 dark:text-dark-400" :title="b.source_label">
                {{ b.source_label }}
              </div>
            </td>
            <td class="text-xs">
              <div class="font-mono">{{ b.upstream_snapshot || '—' }}</div>
              <div class="text-gray-500 dark:text-dark-400">
                {{ t('admin.modelFingerprint.baselines.sampleCount', { count: b.sample_count }) }}
              </div>
            </td>
            <td class="font-mono text-xs">{{ b.self_divergence_p95.toFixed(4) }}</td>
            <td class="font-mono text-xs">
              {{ b.match_threshold.toFixed(4) }} / {{ b.suspect_threshold.toFixed(4) }}
            </td>
            <td class="text-xs">
              <span class="badge" :class="freshnessBadgeMeta(b.freshness).badgeClass">
                {{ t(freshnessBadgeMeta(b.freshness).labelKey) }}
              </span>
              <div v-if="b.expires_at" class="mt-1 text-[11px] text-gray-500 dark:text-dark-400">
                {{ t('admin.modelFingerprint.baselines.expiresAt', { time: formatDateTime(b.expires_at, locale) }) }}
              </div>
            </td>
            <td>
              <span
                class="badge"
                :class="b.status === 'active' ? 'badge-success' : 'badge-gray'"
              >
                {{ t(`admin.modelFingerprint.baselineStatus.${b.status}`) }}
              </span>
            </td>
            <td class="text-xs text-gray-600 dark:text-dark-300">
              {{ formatDateTime(b.collected_at, locale) }}
            </td>
            <td>
              <div class="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  data-test="edit-baseline-btn"
                  class="btn btn-secondary btn-sm"
                  @click="openEditModal(b)"
                >
                  {{ t('admin.modelFingerprint.baselines.actions.edit') }}
                </button>
                <button
                  type="button"
                  data-test="toggle-baseline-status-btn"
                  class="btn btn-secondary btn-sm"
                  @click="toggleBaselineStatus(b)"
                >
                  {{
                    b.status === 'active'
                      ? t('admin.modelFingerprint.baselines.actions.archive')
                      : t('admin.modelFingerprint.baselines.actions.activate')
                  }}
                </button>
                <button
                  type="button"
                  data-test="delete-baseline-btn"
                  class="btn btn-danger btn-sm"
                  @click="deleteTarget = b"
                >
                  {{ t('admin.modelFingerprint.baselines.actions.delete') }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Capture Modal -->
    <BaseDialog
      :show="showCaptureModal"
      :title="t('admin.modelFingerprint.baselines.captureModal.title')"
      width="wide"
      @close="closeCaptureModal"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.baselines.captureModal.description') }}
        </p>

        <div class="flex items-center justify-between gap-3">
          <span class="input-label mb-0">
            {{ t('admin.modelFingerprint.baselines.captureModal.targetSource') }}
          </span>
          <div class="tabs inline-flex">
            <button
              type="button"
              data-test="capture-mode-adhoc"
              class="tab py-1.5 text-xs"
              :class="{ 'tab-active': captureForm.targetSource === 'adhoc' }"
              @click="captureForm.targetSource = 'adhoc'"
            >
              {{ t('admin.modelFingerprint.verify.adhocMode') }}
            </button>
            <button
              type="button"
              data-test="capture-mode-account"
              class="tab py-1.5 text-xs"
              :class="{ 'tab-active': captureForm.targetSource === 'account' }"
              @click="captureForm.targetSource = 'account'"
            >
              {{ t('admin.modelFingerprint.verify.accountMode') }}
            </button>
          </div>
        </div>

        <div v-if="captureForm.targetSource === 'adhoc'" class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label" for="cap-protocol">
              {{ t('admin.modelFingerprint.baselines.captureModal.protocol') }}
            </label>
            <select id="cap-protocol" v-model="captureForm.adhocProtocol" class="input">
              <option v-for="proto in SUPPORTED_PROTOCOLS" :key="proto" :value="proto">
                {{ t(`admin.modelFingerprint.protocols.${proto}`) }}
              </option>
            </select>
          </div>
          <div>
            <label class="input-label" for="cap-auth-mode">
              {{ t('admin.modelFingerprint.baselines.captureModal.authMode') }}
            </label>
            <select id="cap-auth-mode" v-model="captureForm.authMode" class="input">
              <option value="">{{ t('admin.modelFingerprint.authModes.default') }}</option>
              <option value="bearer">{{ t('admin.modelFingerprint.authModes.bearer') }}</option>
              <option value="x-api-key">{{ t('admin.modelFingerprint.authModes.x-api-key') }}</option>
            </select>
          </div>
          <div class="sm:col-span-2">
            <label class="input-label" for="cap-base-url">
              {{ t('admin.modelFingerprint.baselines.captureModal.baseUrl') }}
            </label>
            <input
              id="cap-base-url"
              v-model="captureForm.baseUrl"
              type="url"
              class="input"
              :placeholder="t('admin.modelFingerprint.verify.baseUrlPlaceholder')"
            />
          </div>
          <div>
            <label class="input-label" for="cap-api-key">
              {{ t('admin.modelFingerprint.baselines.captureModal.apiKey') }}
            </label>
            <input
              id="cap-api-key"
              v-model="captureForm.apiKey"
              type="password"
              autocomplete="off"
              class="input"
              :placeholder="t('admin.modelFingerprint.verify.apiKeyPlaceholder')"
            />
          </div>
          <div>
            <label class="input-label" for="cap-proxy">
              {{ t('admin.modelFingerprint.baselines.captureModal.proxy') }}
            </label>
            <select id="cap-proxy" v-model="captureForm.proxyId" class="input">
              <option :value="null">{{ t('admin.modelFingerprint.verify.proxyNone') }}</option>
              <option v-for="proxy in proxies" :key="proxy.id" :value="proxy.id">
                {{ proxy.name }} ({{ proxy.protocol }}://{{ proxy.host }}:{{ proxy.port }})
              </option>
            </select>
          </div>
        </div>

        <div v-else class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label" for="cap-account">
              {{ t('admin.modelFingerprint.baselines.captureModal.accountLabel') }}
            </label>
            <select
              id="cap-account"
              v-model="captureForm.accountId"
              data-test="capture-account-select"
              class="input"
            >
              <option :value="null" disabled>
                {{ t('admin.modelFingerprint.verify.accountPlaceholder') }}
              </option>
              <option v-for="acc in eligibleAccounts" :key="acc.id" :value="acc.id">
                #{{ acc.id }} · {{ acc.name }} ({{ acc.platform }})
              </option>
            </select>
          </div>
          <div>
            <label class="input-label" for="cap-acc-protocol">
              {{ t('admin.modelFingerprint.baselines.captureModal.protocol') }}
            </label>
            <select
              id="cap-acc-protocol"
              v-model="captureForm.accountProtocol"
              data-test="capture-account-protocol"
              class="input"
            >
              <option value="">{{ t('admin.modelFingerprint.verify.protocolAuto') }}</option>
              <option v-for="proto in SUPPORTED_PROTOCOLS" :key="proto" :value="proto">
                {{ t(`admin.modelFingerprint.protocols.${proto}`) }}
              </option>
            </select>
          </div>
        </div>

        <div class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label" for="cap-suite">
              {{ t('admin.modelFingerprint.baselines.captureModal.suite') }}
            </label>
            <select id="cap-suite" v-model="captureForm.suiteId" class="input">
              <option :value="0">{{ t('admin.modelFingerprint.verify.suiteDefaultOption') }}</option>
              <option v-for="s in activeSuites" :key="s.id" :value="s.id">
                {{ s.name }} ({{ s.suite_key }} {{ s.version }})
              </option>
            </select>
          </div>
          <div>
            <label class="input-label" for="cap-source-type">
              {{ t('admin.modelFingerprint.baselines.captureModal.sourceType') }}
            </label>
            <select id="cap-source-type" v-model="captureForm.sourceType" class="input">
              <option v-for="st in SOURCE_TYPES" :key="st" :value="st">
                {{ t(`admin.modelFingerprint.sourceTypes.${st}`) }}
              </option>
            </select>
          </div>
        </div>

        <div class="grid gap-3 sm:grid-cols-3">
          <div>
            <label class="input-label" for="cap-source-label">
              {{ t('admin.modelFingerprint.baselines.captureModal.sourceLabel') }}
            </label>
            <input id="cap-source-label" v-model="captureForm.sourceLabel" type="text" class="input" />
          </div>
          <div>
            <label class="input-label" for="cap-snapshot">
              {{ t('admin.modelFingerprint.baselines.captureModal.upstreamSnapshot') }}
            </label>
            <input id="cap-snapshot" v-model="captureForm.upstreamSnapshot" type="text" class="input" />
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="input-label" for="cap-rounds">
                {{ t('admin.modelFingerprint.baselines.captureModal.sampleRounds') }}
              </label>
              <input
                id="cap-rounds"
                v-model.number="captureForm.sampleRounds"
                type="number"
                min="3"
                max="5"
                class="input"
              />
            </div>
            <div>
              <label class="input-label" for="cap-ttl">
                {{ t('admin.modelFingerprint.baselines.captureModal.ttlDays') }}
              </label>
              <input
                id="cap-ttl"
                v-model.number="captureForm.ttlDays"
                type="number"
                min="1"
                class="input"
              />
            </div>
          </div>
        </div>

        <div>
          <label class="input-label" for="cap-models">
            {{ t('admin.modelFingerprint.baselines.captureModal.models') }}
          </label>
          <textarea
            id="cap-models"
            v-model="captureForm.modelsRaw"
            rows="3"
            class="input font-mono text-xs"
            :placeholder="t('admin.modelFingerprint.baselines.captureModal.modelsPlaceholder')"
          />
        </div>

        <div>
          <label class="input-label" for="cap-notes">
            {{ t('admin.modelFingerprint.baselines.captureModal.notes') }}
          </label>
          <input id="cap-notes" v-model="captureForm.notes" type="text" class="input" />
        </div>

        <!-- Capture Job Progress & Results -->
        <div
          v-if="captureJob"
          data-test="capture-job-status"
          class="space-y-3 rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-900/50"
        >
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span class="text-sm font-semibold text-gray-900 dark:text-white">
                {{ t('admin.modelFingerprint.baselines.captureModal.jobStatus') }}
              </span>
              <span class="badge" :class="runStatusBadgeMeta(captureJob.status).badgeClass">
                {{ t(runStatusBadgeMeta(captureJob.status).labelKey) }}
              </span>
            </div>
            <span class="font-mono text-xs text-gray-600 dark:text-dark-300">
              {{
                t('admin.modelFingerprint.baselines.captureModal.jobProgress', {
                  completed: captureJob.completed_models,
                  total: captureJob.total_models,
                })
              }}
            </span>
          </div>

          <div class="progress">
            <div
              class="progress-bar"
              :style="{
                width: `${
                  captureJob.total_models > 0
                    ? Math.round((captureJob.completed_models / captureJob.total_models) * 100)
                    : 0
                }%`,
              }"
            />
          </div>

          <p v-if="captureJob.error_message" class="text-xs text-red-600 dark:text-red-400">
            {{ captureJob.error_message }}
          </p>

          <div v-if="captureJob.results?.length" class="space-y-2">
            <div
              v-for="res in captureJob.results"
              :key="res.model"
              class="rounded-lg border border-gray-200 bg-white p-3 text-xs dark:border-dark-700 dark:bg-dark-800"
            >
              <div class="flex flex-wrap items-center justify-between gap-2">
                <span class="font-mono font-semibold text-gray-900 dark:text-white">
                  {{ res.model }} → {{ res.canonical_model }}
                </span>
                <span
                  v-if="res.overlap_warning"
                  class="badge border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300"
                >
                  {{ t('admin.modelFingerprint.baselines.captureModal.overlapWarningBadge') }}
                </span>
              </div>
              <div class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-gray-600 dark:text-dark-300">
                <span v-if="res.logprobs_baseline_id">
                  {{ t('admin.modelFingerprint.baselines.captureModal.logprobsBaseline') }}: #{{
                    res.logprobs_baseline_id
                  }}
                  <span v-if="res.logprobs_self_div_p95 != null" class="font-mono">
                    (P95 {{ res.logprobs_self_div_p95.toFixed(4) }})
                  </span>
                </span>
                <span v-if="res.behavior_baseline_id">
                  {{ t('admin.modelFingerprint.baselines.captureModal.behaviorBaseline') }}: #{{
                    res.behavior_baseline_id
                  }}
                  <span v-if="res.behavior_self_div_p95 != null" class="font-mono">
                    (P95 {{ res.behavior_self_div_p95.toFixed(4) }})
                  </span>
                </span>
              </div>
              <p v-if="res.overlap_details?.length" class="mt-1 text-amber-700 dark:text-amber-300">
                {{ t('admin.modelFingerprint.baselines.captureModal.overlapDetails') }}:
                {{ res.overlap_details.join(' ; ') }}
              </p>
              <p v-if="res.error" class="mt-1 text-red-600 dark:text-red-400">
                {{ res.error }}
              </p>
            </div>
          </div>
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="closeCaptureModal">
          {{ t('admin.modelFingerprint.baselines.captureModal.closeButton') }}
        </button>
        <button
          type="button"
          data-test="start-capture-btn"
          class="btn btn-primary"
          :disabled="!canStartCapture || startingCapture"
          @click="handleStartCapture"
        >
          {{
            startingCapture
              ? t('admin.modelFingerprint.baselines.captureModal.starting')
              : t('admin.modelFingerprint.baselines.captureModal.startButton')
          }}
        </button>
      </template>
    </BaseDialog>

    <!-- Confusion Matrix Modal -->
    <BaseDialog
      :show="showConfusionModal"
      :title="t('admin.modelFingerprint.baselines.confusionModal.title')"
      width="extra-wide"
      @close="showConfusionModal = false"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.baselines.confusionModal.description') }}
        </p>

        <div class="grid gap-3 sm:grid-cols-4">
          <div>
            <label class="input-label" for="cm-protocol">
              {{ t('admin.modelFingerprint.baselines.confusionModal.protocol') }}
            </label>
            <select id="cm-protocol" v-model="confusionForm.protocol" class="input">
              <option v-for="proto in SUPPORTED_PROTOCOLS" :key="proto" :value="proto">
                {{ t(`admin.modelFingerprint.protocols.${proto}`) }}
              </option>
            </select>
          </div>
          <div>
            <label class="input-label" for="cm-suite">
              {{ t('admin.modelFingerprint.baselines.confusionModal.suite') }}
            </label>
            <select id="cm-suite" v-model="confusionForm.suiteId" class="input">
              <option :value="0">{{ t('admin.modelFingerprint.verify.suiteDefaultOption') }}</option>
              <option v-for="s in suites" :key="s.id" :value="s.id">
                {{ s.name }} ({{ s.version }})
              </option>
            </select>
          </div>
          <div>
            <label class="input-label" for="cm-detector">
              {{ t('admin.modelFingerprint.baselines.confusionModal.detectorKind') }}
            </label>
            <select id="cm-detector" v-model="confusionForm.detectorKind" class="input">
              <option value="logprobs">{{ t('admin.modelFingerprint.detectors.logprobs') }}</option>
              <option value="behavior">{{ t('admin.modelFingerprint.detectors.behavior') }}</option>
            </select>
          </div>
          <div class="flex items-end">
            <button
              type="button"
              data-test="compute-confusion-btn"
              class="btn btn-primary w-full"
              :disabled="computingConfusion"
              @click="handleComputeConfusionMatrix"
            >
              {{
                computingConfusion
                  ? t('admin.modelFingerprint.baselines.confusionModal.computing')
                  : t('admin.modelFingerprint.baselines.confusionModal.computeButton')
              }}
            </button>
          </div>
        </div>

        <template v-if="confusionResult">
          <div
            v-if="confusionResult.models.length === 0"
            class="rounded-xl border border-dashed border-gray-200 p-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
          >
            {{ t('admin.modelFingerprint.baselines.confusionModal.empty') }}
          </div>

          <div v-else class="space-y-4">
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="rounded-xl border border-gray-200 bg-gray-50 p-3.5 dark:border-dark-700 dark:bg-dark-900/50">
                <p class="text-xs text-gray-500 dark:text-dark-400">
                  {{ t('admin.modelFingerprint.baselines.confusionModal.minOffDiagonal') }}
                </p>
                <p class="mt-1 font-mono text-lg font-bold text-gray-900 dark:text-white">
                  {{ confusionResult.min_off_diagonal.toFixed(4) }}
                </p>
              </div>

              <div class="rounded-xl border border-gray-200 bg-gray-50 p-3.5 dark:border-dark-700 dark:bg-dark-900/50">
                <p class="text-xs font-medium text-gray-700 dark:text-dark-200">
                  {{ t('admin.modelFingerprint.baselines.confusionModal.closePairsTitle') }}
                </p>
                <p
                  v-if="!confusionResult.close_pairs?.length"
                  class="mt-1 text-xs text-emerald-700 dark:text-emerald-300"
                >
                  {{ t('admin.modelFingerprint.baselines.confusionModal.closePairsNone') }}
                </p>
                <ul v-else class="mt-1.5 space-y-1 text-xs">
                  <li
                    v-for="pair in confusionResult.close_pairs"
                    :key="`${pair.model_a}-${pair.model_b}`"
                    class="flex flex-wrap items-center gap-2 text-red-700 dark:text-red-300"
                  >
                    <span class="font-mono">
                      {{
                        t('admin.modelFingerprint.baselines.confusionModal.closePairItem', {
                          modelA: pair.model_a,
                          modelB: pair.model_b,
                          distance: pair.distance.toFixed(4),
                        })
                      }}
                    </span>
                    <span
                      v-if="pair.overlap_warning"
                      class="badge border border-red-200 bg-red-50 text-red-700 dark:border-red-800/60 dark:bg-red-950/40 dark:text-red-300"
                    >
                      {{ t('admin.modelFingerprint.baselines.confusionModal.overlapBadge') }}
                    </span>
                  </li>
                </ul>
              </div>
            </div>

            <div class="space-y-2">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
                  {{ t('admin.modelFingerprint.baselines.confusionModal.matrixTitle') }}
                </h4>
                <p class="text-xs text-gray-500 dark:text-dark-400">
                  {{ t('admin.modelFingerprint.baselines.confusionModal.legendHint') }}
                </p>
              </div>

              <div class="table-container">
                <table class="table text-xs">
                  <thead>
                    <tr>
                      <th />
                      <th v-for="modelName in confusionResult.models" :key="modelName" class="font-mono">
                        {{ modelName }}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(rowModel, rIdx) in confusionResult.models" :key="rowModel">
                      <td class="font-mono font-semibold text-gray-900 dark:text-white">
                        {{ rowModel }}
                      </td>
                      <td
                        v-for="(colModel, cIdx) in confusionResult.models"
                        :key="`${rowModel}-${colModel}`"
                        class="font-mono text-center"
                        :class="
                          confusionCellMeta(
                            confusionResult.matrix[rIdx]?.[cIdx] ?? 0,
                            rIdx === cIdx,
                            isCloseConfusionPair(confusionResult, rowModel, colModel),
                          ).cellClass
                        "
                      >
                        {{ (confusionResult.matrix[rIdx]?.[cIdx] ?? 0).toFixed(3) }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </template>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="showConfusionModal = false">
          {{ t('admin.modelFingerprint.common.close') }}
        </button>
      </template>
    </BaseDialog>

    <!-- Family & Alias Mappings Modal -->
    <BaseDialog
      :show="showFamiliesModal"
      :title="t('admin.modelFingerprint.baselines.families.title')"
      width="wide"
      @close="showFamiliesModal = false"
    >
      <div class="space-y-5">
        <p class="text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.baselines.families.description') }}
        </p>

        <!-- Family Map Form -->
        <form
          class="space-y-3 rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-900/50"
          @submit.prevent="handleSaveFamily"
        >
          <div class="flex items-center justify-between gap-2">
            <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
              {{ t('admin.modelFingerprint.baselines.families.addButton') }}
            </h4>
            <button
              v-if="editingFamilyCanonical"
              type="button"
              class="btn btn-ghost btn-sm"
              @click="resetFamilyForm"
            >
              {{ t('admin.modelFingerprint.common.cancel') }}
            </button>
          </div>

          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="input-label" for="fam-canonical">
                {{ t('admin.modelFingerprint.baselines.families.canonicalModel') }}
              </label>
              <input
                id="fam-canonical"
                v-model="familyForm.canonicalModel"
                data-test="family-canonical-input"
                type="text"
                class="input font-mono text-xs"
                :disabled="Boolean(editingFamilyCanonical)"
              />
            </div>
            <div>
              <label class="input-label" for="fam-family">
                {{ t('admin.modelFingerprint.baselines.families.family') }}
              </label>
              <input
                id="fam-family"
                v-model="familyForm.family"
                data-test="family-name-input"
                type="text"
                class="input text-xs"
              />
            </div>
          </div>

          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="input-label" for="fam-aliases">
                {{ t('admin.modelFingerprint.baselines.families.aliases') }}
              </label>
              <textarea
                id="fam-aliases"
                v-model="familyForm.aliasesRaw"
                data-test="family-aliases-input"
                rows="2"
                class="input font-mono text-xs"
                :placeholder="t('admin.modelFingerprint.baselines.families.aliasesPlaceholder')"
              />
            </div>
            <div>
              <label class="input-label" for="fam-peers">
                {{ t('admin.modelFingerprint.baselines.families.confusionPeers') }}
              </label>
              <textarea
                id="fam-peers"
                v-model="familyForm.peersRaw"
                data-test="family-peers-input"
                rows="2"
                class="input font-mono text-xs"
                :placeholder="t('admin.modelFingerprint.baselines.families.confusionPeersPlaceholder')"
              />
            </div>
          </div>

          <div class="flex justify-end">
            <button
              type="submit"
              data-test="save-family-btn"
              class="btn btn-primary btn-sm"
              :disabled="!familyForm.canonicalModel.trim() || savingFamily"
            >
              {{ t('admin.modelFingerprint.baselines.families.saveButton') }}
            </button>
          </div>
        </form>

        <!-- Families List -->
        <div v-if="loadingFamilies" class="py-6 text-center text-sm text-gray-500">
          {{ t('admin.modelFingerprint.common.loading') }}
        </div>
        <div
          v-else-if="families.length === 0"
          class="rounded-xl border border-dashed border-gray-200 p-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-dark-400"
        >
          {{ t('admin.modelFingerprint.baselines.families.empty') }}
        </div>
        <div v-else class="table-container">
          <table class="table text-xs">
            <thead>
              <tr>
                <th>{{ t('admin.modelFingerprint.baselines.families.canonicalModel') }}</th>
                <th>{{ t('admin.modelFingerprint.baselines.families.family') }}</th>
                <th>{{ t('admin.modelFingerprint.baselines.families.aliases') }}</th>
                <th>{{ t('admin.modelFingerprint.baselines.families.confusionPeers') }}</th>
                <th>{{ t('admin.modelFingerprint.common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="fm in families" :key="fm.canonical_model">
                <td class="font-mono font-semibold text-gray-900 dark:text-white">
                  {{ fm.canonical_model }}
                </td>
                <td>{{ fm.family || '—' }}</td>
                <td class="font-mono">{{ fm.aliases?.join(', ') || '—' }}</td>
                <td class="font-mono">{{ fm.confusion_peers?.join(', ') || '—' }}</td>
                <td>
                  <div class="flex items-center gap-1.5">
                    <button
                      type="button"
                      class="btn btn-secondary btn-sm"
                      @click="startEditFamily(fm)"
                    >
                      {{ t('admin.modelFingerprint.common.edit') }}
                    </button>
                    <button
                      type="button"
                      class="btn btn-danger btn-sm"
                      @click="familyDeleteTarget = fm"
                    >
                      {{ t('admin.modelFingerprint.common.delete') }}
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="showFamiliesModal = false">
          {{ t('admin.modelFingerprint.common.close') }}
        </button>
      </template>
    </BaseDialog>

    <!-- Edit Baseline Thresholds Modal -->
    <BaseDialog
      :show="Boolean(editingBaseline)"
      :title="t('admin.modelFingerprint.baselines.editModal.title')"
      width="normal"
      @close="editingBaseline = null"
    >
      <div v-if="editingBaseline" class="space-y-4">
        <p class="font-mono text-xs font-semibold text-gray-900 dark:text-white">
          {{ editingBaseline.canonical_model }} · {{ editingBaseline.protocol }} ({{
            editingBaseline.detector_kind
          }})
        </p>

        <div class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label" for="edit-match-thr">
              {{ t('admin.modelFingerprint.baselines.editModal.matchThreshold') }}
            </label>
            <input
              id="edit-match-thr"
              v-model.number="editForm.matchThreshold"
              type="number"
              step="0.001"
              min="0"
              max="1"
              class="input font-mono"
            />
          </div>
          <div>
            <label class="input-label" for="edit-suspect-thr">
              {{ t('admin.modelFingerprint.baselines.editModal.suspectThreshold') }}
            </label>
            <input
              id="edit-suspect-thr"
              v-model.number="editForm.suspectThreshold"
              type="number"
              step="0.001"
              min="0"
              max="1"
              class="input font-mono"
            />
          </div>
        </div>

        <p v-if="!editThresholdsValid" class="input-error-text">
          {{ t('admin.modelFingerprint.baselines.editModal.thresholdError') }}
        </p>

        <div class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label" for="edit-ttl">
              {{ t('admin.modelFingerprint.baselines.editModal.ttlDays') }}
            </label>
            <input id="edit-ttl" v-model.number="editForm.ttlDays" type="number" min="1" class="input" />
          </div>
          <div>
            <label class="input-label" for="edit-status">
              {{ t('admin.modelFingerprint.baselines.editModal.status') }}
            </label>
            <select id="edit-status" v-model="editForm.status" class="input">
              <option value="active">{{ t('admin.modelFingerprint.baselineStatus.active') }}</option>
              <option value="archived">{{ t('admin.modelFingerprint.baselineStatus.archived') }}</option>
            </select>
          </div>
        </div>

        <div>
          <label class="input-label" for="edit-notes">
            {{ t('admin.modelFingerprint.baselines.editModal.notes') }}
          </label>
          <textarea id="edit-notes" v-model="editForm.notes" rows="2" class="input" />
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="editingBaseline = null">
          {{ t('admin.modelFingerprint.common.cancel') }}
        </button>
        <button
          type="button"
          data-test="save-baseline-btn"
          class="btn btn-primary"
          :disabled="!editThresholdsValid || savingBaseline"
          @click="handleSaveBaseline"
        >
          {{ t('admin.modelFingerprint.baselines.editModal.saveButton') }}
        </button>
      </template>
    </BaseDialog>

    <!-- Export Modal -->
    <BaseDialog
      :show="showExportModal"
      :title="t('admin.modelFingerprint.baselines.exportModal.title')"
      width="wide"
      @close="showExportModal = false"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.baselines.exportModal.description') }}
        </p>

        <label class="flex cursor-pointer items-center gap-2 text-sm text-gray-700 dark:text-dark-200">
          <input
            v-model="exportIncludePrivate"
            data-test="export-include-private"
            type="checkbox"
            class="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-600"
          />
          <span>{{ t('admin.modelFingerprint.baselines.exportModal.includePrivate') }}</span>
        </label>

        <div
          v-if="exportedBundle && exportedBundleIncludePrivate"
          data-test="export-private-warning"
          class="rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800 dark:border-amber-800/70 dark:bg-amber-950/30 dark:text-amber-200"
        >
          {{ t('admin.modelFingerprint.baselines.exportModal.includePrivateWarning') }}
        </div>

        <div v-if="exportedBundle" class="space-y-3 rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-900/50">
          <div>
            <p class="text-xs font-medium text-gray-500 dark:text-dark-400">
              {{ t('admin.modelFingerprint.baselines.exportModal.sha256Label') }}
            </p>
            <p class="mt-1 break-all font-mono text-xs text-gray-900 dark:text-white">
              {{ exportedBundle.sha256 }}
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <button type="button" class="btn btn-secondary btn-sm" @click="downloadExportedBundle">
              <Icon name="download" size="xs" />
              {{ t('admin.modelFingerprint.baselines.exportModal.downloadJson') }}
            </button>
            <button type="button" class="btn btn-secondary btn-sm" @click="copyExportedBundle">
              <Icon name="copy" size="xs" />
              {{ t('admin.modelFingerprint.baselines.exportModal.copyJson') }}
            </button>
          </div>
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="showExportModal = false">
          {{ t('admin.modelFingerprint.common.close') }}
        </button>
        <button
          type="button"
          data-test="run-export-btn"
          class="btn btn-primary"
          :disabled="exporting"
          @click="handleExportBundle"
        >
          {{
            exporting
              ? t('admin.modelFingerprint.baselines.exportModal.exporting')
              : t('admin.modelFingerprint.baselines.exportModal.exportButton')
          }}
        </button>
      </template>
    </BaseDialog>

    <!-- Import Modal -->
    <BaseDialog
      :show="showImportModal"
      :title="t('admin.modelFingerprint.baselines.importModal.title')"
      width="wide"
      @close="showImportModal = false"
    >
      <div class="space-y-4">
        <p class="text-sm text-gray-500 dark:text-dark-400">
          {{ t('admin.modelFingerprint.baselines.importModal.description') }}
        </p>

        <div class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label" for="imp-conflict">
              {{ t('admin.modelFingerprint.baselines.importModal.conflictMode') }}
            </label>
            <select id="imp-conflict" v-model="importConflictMode" class="input">
              <option value="skip">
                {{ t('admin.modelFingerprint.baselines.importModal.conflictSkip') }}
              </option>
              <option value="overwrite">
                {{ t('admin.modelFingerprint.baselines.importModal.conflictOverwrite') }}
              </option>
            </select>
          </div>

          <div>
            <label class="input-label" for="imp-file">
              {{ t('admin.modelFingerprint.baselines.importModal.fileInputLabel') }}
            </label>
            <input
              id="imp-file"
              type="file"
              accept=".json,application/json"
              class="input py-1.5 text-xs"
              @change="handleImportFile"
            />
          </div>
        </div>

        <div>
          <label class="input-label" for="imp-json">
            {{ t('admin.modelFingerprint.baselines.importModal.jsonLabel') }}
          </label>
          <textarea
            id="imp-json"
            v-model="importJsonRaw"
            rows="8"
            class="input font-mono text-xs"
            :placeholder="t('admin.modelFingerprint.baselines.importModal.jsonPlaceholder')"
          />
          <p v-if="importValidationError" class="input-error-text">
            {{ importValidationError }}
          </p>
        </div>

        <div
          v-if="importResult"
          class="rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-800 dark:border-emerald-800/60 dark:bg-emerald-950/30 dark:text-emerald-200"
        >
          {{
            t('admin.modelFingerprint.baselines.importModal.resultSummary', {
              suitesImported: importResult.suites_imported,
              suitesSkipped: importResult.suites_skipped,
              familiesImported: importResult.family_maps_imported,
              familiesSkipped: importResult.family_maps_skipped,
              baselinesImported: importResult.baselines_imported,
              baselinesSkipped: importResult.baselines_skipped,
            })
          }}
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn btn-secondary" @click="showImportModal = false">
          {{ t('admin.modelFingerprint.common.close') }}
        </button>
        <button
          type="button"
          data-test="run-import-btn"
          class="btn btn-primary"
          :disabled="!importJsonRaw.trim() || importing"
          @click="handleImportBundle"
        >
          {{
            importing
              ? t('admin.modelFingerprint.baselines.importModal.importing')
              : t('admin.modelFingerprint.baselines.importModal.importButton')
          }}
        </button>
      </template>
    </BaseDialog>

    <!-- Delete Confirmations -->
    <ConfirmDialog
      :show="Boolean(deleteTarget)"
      :title="t('admin.modelFingerprint.baselines.deleteConfirmTitle')"
      :message="
        t('admin.modelFingerprint.baselines.deleteConfirmMessage', {
          model: deleteTarget?.canonical_model ?? '',
        })
      "
      :confirm-text="t('admin.modelFingerprint.common.delete')"
      danger
      @confirm="confirmDeleteBaseline"
      @cancel="deleteTarget = null"
    />

    <ConfirmDialog
      :show="Boolean(familyDeleteTarget)"
      :title="t('admin.modelFingerprint.common.delete')"
      :message="
        t('admin.modelFingerprint.baselines.families.deleteConfirm', {
          model: familyDeleteTarget?.canonical_model ?? '',
        })
      "
      :confirm-text="t('admin.modelFingerprint.common.delete')"
      danger
      @confirm="confirmDeleteFamily"
      @cancel="familyDeleteTarget = null"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import * as adminAccounts from '@/api/admin/accounts'
import * as adminProxies from '@/api/admin/proxies'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import { useClipboard } from '@/composables/useClipboard'
import { useAppStore } from '@/stores/app'
import type { AccountListItem, Proxy } from '@/types'
import modelFingerprintAPI from '../api'
import type {
  BaselineFilter,
  BaselineView,
  Bundle,
  CaptureJob,
  ConfusionMatrixResult,
  DetectorKind,
  FamilyMap,
  ImportBundleResult,
  ImportConflictMode,
  ProbeSuite,
  Protocol,
  SourceType,
  Status,
  TargetSource,
} from '../types'
import {
  buildTargetPayload,
  confusionCellMeta,
  formatDateTime,
  formatModelFpError,
  freshnessBadgeMeta,
  isCloseConfusionPair,
  isEligibleFingerprintAccount,
  isTerminalRunStatus,
  parseModelInput,
  runStatusBadgeMeta,
  SUPPORTED_PROTOCOLS,
} from '../viewModel'

const props = withDefaults(
  defineProps<{
    suitesRefreshKey?: number
  }>(),
  { suitesRefreshKey: 0 },
)

const emit = defineEmits<{
  (e: 'suites-changed'): void
}>()

const { t, locale } = useI18n()
const appStore = useAppStore()
const { copyToClipboard } = useClipboard()

const SOURCE_TYPES: readonly SourceType[] = [
  'official_direct',
  'trusted_cloud',
  'cross_verified',
  'community_seed',
]

const baselines = ref<BaselineView[]>([])
const suites = ref<ProbeSuite[]>([])
const accounts = ref<AccountListItem[]>([])
const proxies = ref<Proxy[]>([])
const loading = ref(false)

const filters = reactive<BaselineFilter>({
  protocol: '',
  suite_id: null,
  canonical_model: '',
  detector_kind: '',
  status: '',
  visibility: '',
})

let filterDebounceTimer: number | null = null
let capturePollTimer: number | null = null
let exportSeq = 0
let isUnmounted = false

const eligibleAccounts = computed(() => accounts.value.filter(isEligibleFingerprintAccount))
const activeSuites = computed(() => suites.value.filter((s) => s.status === 'active'))

// Capture Modal state
const showCaptureModal = ref(false)
const startingCapture = ref(false)
const captureJob = ref<CaptureJob | null>(null)
const captureForm = reactive<{
  targetSource: TargetSource
  accountId: number | null
  accountProtocol: Protocol | ''
  adhocProtocol: Protocol
  baseUrl: string
  apiKey: string
  authMode: string
  proxyId: number | null
  suiteId: number
  modelsRaw: string
  sourceType: SourceType
  sourceLabel: string
  upstreamSnapshot: string
  sampleRounds: number
  ttlDays: number
  notes: string
}>({
  targetSource: 'adhoc',
  accountId: null,
  accountProtocol: '',
  adhocProtocol: 'openai_chat',
  baseUrl: '',
  apiKey: '',
  authMode: '',
  proxyId: null,
  suiteId: 0,
  modelsRaw: '',
  sourceType: 'official_direct',
  sourceLabel: '',
  upstreamSnapshot: '',
  sampleRounds: 3,
  ttlDays: 90,
  notes: '',
})

const captureModels = computed(() => parseModelInput(captureForm.modelsRaw))
const canStartCapture = computed(() => {
  const targetReady =
    captureForm.targetSource === 'account'
      ? captureForm.accountId !== null && captureForm.accountId > 0
      : Boolean(captureForm.baseUrl.trim() && captureForm.apiKey.trim())
  return targetReady && captureModels.value.length > 0 && captureModels.value.length <= 20
})

watch(
  () => captureForm.accountId,
  () => {
    captureForm.accountProtocol = ''
  },
)

// Confusion Matrix Modal state
const showConfusionModal = ref(false)
const computingConfusion = ref(false)
const confusionResult = ref<ConfusionMatrixResult | null>(null)
const confusionForm = reactive<{
  protocol: Protocol
  suiteId: number
  detectorKind: DetectorKind
}>({
  protocol: 'openai_chat',
  suiteId: 0,
  detectorKind: 'logprobs',
})

// Family & Alias Maps Modal state
const showFamiliesModal = ref(false)
const loadingFamilies = ref(false)
const savingFamily = ref(false)
const families = ref<FamilyMap[]>([])
const editingFamilyCanonical = ref<string | null>(null)
const familyDeleteTarget = ref<FamilyMap | null>(null)
const familyForm = reactive({
  canonicalModel: '',
  family: '',
  aliasesRaw: '',
  peersRaw: '',
})

// Edit Baseline Modal state
const editingBaseline = ref<BaselineView | null>(null)
const savingBaseline = ref(false)
const editForm = reactive<{
  matchThreshold: number
  suspectThreshold: number
  ttlDays: number
  status: Status
  notes: string
}>({
  matchThreshold: 0.05,
  suspectThreshold: 0.15,
  ttlDays: 90,
  status: 'active',
  notes: '',
})

const editThresholdsValid = computed(() => {
  const m = editForm.matchThreshold
  const s = editForm.suspectThreshold
  return (
    Number.isFinite(m) &&
    Number.isFinite(s) &&
    m >= 0 &&
    m <= 1 &&
    s >= 0 &&
    s <= 1 &&
    m <= s
  )
})

// Delete Baseline Confirm state
const deleteTarget = ref<BaselineView | null>(null)

// Export / Import Modals state
const showExportModal = ref(false)
const exportIncludePrivate = ref(false)
const exporting = ref(false)
const exportedBundle = ref<Bundle | null>(null)
const exportedBundleIncludePrivate = ref(false)

const showImportModal = ref(false)
const importConflictMode = ref<ImportConflictMode>('skip')
const importJsonRaw = ref('')
const importing = ref(false)
const importValidationError = ref('')
const importResult = ref<ImportBundleResult | null>(null)

watch(
  [
    () => filters.protocol,
    () => filters.suite_id,
    () => filters.detector_kind,
    () => filters.status,
    () => filters.visibility,
  ],
  () => {
    void loadBaselines()
  },
)

watch(
  () => filters.canonical_model,
  () => {
    if (filterDebounceTimer !== null) {
      window.clearTimeout(filterDebounceTimer)
    }
    filterDebounceTimer = window.setTimeout(() => {
      void loadBaselines()
    }, 250)
  },
)

watch(
  () => props.suitesRefreshKey,
  () => {
    void loadSuites()
  },
)

function resetFilters() {
  filters.protocol = ''
  filters.suite_id = null
  filters.canonical_model = ''
  filters.detector_kind = ''
  filters.status = ''
  filters.visibility = ''
}

async function loadSuites() {
  try {
    suites.value = await modelFingerprintAPI.listSuites()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadSuitesFailed'))
  }
}

async function loadBaselines() {
  loading.value = true
  try {
    baselines.value = await modelFingerprintAPI.listBaselines({ ...filters })
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadBaselinesFailed'))
  } finally {
    loading.value = false
  }
}

async function loadMetaAndBaselines() {
  await Promise.allSettled([
    loadBaselines(),
    loadSuites(),
    adminAccounts.list(1, 500).then((res) => {
      accounts.value = res?.items ?? []
    }),
    adminProxies.getAll().then((res) => {
      proxies.value = res ?? []
    }),
  ])
}

// Capture workflow
function openCaptureModal() {
  captureJob.value = null
  showCaptureModal.value = true
}

function stopCapturePolling() {
  if (capturePollTimer !== null) {
    window.clearTimeout(capturePollTimer)
    capturePollTimer = null
  }
}

function closeCaptureModal() {
  stopCapturePolling()
  captureForm.apiKey = ''
  showCaptureModal.value = false
}

function scheduleCapturePoll(jobId: number) {
  stopCapturePolling()
  if (isUnmounted || !showCaptureModal.value) return
  capturePollTimer = window.setTimeout(() => {
    void pollCaptureJob(jobId)
  }, 2000)
}

async function pollCaptureJob(jobId: number) {
  if (isUnmounted || !showCaptureModal.value || captureJob.value?.id !== jobId) return
  try {
    const job = await modelFingerprintAPI.getCaptureJob(jobId)
    if (isUnmounted || !showCaptureModal.value || captureJob.value?.id !== jobId) return
    captureJob.value = job
    if (isTerminalRunStatus(job.status)) {
      stopCapturePolling()
      if (job.status === 'completed') {
        appStore.showSuccess(t('admin.modelFingerprint.messages.captureCompleted'))
        await loadBaselines()
      }
    } else {
      scheduleCapturePoll(jobId)
    }
  } catch (error) {
    stopCapturePolling()
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadCaptureFailed'))
  }
}

async function handleStartCapture() {
  if (!canStartCapture.value || startingCapture.value) return
  stopCapturePolling()
  startingCapture.value = true
  try {
    const rounds = Math.min(5, Math.max(3, Number(captureForm.sampleRounds) || 3))
    captureForm.sampleRounds = rounds
    const targetPayload = buildTargetPayload({
      targetSource: captureForm.targetSource,
      accountId: captureForm.accountId,
      accountProtocol: captureForm.accountProtocol,
      adhocProtocol: captureForm.adhocProtocol,
      baseUrl: captureForm.baseUrl,
      apiKey: captureForm.apiKey,
      authMode: captureForm.authMode,
      proxyId: captureForm.proxyId,
    })
    const job = await modelFingerprintAPI.startCapture({
      ...targetPayload,
      suite_id: captureForm.suiteId > 0 ? captureForm.suiteId : undefined,
      models: captureModels.value,
      source_type: captureForm.sourceType,
      source_label: captureForm.sourceLabel.trim() || undefined,
      upstream_snapshot: captureForm.upstreamSnapshot.trim() || undefined,
      sample_rounds: rounds,
      ttl_days: Number(captureForm.ttlDays) || 90,
      notes: captureForm.notes.trim() || undefined,
    })
    captureJob.value = job
    appStore.showSuccess(t('admin.modelFingerprint.messages.captureStarted'))
    if (isTerminalRunStatus(job.status)) {
      if (job.status === 'completed') {
        appStore.showSuccess(t('admin.modelFingerprint.messages.captureCompleted'))
        await loadBaselines()
      }
    } else {
      scheduleCapturePoll(job.id)
    }
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.startCaptureFailed'))
  } finally {
    startingCapture.value = false
  }
}

// Confusion matrix
function openConfusionModal() {
  confusionResult.value = null
  showConfusionModal.value = true
}

async function handleComputeConfusionMatrix() {
  if (computingConfusion.value) return
  computingConfusion.value = true
  try {
    confusionResult.value = await modelFingerprintAPI.getConfusionMatrix({
      protocol: confusionForm.protocol,
      suite_id: confusionForm.suiteId > 0 ? confusionForm.suiteId : undefined,
      detector_kind: confusionForm.detectorKind,
    })
  } catch (error) {
    appStore.showError(
      formatModelFpError(error, t, 'admin.modelFingerprint.errors.confusionMatrixFailed'),
    )
  } finally {
    computingConfusion.value = false
  }
}

// Family maps
function resetFamilyForm() {
  editingFamilyCanonical.value = null
  familyForm.canonicalModel = ''
  familyForm.family = ''
  familyForm.aliasesRaw = ''
  familyForm.peersRaw = ''
}

function startEditFamily(fm: FamilyMap) {
  editingFamilyCanonical.value = fm.canonical_model
  familyForm.canonicalModel = fm.canonical_model
  familyForm.family = fm.family
  familyForm.aliasesRaw = fm.aliases?.join(', ') ?? ''
  familyForm.peersRaw = fm.confusion_peers?.join(', ') ?? ''
}

async function loadFamilies() {
  loadingFamilies.value = true
  try {
    families.value = await modelFingerprintAPI.listFamilies()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.loadFamiliesFailed'))
  } finally {
    loadingFamilies.value = false
  }
}

function openFamiliesModal() {
  resetFamilyForm()
  showFamiliesModal.value = true
  void loadFamilies()
}

async function handleSaveFamily() {
  const canonical = familyForm.canonicalModel.trim()
  if (!canonical || savingFamily.value) return
  savingFamily.value = true
  try {
    await modelFingerprintAPI.upsertFamily(canonical, {
      family: familyForm.family.trim(),
      aliases: parseModelInput(familyForm.aliasesRaw),
      confusion_peers: parseModelInput(familyForm.peersRaw),
    })
    appStore.showSuccess(t('admin.modelFingerprint.messages.familySaved'))
    resetFamilyForm()
    await loadFamilies()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.saveFamilyFailed'))
  } finally {
    savingFamily.value = false
  }
}

async function confirmDeleteFamily() {
  if (!familyDeleteTarget.value) return
  const target = familyDeleteTarget.value
  familyDeleteTarget.value = null
  try {
    await modelFingerprintAPI.deleteFamily(target.canonical_model)
    appStore.showSuccess(t('admin.modelFingerprint.messages.familyDeleted'))
    if (editingFamilyCanonical.value === target.canonical_model) {
      resetFamilyForm()
    }
    await loadFamilies()
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.deleteFamilyFailed'))
  }
}

// Edit / archive / delete baselines
function openEditModal(baseline: BaselineView) {
  editingBaseline.value = baseline
  editForm.matchThreshold = baseline.match_threshold
  editForm.suspectThreshold = baseline.suspect_threshold
  editForm.ttlDays = baseline.ttl_days
  editForm.status = baseline.status
  editForm.notes = baseline.notes ?? ''
}

async function handleSaveBaseline() {
  if (!editingBaseline.value || !editThresholdsValid.value || savingBaseline.value) return
  savingBaseline.value = true
  try {
    await modelFingerprintAPI.updateBaseline(editingBaseline.value.id, {
      match_threshold: editForm.matchThreshold,
      suspect_threshold: editForm.suspectThreshold,
      ttl_days: Number(editForm.ttlDays) || 90,
      status: editForm.status,
      notes: editForm.notes,
    })
    appStore.showSuccess(t('admin.modelFingerprint.messages.baselineUpdated'))
    editingBaseline.value = null
    await loadBaselines()
  } catch (error) {
    appStore.showError(
      formatModelFpError(error, t, 'admin.modelFingerprint.errors.updateBaselineFailed'),
    )
  } finally {
    savingBaseline.value = false
  }
}

async function toggleBaselineStatus(baseline: BaselineView) {
  const nextStatus: Status = baseline.status === 'active' ? 'archived' : 'active'
  try {
    await modelFingerprintAPI.updateBaseline(baseline.id, { status: nextStatus })
    appStore.showSuccess(t('admin.modelFingerprint.messages.baselineUpdated'))
    await loadBaselines()
  } catch (error) {
    appStore.showError(
      formatModelFpError(error, t, 'admin.modelFingerprint.errors.updateBaselineFailed'),
    )
  }
}

async function confirmDeleteBaseline() {
  if (!deleteTarget.value) return
  const target = deleteTarget.value
  deleteTarget.value = null
  try {
    await modelFingerprintAPI.deleteBaseline(target.id)
    appStore.showSuccess(t('admin.modelFingerprint.messages.baselineDeleted'))
    await loadBaselines()
  } catch (error) {
    appStore.showError(
      formatModelFpError(error, t, 'admin.modelFingerprint.errors.deleteBaselineFailed'),
    )
  }
}

watch(exportIncludePrivate, () => {
  exportSeq++
  exporting.value = false
  exportedBundle.value = null
  exportedBundleIncludePrivate.value = false
})

// Export / Import
function openExportModal() {
  exportSeq++
  exportIncludePrivate.value = false
  exporting.value = false
  exportedBundle.value = null
  exportedBundleIncludePrivate.value = false
  showExportModal.value = true
}

async function handleExportBundle() {
  if (exporting.value) return
  const seq = ++exportSeq
  const includePrivate = exportIncludePrivate.value
  exporting.value = true
  try {
    const bundle = await modelFingerprintAPI.exportBaselines(includePrivate)
    if (isUnmounted || seq !== exportSeq || !showExportModal.value) return
    exportedBundle.value = bundle
    exportedBundleIncludePrivate.value = Boolean(bundle.include_private)
    appStore.showSuccess(t('admin.modelFingerprint.messages.bundleExported'))
  } catch (error) {
    if (isUnmounted || seq !== exportSeq) return
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.exportFailed'))
  } finally {
    if (!isUnmounted && seq === exportSeq) {
      exporting.value = false
    }
  }
}

function downloadExportedBundle() {
  if (!exportedBundle.value) return
  const json = JSON.stringify(exportedBundle.value, null, 2)
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `modelfp-bundle-${exportedBundle.value.exported_at.slice(0, 10)}.json`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

async function copyExportedBundle() {
  if (!exportedBundle.value) return
  await copyToClipboard(JSON.stringify(exportedBundle.value, null, 2))
}

function openImportModal() {
  importConflictMode.value = 'skip'
  importJsonRaw.value = ''
  importValidationError.value = ''
  importResult.value = null
  showImportModal.value = true
}

async function handleImportFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  importJsonRaw.value = await file.text()
  importValidationError.value = ''
}

async function handleImportBundle() {
  if (importing.value) return
  importValidationError.value = ''
  let parsed: unknown
  try {
    parsed = JSON.parse(importJsonRaw.value)
  } catch {
    importValidationError.value = t('admin.modelFingerprint.baselines.importModal.invalidJson')
    return
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    importValidationError.value = t('admin.modelFingerprint.baselines.importModal.invalidJson')
    return
  }

  importing.value = true
  try {
    const res = await modelFingerprintAPI.importBaselines({
      bundle: parsed as Bundle,
      conflict_mode: importConflictMode.value,
    })
    importResult.value = res
    appStore.showSuccess(t('admin.modelFingerprint.messages.bundleImported'))
    emit('suites-changed')
    await Promise.allSettled([loadBaselines(), loadSuites()])
  } catch (error) {
    appStore.showError(formatModelFpError(error, t, 'admin.modelFingerprint.errors.importFailed'))
  } finally {
    importing.value = false
  }
}

onMounted(() => {
  void loadMetaAndBaselines()
})

onUnmounted(() => {
  isUnmounted = true
  stopCapturePolling()
  if (filterDebounceTimer !== null) {
    window.clearTimeout(filterDebounceTimer)
  }
})
</script>
