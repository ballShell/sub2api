<template>
  <AppLayout>
    <div class="mx-auto max-w-[1600px] pb-8">
      <header class="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.16em] text-primary-600 dark:text-primary-400">
            {{ t('nav.channelManagement') }}
          </p>
          <h1 class="mt-1 text-2xl font-semibold tracking-tight text-gray-950 dark:text-white">
            {{ t('admin.modelFingerprint.title') }}
          </h1>
          <p class="mt-2 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
            {{ t('admin.modelFingerprint.description') }}
          </p>
        </div>
      </header>

      <div class="mb-4" role="tablist" :aria-label="t('admin.modelFingerprint.title')">
        <div class="tabs inline-flex flex-wrap">
          <button
            v-for="tab in pageTabs"
            :key="tab.id"
            type="button"
            role="tab"
            class="tab"
            :class="{ 'tab-active': activeTab === tab.id }"
            :aria-selected="activeTab === tab.id"
            :data-test="`tab-${tab.id}`"
            @click="selectTab(tab.id)"
          >
            {{ tab.label }}
          </button>
        </div>
      </div>

      <main class="card p-4 sm:p-6 lg:p-8">
        <div v-show="activeTab === 'verify'" data-test="tab-panel-verify" role="tabpanel">
          <VerifyWorkbench
            :suites-refresh-key="suitesRefreshKey"
            @run-completed="runsRefreshKey += 1"
          />
        </div>

        <div v-show="activeTab === 'baselines'" data-test="tab-panel-baselines" role="tabpanel">
          <BaselineManager
            :suites-refresh-key="suitesRefreshKey"
            @suites-changed="suitesRefreshKey += 1"
          />
        </div>

        <div v-show="activeTab === 'suites'" data-test="tab-panel-suites" role="tabpanel">
          <ProbeSuiteManager @suites-changed="suitesRefreshKey += 1" />
        </div>

        <div v-show="activeTab === 'runs'" data-test="tab-panel-runs" role="tabpanel">
          <RunHistoryPanel :refresh-key="runsRefreshKey" />
        </div>
      </main>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import BaselineManager from './components/BaselineManager.vue'
import ProbeSuiteManager from './components/ProbeSuiteManager.vue'
import RunHistoryPanel from './components/RunHistoryPanel.vue'
import VerifyWorkbench from './components/VerifyWorkbench.vue'

type WorkbenchTab = 'verify' | 'baselines' | 'suites' | 'runs'

const { t } = useI18n()

const activeTab = ref<WorkbenchTab>('verify')
const suitesRefreshKey = ref(0)
const runsRefreshKey = ref(0)

const pageTabs = computed(() => [
  { id: 'verify' as const, label: t('admin.modelFingerprint.tabs.verify') },
  { id: 'baselines' as const, label: t('admin.modelFingerprint.tabs.baselines') },
  { id: 'suites' as const, label: t('admin.modelFingerprint.tabs.suites') },
  { id: 'runs' as const, label: t('admin.modelFingerprint.tabs.runs') },
])

function selectTab(tab: WorkbenchTab) {
  activeTab.value = tab
  if (tab === 'runs') {
    runsRefreshKey.value += 1
  }
}
</script>
