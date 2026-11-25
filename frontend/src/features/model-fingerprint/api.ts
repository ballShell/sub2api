import { apiClient } from '@/api/client'
import type {
  BaselineFilter,
  BaselineView,
  Bundle,
  CancelRunResult,
  CaptureJob,
  CaptureRequest,
  ConfusionMatrixRequest,
  ConfusionMatrixResult,
  CreateRunRequest,
  CreateSuiteRequest,
  DeleteResult,
  DiscoverModelsRequest,
  DiscoverModelsResponse,
  FamilyMap,
  ImportBundleRequest,
  ImportBundleResult,
  ProbeSuite,
  RunDetail,
  RunPage,
  UpdateBaselineRequest,
  UpdateSuiteStatusRequest,
  UpsertFamilyMapRequest,
} from './types'
import { baselineQueryParams } from './viewModel'

const basePath = '/admin/model-fingerprint'

export async function discoverModels(
  payload: DiscoverModelsRequest,
): Promise<DiscoverModelsResponse> {
  const { data } = await apiClient.post<DiscoverModelsResponse>(
    `${basePath}/discover-models`,
    payload,
  )
  return data
}

export async function createRun(payload: CreateRunRequest): Promise<RunDetail> {
  const { data } = await apiClient.post<RunDetail>(`${basePath}/runs`, payload)
  return data
}

export async function listRuns(page = 1, pageSize = 20): Promise<RunPage> {
  const { data } = await apiClient.get<RunPage>(`${basePath}/runs`, {
    params: { page, page_size: pageSize },
  })
  return data
}

export async function getRun(id: number): Promise<RunDetail> {
  const { data } = await apiClient.get<RunDetail>(`${basePath}/runs/${id}`)
  return data
}

export async function cancelRun(id: number): Promise<CancelRunResult> {
  const { data } = await apiClient.post<CancelRunResult>(`${basePath}/runs/${id}/cancel`)
  return data
}

export async function deleteRun(id: number): Promise<DeleteResult> {
  const { data } = await apiClient.delete<DeleteResult>(`${basePath}/runs/${id}`)
  return data
}

export async function listBaselines(filter: BaselineFilter = {}): Promise<BaselineView[]> {
  const params = baselineQueryParams(filter)
  const { data } =
    Object.keys(params).length > 0
      ? await apiClient.get<BaselineView[]>(`${basePath}/baselines`, { params })
      : await apiClient.get<BaselineView[]>(`${basePath}/baselines`)
  return data ?? []
}

export async function startCapture(payload: CaptureRequest): Promise<CaptureJob> {
  const { data } = await apiClient.post<CaptureJob>(
    `${basePath}/baselines/capture`,
    payload,
  )
  return data
}

export async function getCaptureJob(jobId: number): Promise<CaptureJob> {
  const { data } = await apiClient.get<CaptureJob>(
    `${basePath}/baselines/capture/${jobId}`,
  )
  return data
}

export async function getConfusionMatrix(
  payload: ConfusionMatrixRequest,
): Promise<ConfusionMatrixResult> {
  const { data } = await apiClient.post<ConfusionMatrixResult>(
    `${basePath}/baselines/confusion-matrix`,
    payload,
  )
  return data
}

export async function updateBaseline(
  id: number,
  payload: UpdateBaselineRequest,
): Promise<BaselineView> {
  const { data } = await apiClient.put<BaselineView>(
    `${basePath}/baselines/${id}`,
    payload,
  )
  return data
}

export async function deleteBaseline(id: number): Promise<DeleteResult> {
  const { data } = await apiClient.delete<DeleteResult>(`${basePath}/baselines/${id}`)
  return data
}

export async function exportBaselines(includePrivate = false): Promise<Bundle> {
  const { data } = await apiClient.get<Bundle>(`${basePath}/baselines/export`, {
    params: { include_private: includePrivate },
  })
  return data
}

export async function importBaselines(
  payload: ImportBundleRequest,
): Promise<ImportBundleResult> {
  const { data } = await apiClient.post<ImportBundleResult>(
    `${basePath}/baselines/import`,
    {
      bundle: payload.bundle,
      conflict_mode: payload.conflict_mode ?? 'skip',
    },
  )
  return data
}

export async function listSuites(): Promise<ProbeSuite[]> {
  const { data } = await apiClient.get<ProbeSuite[]>(`${basePath}/suites`)
  return data ?? []
}

export async function createSuite(payload: CreateSuiteRequest): Promise<ProbeSuite> {
  const { data } = await apiClient.post<ProbeSuite>(`${basePath}/suites`, payload)
  return data
}

export async function updateSuiteStatus(
  id: number,
  payload: UpdateSuiteStatusRequest,
): Promise<ProbeSuite> {
  const { data } = await apiClient.put<ProbeSuite>(
    `${basePath}/suites/${id}/status`,
    payload,
  )
  return data
}

export async function listFamilies(): Promise<FamilyMap[]> {
  const { data } = await apiClient.get<FamilyMap[]>(`${basePath}/families`)
  return data ?? []
}

export async function upsertFamily(
  canonicalModel: string,
  payload: UpsertFamilyMapRequest,
): Promise<FamilyMap> {
  const { data } = await apiClient.put<FamilyMap>(
    `${basePath}/families/${encodeURIComponent(canonicalModel)}`,
    {
      ...payload,
      canonical_model: canonicalModel,
    },
  )
  return data
}

export async function deleteFamily(canonicalModel: string): Promise<DeleteResult> {
  const { data } = await apiClient.delete<DeleteResult>(
    `${basePath}/families/${encodeURIComponent(canonicalModel)}`,
  )
  return data
}

export const modelFingerprintAPI = {
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
}

export default modelFingerprintAPI
