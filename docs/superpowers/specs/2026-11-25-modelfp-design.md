# Sub2API 模型指纹识别模块（`modelfp`）设计文档

- **日期**：2026-11-25
- **目标仓库**：`ballShell/sub2api`（fork 自 `Wei-Shaw/sub2api`，基线 `v0.2.24`）
- **部署环境**：`starbridge-jp`（Azure VM，2 vCPU / 891 MB RAM + 2 GB Swap；单镜像 `ghcr.io/ballshell/sub2api:<version>` 蓝绿部署；PostgreSQL 16 + Redis + Cloudflare + Nginx）
- **状态**：已通过独立工程评审与决策修订，待用户最终批准

---

## 1. 意图与背景（Intent & Why）

Starbridge 中转站接入的上游 API 包含第三方中转站及后续官方 API Key 渠道。在引入新上游时，上游宣称支持的模型清单经常存在三类风险：

1. **不可用或假宣称**：`/v1/models` 或上游页面列出大量模型，实际调用返回 404/502/503（直接上线会触发 Sub2API 账号 30 分钟冷却）。
2. **暗中替换 / 降级（Model Substitution / Downgrade）**：宣称 `claude-opus-4-6` 实为 `claude-sonnet-4-6` 或低价模型，宣称 `gpt-5` 实为小模型或开源套壳。
3. **隐性上下文注入**：上游中转自动注入数千 token 的固定系统提示词（已在 `gateai.cc` 实测观察到约 4K 缓存 token 注入），既抬高成本，也会干扰简单问答式验真。

本模块面向 **Sub2API 管理员**，在引入上游 API 时提供**逐模型验真工作台**与**可长期维护的版本化指纹库**，确保配置进网关提供给用户的模型保真。

**成功标准**：
- 管理员可直接填临时上游凭据（采购前验货）或选择 Sub2API 已有标准 REST API Key 账号，拉取或输入模型清单后一键逐个验真；
- 覆盖 **OpenAI Chat Completions、OpenAI Responses、Anthropic Messages、Gemini** 四大主力协议；
- 返回 `logprobs` 时走高置信度分布比对，无 `logprobs`（Claude / Responses / Gemini / 阉割中转）时自动回退至多维度黑盒行为/协议探针；
- 管理员可在后台自主采集官方/可信基准指纹、运行混淆矩阵冲突检查、管理私有金丝雀探针、导出/导入指纹包；
- 验收完毕后可在验货台一键复制通过核验的模型清单（支持换行 / 逗号 / JSON 格式）；
- 纯 Go 进程内实现，无新增容器，内存增量极低，与上游 `Wei-Shaw/sub2api` 保持极低合并冲突。

---

## 2. 目标、非目标与反目标

### 2.1 目标（Goals）

1. **独立垂直切片架构**：后端全部收口在 `backend/internal/modelfp/`，前端全部收口在 `frontend/src/features/model-fingerprint/`（对齐 Sub2API 现有的 `internal/securityaudit` + `features/prompt-audit`），对上游文件仅保留 5 处极小挂载点，不修改其他业务页面或组件。
2. **四协议双引擎纯 Go 识别（顺序回退）**：
   - 协议层：`openai_chat`、`openai_responses`、`anthropic`、`gemini`，统一走 SSRF 安全客户端，并支持复用账号绑定代理或管理员按 Sub2API `proxy_id` 指定代理。
   - 引擎层：`LogprobsDetector`（优先）→ 不支持或无 `logprobs` 基线时顺序回退至 `BehaviorProtocolDetector`；两类引擎统一执行上游隐性提示词注入检测。
3. **异步逐模型批量验货**：支持单次批量核验多个模型（上限 50），后台任务异步推进、前端轮询进度与单模型实时结果，规避 Cloudflare 100 秒超时。
4. **版本化指纹库与校准闭环**：支持 `go:embed` 内置种子 + PostgreSQL 覆盖层；支持公开探针套件与私有金丝雀探针套件；支持后台从官方/可信端点多轮采集基线（自动算类内波动与自适应阈值）、混淆矩阵自检、JSON 导出/导入（SHA-256 校验）。
5. **零 Ent / 零上游迁移编号冲突**：模块通过 `*sql.DB` 启动时幂等建表，不修改 `ent/schema/*.go`，不占用 `backend/migrations/253_*.sql` 上游序号。

### 2.2 非目标（Non-Goals，留待二期按需扩展）

- 支持 OAuth / `setup-token` / 影子账号 / Bedrock / Vertex（`service_account`）/ Antigravity / Grok 非标端点的账号直验（用户确认首版不做 OAuth 账号）。
- 修改现有账号配置弹窗组件（如 `ModelWhitelistSelector.vue`；用户确认选方案 A，严守最小上游前端改动面）。
- 后台定时漂移巡检 Runner（Redis Leader Lock 定时扫描）。
- 账号级一键锚定（写入 `accounts.extra["modelfp"]`）与账号列表页真伪徽章。
- 异常结果自动触发 `temp_unsched` 摘流或推送外部告警通知。
- 本地或远程 Python ML Sidecar（如 LLMmap PyTorch 推理）；但 `Detector` 接口预留扩展点，未来可无缝接入 `SidecarDetector`。
- 终端用户侧页面或公开免鉴权接口（本功能仅限 Admin）。
- 图像/音频/视频/Embedding 非文本模型的指纹识别（首版聚焦文本 LLM）。

### 2.3 反目标（Anti-Goals）

- **破坏 891 MB VM 内存红线或单镜像蓝绿发布**：禁止引入常驻 Python/ML 进程或额外 Docker 容器。
- **高冲突侵入上游热文件**：禁止改造 `account_test_service.go`、`channel_monitor_*.go`、`ModelWhitelistSelector.vue` 或 `ent/schema/`。
- **敏感凭据或私有探针泄露**：临时验货输入的 API Key、`extra_headers` 中的自定义鉴权头以及私有金丝雀探针严禁明文落入 `modelfp_runs`、系统日志或 `audit_logs.request_body`。
- **伪精确误导管理员**：无对应基线或证据不足时，禁止硬猜真假；必须明确返回 `unverified` / `suspect` 并展示完整原始逐条证据链。

---

## 3. 硬约束（Constraints）

- **运行资源**：Azure VM 总内存 891 MB（可用 ~320 MB，蓝绿发布双容器并存），`modelfp` 常驻内存增量应 < 15 MB，运行中单批次受并发上限（默认 3，可配 1–5）与响应体字节上限（256 KB）约束。
- **技术栈与 CI 门禁**：Go `1.27.4`、Gin、Wire DI、PostgreSQL 16、Vue 3 + TypeScript + `pnpm`（不新增重型前端依赖；若改动 `package.json` 必须同步 `pnpm-lock.yaml`）。必须通过 `go test -tags=unit ./...`、`golangci-lint`（v2.13）及前端 `vitest` / `vue-tsc` 检查。
- **命名隔离**：禁止复用 `fingerprint` / `tlsfingerprint` / `anthropicfp` 等已有命名，统一使用包名 `modelfp`、表前缀 `modelfp_`、路由前缀 `/api/v1/admin/model-fingerprint`、前端路由 `/admin/model-fingerprint`。
- **超时与网关穿透**：批量验货与多轮基准采集必须采用**异步任务提交 + 2 秒状态轮询**，不阻塞单个 HTTP 请求超过 Cloudflare 100 秒上限。
- **安全、SSRF 与审计日志脱敏**：
  - 临时上游 Base URL 必须校验 scheme（`http`/`https`）与主机，拒绝回环/私网/链路本地/云元数据 IP，且在 socket 级 `DialContext` 防 DNS Rebinding；
  - **[设计方默认决定]** 临时目标仅允许通过 Sub2API 已有 `proxy_id`（只读查 `ProxyRepository`）选择代理，不接受自由输入的原始 `proxy_url` 字符串，从根源消除代理 SSRF 与代理账密泄露风险；
  - **[设计方默认决定]** 将携带凭据/自定义头/私有探针的 `modelfp` 路由加入 `backend/internal/server/middleware/audit_log.go` 的 `auditBodyOmittedRoutes`（对齐 `prompt-audit`），防止 `audit_logs.request_body` 记录自定义鉴权头或私有金丝雀探针。

---

## 4. 方案对比与选型（Approaches）

| 方案 | 核心做法 | 优点 | 缺点与取舍 | 结论 |
| :--- | :--- | :--- | :--- | :--- |
| **方案 1：独立垂直切片聚焦首版** | 建独立包 `internal/modelfp` + `features/model-fingerprint`，聚焦「引入验货 + 四协议双引擎 + 可维护指纹库」，暂不做定时巡检与自动摘流 | 100% 契合管理员引入验货痛点；与上游几乎零合并冲突；单二进制低内存；先在真实上游校准探针准确率，二期加定时巡检零返工 | 首版无后台自动定时复检，需人工手动触发 | **已选定** |
| **方案 2：完整一体版** | 在方案 1 上同步做完定时巡检、账号 `extra` 锚定、自动 `temp_unsched` 摘流 | 上线即覆盖引入后防降级 | 首版工作量约翻倍；阈值未经真实上游验证前接自动摘流易误杀断流 | 留作二期增量 |
| **方案 3：挂入 `channel_monitor`** | 在现有渠道监控 `check_mode` 中新增指纹检测模式 | 复用部分列表和定时代码 | `channel_monitor` 是上游高频迭代区，合并冲突高；且分钟级探活与引入验货/指纹库维护体验错配 | 淘汰 |

---

## 5. 系统架构与代码组织

### 5.1 后端垂直切片结构（`sub2api/backend/internal/modelfp/`）

```text
backend/internal/modelfp/
├── module.go                  # Wire ProviderSet，供 cmd/server/wire.go 引入
├── types.go                   # 协议/裁决枚举、领域结构、API DTO、领域错误
├── schema.go                  # EnsureSchema(ctx, *sql.DB) 幂等建表与索引
├── seeds/
│   ├── embed.go               # go:embed 加载默认种子包
│   ├── probe_suites.v1.json   # 默认内置公开探针套件（v1）
│   ├── family_maps.v1.json    # 默认主力模型别名与近亲对照表
│   └── baselines.v1.json      # 初始参考基线（默认空数组，绝不编造未经实测的分布）
├── ssrf.go                    # 独立 SSRF 校验与 safeDialContext（不依赖 service 包私有函数）
├── transport.go               # 四协议 HTTP 请求构造、响应解析、受控代理拨号、/models 模型发现
├── account_resolver.go        # 只读桥接 service.AccountRepository & ProxyRepository 解析目标
├── detector.go                # Detector 接口、双引擎顺序回退编排器、统一提示词注入检测、Top-K 排名
├── detector_logprobs.go       # 单 Token logprobs 分布提取、归一化、JS 散度与 Top-K 重叠度
├── detector_behavior.go       # 多维黑盒探针（协议元特征 + 确定性/结构化探针）
├── calibration.go             # 类内波动 D_self、最近邻距离 D_near、自适应阈值推导、混淆矩阵
├── repository.go              # PostgreSQL 持久化（基于 *sql.DB，附接口便于单测 mock）
├── baseline_service.go        # L1/L2 指纹库读取、双引擎基准采集、混淆矩阵、JSON 导出/导入
├── verify_service.go          # 批量验货任务编排、并发池、取消控制、白名单提取
├── service.go                 # 统一门面 Service（含 Start/Stop 生命周期、启动时清理遗留 running 状态）
├── handler.go                 # Gin AdminHandler（统一使用 pkg/response 与 pkg/errors）
└── *_test.go                  # 单元测试（httptest 模拟四协议、数学计算、SSRF、导入导出、Handler）
```

### 5.2 前端独立特性目录（`sub2api/frontend/src/features/model-fingerprint/`）

```text
frontend/src/features/model-fingerprint/
├── api.ts                     # 对接 /admin/model-fingerprint/* 的类型化 API 客户端
├── types.ts                   # TypeScript 类型定义
├── viewModel.ts               # 纯逻辑转换（白名单多格式生成、状态标签、混淆矩阵映射）
├── ModelFingerprintView.vue   # 主视图（4 Tab：验货工作台 / 指纹基准库 / 探针套件 / 验货历史）
├── components/
│   ├── VerifyWorkbench.vue    # 临时凭据/已有 API Key 账号切换、拉取模型、批量进度与结果表
│   ├── EvidenceDrawer.vue     # 抽屉：逐条探针响应、logprobs Top-K 对比、注入警告、Top-3 候选
│   ├── BaselineManager.vue    # 基线列表、采集弹窗、混淆矩阵弹窗、导出/导入 JSON
│   ├── ProbeSuiteManager.vue  # 探针套件列表、新建私有金丝雀套件、启用/归档
│   └── RunHistoryPanel.vue    # 历史批次列表与详情回看
└── __tests__/                 # Vitest 单元测试（api / viewModel / 核心组件）
```

### 5.3 对上游文件的最小侵入面（仅 5 处）

| 文件 | 改动内容 | 备注 |
| :--- | :--- | :--- |
| `backend/cmd/server/wire.go`（及重新生成的 `wire_gen.go`）、`backend/cmd/server/main.go` | 引入 `modelfp.ProviderSet`；`Application` 增加 `ModelFP *modelfp.Service`；`runMainServer` 启动时调用 `app.ModelFP.Start(ctx)`（失败仅降级打日志，不阻塞主网关）；`provideCleanup` 注册 `Stop()` | 完全仿照 `PromptAudit` |
| `backend/internal/handler/handler.go`、`backend/internal/handler/wire.go` | `AdminHandlers` 增加 `ModelFP *modelfp.AdminHandler`；`ProvideAdminHandlers` 透传 | 2 行改动 |
| `backend/internal/server/routes/admin.go` | `RegisterAdminRoutes` 内增加 `registerModelFingerprintRoutes(admin, h)` | 独立小函数 |
| `backend/internal/server/middleware/audit_log.go` | 在 `auditBodyOmittedRoutes` 中注册 `modelfp` 含凭据/私有探针的 5 条写路由 | 安全必需，对齐 `prompt-audit` |
| `frontend/src/router/index.ts`、`frontend/src/components/layout/AppSidebar.vue`、`frontend/src/i18n/locales/{zh,en}` | 注册 `/admin/model-fingerprint` 路由与侧边栏菜单、补充中英文文案 | 不改 `ModelWhitelistSelector.vue` 或其他业务页面 |

---

## 6. 目标解析、四协议适配与双引擎检测设计

### 6.1 目标解析规则（`account_resolver.go`）

统一抽象 `ProbeTarget`：
- **`source = "adhoc"`（采购前临时验货）**：管理员输入 `protocol`、`base_url`、`api_key`、可选 `auth_mode`（Anthropic 默认 `x-api-key`，可选 `bearer`）、可选 `proxy_id`（查 `ProxyRepository` 获取受控代理）、可选 `extra_headers`。
- **`source = "account"`（已有账号验真）**：
  - **支持范围（用户已确认）**：仅支持标准 REST 的 **API Key 类账号**（`account.Type == "apikey"` 且 `account.ParentAccountID == nil`，平台为 `openai`、`anthropic`、`gemini` 及 OpenAI 兼容国产供应商 `kimi`/`zhipu`/`deepseek`/`minimax`）。
  - **明确拒绝的非目标账号**：OAuth、`setup-token`、影子账号（`ParentAccountID != nil`）、Bedrock、Vertex（`service_account`）、Antigravity 及非标协议账号一律返回结构化 `400 MODELFP_UNSUPPORTED_ACCOUNT_TYPE`，提示管理员使用 API Key 账号或临时凭据。
  - **协议默认推断**：`openai` 账号默认按账号配置或管理员显式选定 `openai_chat` / `openai_responses`；`anthropic` 走 `anthropic`；`gemini` 走 `gemini`；国产 OpenAI 兼容渠道按其协议基址走 `openai_chat`（支持管理员在验货台覆盖所选协议）。
  - **[设计方默认决定] 映射与请求头透传**：解析已有账号时，**应用该账号生效的 `model_mapping` 与 `header_overrides`**（确保验的是用户经该账号实际拿到的模型），并在每条验货记录与证据中同时保留 `claimed_model`（对外宣称/请求模型名）和 `upstream_model`（映射后实际发往上游的模型名）。

### 6.2 四协议探测适配矩阵（`transport.go`）

| 协议标识 | 默认探测路径（兼容 BaseURL 带或不带 `/v1`） | 模型发现路径 | 鉴权头 | `logprobs` 探测能力 |
| :--- | :--- | :--- | :--- | :--- |
| `openai_chat` | `POST /v1/chat/completions` | `GET /v1/models` | `Authorization: Bearer <key>` | 请求 `logprobs: true, top_logprobs: 20, max_tokens: 1, temperature: 0, seed: 42`；若上游忽略或返回 400 参数错自动去参重试并标记 `logprobs_supported = false` |
| `openai_responses` | `POST /v1/responses` | `GET /v1/models` | `Authorization: Bearer <key>` | 无稳定单 token logprobs，直接走行为/协议引擎（同时采集 `model`、`reasoning`、`usage` 字段结构） |
| `anthropic` | `POST /v1/messages` | `GET /v1/models`（失败降级手填） | `x-api-key: <key>`（可选 `Bearer`）+ `anthropic-version: 2023-06-01` | Anthropic 原生无 logprobs，直接走行为/协议引擎 |
| `gemini` | `POST /v1beta/models/{model}:generateContent` | `GET /v1beta/models` | `x-goog-api-key: <key>` | 尝试 `generationConfig.responseLogprobs: true, logprobs: 20`；不支持/400 时自动去参重试并回退行为引擎 |

所有请求固定 `stream: false`，响应体上限 **256 KB**，单探针超时 **30 秒**（`openai_responses` 推理类允许 **60 秒**）。

### 6.3 双引擎顺序回退与统一提示词注入检测

**[设计方默认决定]** 核验阶段采用**严格顺序回退**（不做模糊的混合加权融合），并将**隐性提示词注入检测提升至共享探测层**，使两个引擎都能捕获注入信号：

1. **共享提示词注入诊断（两引擎通用）**：
   - 每条短探针都标注 `expected_max_prompt_tokens`（默认 500）。
   - 解析响应 `usage`（OpenAI `prompt_tokens` / `input_tokens` / `cached_tokens`、Anthropic `input_tokens` / `cache_read_input_tokens`、Gemini `promptTokenCount` / `cachedContentTokenCount`）。
   - 任一探针观测到输入 token 超出 `expected_max_prompt_tokens` 时，标记 `prompt_injection_suspected = true` 并记录 `observed_prompt_tokens` 最大值，在前端显式告警（即便 `logprobs` 仍能判别模型，管理员也能一眼看到上游暗中塞了 4K 提示词抬高成本）。

2. **阶段一：优先 `LogprobsDetector`（仅 `openai_chat` / `gemini`）**：
   - 前置条件：协议支持 `logprobs`，且当前 `(protocol, suite_id)` 下**存在对应宣称模型的有效 `logprobs` 基线**（或无该模型基线但库内存在其他 `logprobs` 基线可用于候选排名）。
   - 执行套件内全部 `kind = "logprobs"` 探针（默认 4–5 条多样性短前缀，`max_tokens = 1, temperature = 0`）。
   - 对每条探针提取首 token 的 Top-K 分布 $\{(t_i, p_i)\}$，保留字节/空格差异，剩余质量归入 `<OTHER>` 桶，与基准分布计算归一化 **Jensen-Shannon 散度（JSD $\in [0, 1]$）** 及 Top-5 重叠度，按探针权重加权求平均距离 $D_{\text{lp}}$。
   - 若目标未返回任何有效 `logprobs`（或该宣称模型仅有 `behavior` 基线而无 `logprobs` 基线），自动进入阶段二。

3. **阶段二：回退 `BehaviorProtocolDetector`（四协议全覆盖）**：
   - 执行套件内全部 `kind = "behavior"` 探针（5–6 条抗提示词注入的短探针，`max_tokens <= 64, temperature = 0`，含公开探针与管理员私有金丝雀探针），同时提取协议元信息（`response.model` 是否暴露异族模型名、`system_fingerprint`、`reasoning`/`thinking` 字段形态）。
   - 计算每条探针相对基准样本集的综合距离（规范化编辑距离 + 字符/词 n-gram Jaccard 距离 + 结构化格式匹配度），加权求和得到 $D_{\text{bh}} \in [0, 1]$。

### 6.4 裁决语义（5 种明确状态）

先通过 `ModelFamilyMap` 将 `claimed_model` 归一为 `canonical_model`，再用当前生效引擎与同 `(protocol, suite_id, detector_kind)` 下所有 `active` 基线（无 `active` 时回退 `stale` 并带过期提醒）比对，产出 `top_candidates`（前 3 名）与裁决：

- **`error`**：探测请求失败（细分 `model_not_found` / `auth_error` / `rate_limited` / `upstream_error` / `timeout` / `ssrf_blocked`），方便直接淘汰假宣称/不可用模型。
- **`unverified`**：调用成功，但当前 `(protocol, suite_id, detector_kind)` 中缺少 `canonical_model` 的基准画像（仍返回完整原始探针特征、`logprobs` 支持情况、注入警告与库内 Top-3 最像模型）。
- **`match`**：到宣称模型基线的距离 $\le \text{match\_threshold}$，且在 `top_candidates` 中居首（未明显输给非同源模型）。
- **`suspect`**：距离位于 $(\text{match\_threshold}, \text{suspect\_threshold}]$，或与同家族近亲降级模型（`confusion_peers`）距离过于接近，或触发高强度提示词注入使行为引擎置信度受限。
- **`mismatch`**：到宣称模型基线的距离 $> \text{suspect\_threshold}$；若另一模型距离落在其 `match_threshold` 内，明确提示“疑似实际为 `<candidate_model>`”。

---

## 7. 指纹库维护、双引擎采集与自适应校准

### 7.1 三层来源与导入导出

1. **L1 内置种子（`internal/modelfp/seeds/`，`go:embed`）**：随二进制内置默认公开探针套件（`builtin-public/v1`）与主流模型别名/近亲映射；`baselines.v1.json` 默认空数组，绝不编造未经实测的分布。
2. **L2 PostgreSQL 覆盖层（`modelfp_*` 表）**：存放管理员通过官方/可信账号采集的基线、导入的指纹包、以及自定义/私有金丝雀探针套件。
3. **JSON 导出/导入**：带 `schema_version`、`exported_at`、`sha256` 校验和；导出默认 `include_private=false`（排除私有金丝雀套件），导入严格校验 `sha256` 并支持 `skip` / `overwrite`。

### 7.2 基准采集策略（`POST /baselines/capture`）

**[设计方默认决定] 双引擎同步采集**：
- 在 `openai_chat` / `gemini` 上执行基准采集时，每轮（默认 $K = 3$，可配 $3\sim5$ 轮）同时跑完套件的 **`logprobs` 子集与 `behavior` 子集**：
  - 若源端点返回有效 `logprobs`，为该模型写入/更新 **2 条活跃基线**（`detector_kind = 'logprobs'` 与 `detector_kind = 'behavior'`）；
  - 若源端点不支持 `logprobs`（或协议为 `openai_responses` / `anthropic`），写入/更新 **`detector_kind = 'behavior'`** 1 条基线。
- **价值**：只需用官方/可信端点采一次，后续不管第三方中转站是否剥离 `logprobs`，都能匹配到对应的官方基线，彻底避免“官方采了 `logprobs`、中转站阉割 `logprobs` 后回退行为引擎却报 `unverified`”的断层。

### 7.3 自适应阈值与混淆矩阵自检（`calibration.go`）

- 采集 $K$ 轮后计算：
  - **类内波动 $D_{\text{self}}$**：$K$ 轮样本两两距离的 P95；
  - **最近邻距离 $D_{\text{near}}$**：与库中同 `(protocol, suite_id, detector_kind)` 其他活跃基线的最小距离。
- **自适应阈值推导**（管理员后续可经 `PUT /baselines/:id` 微调）：
  - `logprobs` 引擎（$\epsilon_{\text{min}}=0.03,\ \epsilon_{\text{max}}=0.25$）：
    $$\text{match\_threshold} = \text{clamp}\big(\max(2.5 \cdot D_{\text{self}},\ 0.03),\ 0.03,\ \min(0.45 \cdot D_{\text{near}},\ 0.25)\big)$$
    $$\text{suspect\_threshold} = \min\big(\max(2 \cdot \text{match\_threshold},\ 0.65 \cdot D_{\text{near}}),\ 0.45\big)$$
  - `behavior` 引擎（$\epsilon_{\text{min}}=0.12,\ \epsilon_{\text{max}}=0.38$）：采用同结构公式；若库内尚无其他基线（无 $D_{\text{near}}$），采用引擎默认保守阈值。
- **冲突预警与新鲜度**：若 $D_{\text{near}} < 1.5 \cdot D_{\text{self}}$，在采集结果中返回 `overlap_warning`；支持 `POST /baselines/confusion-matrix` 查看两两距离矩阵；滚动模型默认 `ttl_days = 60`、日期锁定快照默认 `180`，超期后在查询视图中标注 `stale` 提醒复采。

---

## 8. 数据库表结构与 Admin API 契约

### 8.1 PostgreSQL 表（启动时 `EnsureSchema` 幂等建表，零 Ent / 零 `migrations/` 冲突）

1. **`modelfp_probe_suites`**：`id`, `suite_key`, `version`, `name`, `visibility`（`public|private`）, `status`（`active|archived`）, `is_default`, `probes_json`（JSONB）, `content_hash`, `created_by`, `created_at`, `updated_at`；`UNIQUE (suite_key, version)`。
2. **`modelfp_baselines`**：`id`, `canonical_model`, `protocol`, `suite_id`（FK）, `detector_kind`（`logprobs|behavior`）, `source_type`（`official_direct|trusted_cloud|cross_verified|community_seed`）, `source_label`, `upstream_snapshot`, `sample_count`, `signature_json`（JSONB）, `self_divergence_p95`, `match_threshold`, `suspect_threshold`, `ttl_days`, `status`（`active|archived`）, `notes`, `collected_at`, `created_at`, `updated_at`；部分唯一索引 `UNIQUE (canonical_model, protocol, suite_id, detector_kind) WHERE status = 'active'`。
3. **`modelfp_family_maps`**：`canonical_model`（PK）, `family`, `aliases_json`（JSONB）, `confusion_peers_json`（JSONB）, `updated_at`。
4. **`modelfp_runs`**：`id`, `target_source`（`adhoc|account`）, `account_id`（NULLABLE）, `target_label`（脱敏展示名，不含密钥）, `protocol`, `suite_id`, `status`（`queued|running|completed|cancelled|failed`）, `total_models`, `completed_models`, `summary_json`（JSONB）, `error_message`, `created_by`, `started_at`, `finished_at`, `created_at`。
5. **`modelfp_run_items`**：`id`, `run_id`（FK CASCADE）, `claimed_model`, `upstream_model`, `canonical_model`, `verdict`, `detector_used`, `confidence`, `distance`, `prompt_injection_suspected`, `observed_prompt_tokens`, `top_candidates_json`（JSONB）, `evidence_json`（JSONB）, `latency_ms`, `error_code`, `error_message`, `checked_at`。
6. **`modelfp_capture_jobs`**：`id`, `status`, `protocol`, `suite_id`, `source_type`, `sample_rounds`, `total_models`, `completed_models`, `results_json`（JSONB，含每模型生成的 `logprobs`/`behavior` 基线 ID、$D_{\text{self}}$、$D_{\text{near}}$ 与冲突警告）, `error_message`, `created_by`, `created_at`, `finished_at`。

### 8.2 Admin HTTP API（前缀 `/api/v1/admin/model-fingerprint`）

| 方法与路径 | 用途 | 审计体豁免 |
| :--- | :--- | :--- |
| `POST /discover-models` | 对临时凭据或 `account_id` 拉取上游可用模型清单 | 是 |
| `POST /runs` | 创建异步批量验货任务（最多 50 模型，并发 1–5，返回 `run_id`） | 是 |
| `GET /runs` / `GET /runs/:id` | 分页查历史批次 / 轮询批次进度与逐模型明细 | 否 |
| `POST /runs/:id/cancel` / `DELETE /runs/:id` | 取消运行中批次 / 删除历史批次 | 否 |
| `GET /baselines` | 按协议/套件/模型/引擎/状态筛选基线（附 `freshness`） | 否 |
| `POST /baselines/capture` / `GET /baselines/capture/:job_id` | 提交异步双引擎基准采集 / 轮询采集进度与校准报告 | POST 是 |
| `POST /baselines/confusion-matrix` | 计算 `(protocol, suite_id, detector_kind)` 两两距离矩阵 | 否 |
| `PUT /baselines/:id` / `DELETE /baselines/:id` | 调整阈值/状态/TTL/备注 / 删除基线 | 否 |
| `GET /baselines/export` / `POST /baselines/import` | 导出（默认排除私有套件）/ 导入带 `sha256` 校验指纹包 | POST 是 |
| `GET /suites` / `POST /suites` / `PUT /suites/:id/status` | 列表 / 新建版本（含私有金丝雀）/ 启用归档设默认 | POST 是 |
| `GET /families` / `PUT /families/:canonical_model` / `DELETE /families/:canonical_model` | 管理模型别名与近亲平替对照表 | 否 |

---

## 9. 前端管理台交互设计（`/admin/model-fingerprint`）

挂在管理后台侧边栏「渠道管理」组下方（紧邻「渠道监控」），支持中英文 i18n，不修改 `ModelWhitelistSelector.vue` 或其他现有业务组件：

1. **验货工作台（Verify Workbench）**：
   - 目标表单：切换「已有 API Key 账号」/「临时上游」；选已有账号时自动列出支持的标准 REST API Key 账号并带出其协议与已配置模型；选临时上游时填协议、Base URL、API Key、可选已有代理（`proxy_id` 下拉）；点击「拉取模型列表」或手动多行粘贴模型名；选择探针套件与并发度后启动批量验真。
   - 实时进度区（2 秒轮询）：汇总卡片（真实 / 疑似 / 不符 / 无基线 / 调用失败）+ 取消按钮 + **「一键复制通过验真的模型清单」**（提供换行 / 逗号分隔 / JSON 三种格式，默认仅取 `match`，可选勾选 `unverified`）+ 逐模型结果表；点击任一行展开右侧 **证据抽屉**（显示 `claimed_model` vs `upstream_model`、所用引擎、提示词注入告警与观测 token 数、Top-3 最像候选、逐条探针 `logprobs` Top-K 或文本对比）。
2. **指纹基准库（Baselines）**：筛选、发起双引擎采集弹窗、查看混淆矩阵热力表弹窗、导出/导入 JSON 包、编辑阈值/归档。
3. **探针套件（Probe Suites）**：查看公开/私有版本、基于现有版本克隆新建私有金丝雀探针版本、设默认/归档。
4. **验货历史（Runs）**：分页回看历史批次与各模型明细，支持删除。

---

## 10. 测试与验证策略

- **后端单元测试（`go test -tags=unit ./internal/modelfp/...`）**：
  - `httptest.Server` 全量模拟四协议（正常 `logprobs`、400 参数剥离自动回退、高 `prompt_tokens` 注入告警、404/401/429/502、超时与取消）；
  - 数学确定性测试（JSD 对称性/边界值/Top-K 归一化、$D_{\text{self}}$ 与 $D_{\text{near}}$ 阈值推导、混淆矩阵）；
  - 账号解析测试（标准 API Key 账号 + `model_mapping`/`header_overrides` 应用，OAuth/影子/Bedrock/Vertex 账号明确报 `MODELFP_UNSUPPORTED_ACCOUNT_TYPE`）；
  - 安全测试（SSRF 私网/回环/云元数据拦截、无自由 `proxy_url`、API Key 不入库/不入日志、`auditBodyOmittedRoutes` 覆盖测试）；
  - 持久化与导入导出测试（SHA-256 篡改拒绝、`skip`/`overwrite`、默认排除私有套件）。
- **前端单元测试（Vitest）**：`api.ts`、`viewModel.ts`（白名单多格式复制、混淆矩阵映射）及 `VerifyWorkbench` 核心轮询/展示测试。
- **容器化本地验证**：由于本机未装宿主机 `go`/`pnpm` 但已装 Docker，验证阶段通过 `golang:1.27.4` 与 `node`+`pnpm` 容器运行 `wire`、`go test -tags=unit ./...`、`golangci-lint` 和前端 `pnpm test`/`pnpm build`，与 GitHub Actions CI 完全对齐。

---

## 11. 留给实现者决定的细节（Left to the Builder）

- 默认内置公开探针套件（`builtin-public/v1`）具体的 4–5 条 `logprobs` 前缀文本与 5–6 条 `behavior` 探针文案（需短输入、低随机性、高跨模型区分度、无安全审核敏感词）；
- 行为引擎内部各子特征（编辑距离、n-gram Jaccard、协议元信息）的初始默认权重配比；
- 服务启动 `Start()` 时对上次异常退出残留的 `queued`/`running` 任务的自动收尾标记（标为 `failed: server restarted`）；
- 前端组件具体的 Tailwind 样式类、图标选择与抽屉宽度（对齐 `features/prompt-audit`）；
- 历史验货列表的默认分页条数（默认 20 条/页）。
