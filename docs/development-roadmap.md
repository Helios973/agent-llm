# AuditPilot 后续升级路线图

更新时间：2026-07-23

## 实现状态（2026-07-23）

本轮已经落地原清单中除第 6 项“审计结果处置流程”外的功能：

- 任务中心：历史列表、搜索、状态筛选、查看、重命名、重试和删除
- 可恢复任务执行：任务状态持久化，服务重启后重新调度 `queued/running` 任务
- Provider Adapter：OpenAI、DeepSeek、OpenAI-Compatible、Azure OpenAI、Ollama
- Alembic 首个版本迁移及旧数据库兼容补列
- 上传、单文件、总量、文件数、解压总量、压缩比和用户存储配额
- 增量审计基线、变更文件扫描和漏洞新增/持续/已解决对比
- Python AST 调用关系与多语言 Source/Sink 候选分析节点
- LLM Token 用量记录、月度配额检查和管理员配额调整
- 登录会话查看/撤销、管理员强制下线及管理员操作日志

第 6 项仍按原设计保留在路线图中。

## 1. 当前能力判断

当前项目已经具备一个可运行的多用户代码审计产品原型：

- 用户注册、登录、管理员角色和任务归属控制
- 多文件、目录、压缩包上传及受控解压
- 静态扫描、LLM 复核、风险归类和报告生成
- 用户独立配置 OpenAI、DeepSeek、OpenAI-Compatible 平台
- API Key 加密保存、模型列表自动识别
- WebSocket 审计进度、管理员查看和停止普通用户任务
- HTML、Markdown、JSON 报告

当前定位仍然是“单机开发版原型”。下一阶段应优先把任务执行、历史数据、模型适配和数据库迁移做扎实，再继续扩展高级审计能力。

## 2. 现有文档需要同步的内容

### 2.1 `update.md`

当前内容停留在 2026-06-10，需要新增一个版本章节，记录：

- 用户独立 LLM 平台、Base URL、模型和 API Key 配置
- `/auth/llm-config` 与 `/auth/llm-models/discover`
- 本地凭据加密密钥自动初始化
- 管理员停止任务接口
- 管理端删除“审计”按钮后的状态规则
- 最新测试结果

旧文档中“管理员可以启动审计”的描述应删除，管理端目前只保留查看和停止操作。

### 2.2 `README.md`

建议增加：

- LLM 平台配置操作截图和完整流程
- 各平台 Base URL 示例
- 模型探测失败的排查表
- 任务状态机说明
- 数据备份与恢复说明
- 生产部署配置清单

### 2.3 新增文档

建议继续编写：

- `docs/architecture.md`：组件、数据流、任务流和信任边界
- `docs/api.md`：接口、请求响应、状态码和权限矩阵
- `docs/task-lifecycle.md`：任务状态、重试、停止和异常恢复
- `docs/provider-adapters.md`：不同 LLM 平台的兼容差异
- `docs/deployment.md`：Nginx、MySQL、Redis、进程管理和备份
- `docs/troubleshooting.md`：启动、模型识别、扫描器和报告问题

## 3. P0：下一阶段优先开发

### 3.1 持久化任务队列

现状：任务通过进程内 `asyncio.create_task()` 执行，活动任务保存在 `_active_audits` 字典中。

升级目标：

- 使用 Redis + RQ、ARQ、Celery 或 Dramatiq 建立独立 Worker
- API 服务只负责提交任务，Worker 执行审计
- 停止命令写入 Redis，Worker 在每个节点检查取消标志
- 服务重启后恢复 `queued/running` 任务
- 支持并发数、超时、重试次数和优先级

验收标准：重启 API 服务后，运行中的任务状态和停止能力保持正常。

### 3.2 普通用户任务中心

现状：普通用户页面主要保存当前任务 ID，没有完整任务历史接口。

建议新增：

- `GET /audit/tasks`
- 按状态、时间、语言、风险等级搜索和分页
- 查看历史任务、继续查看实时日志、下载报告
- 删除任务和相关上传文件
- 失败任务重新执行
- 任务名称修改与备注

### 3.3 数据库迁移体系

现状：主要依赖 `create_all()` 和手写补列逻辑。

建议接入 Alembic：

- 为所有表建立版本迁移
- 为任务状态、用户 ID、创建时间建立组合索引
- 增加迁移前备份和迁移后校验
- SQLite、MySQL、PostgreSQL 分别验证

### 3.4 LLM Provider Adapter

现状：平台统一走 `/chat/completions`，请求字段仍存在平台差异。

建议建立统一适配器：

```text
ProviderAdapter
├── OpenAIAdapter
├── DeepSeekAdapter
├── OpenAICompatibleAdapter
├── AzureOpenAIAdapter
├── OllamaAdapter
└── CustomAdapter
```

每个适配器负责：

- 模型发现
- 请求字段转换
- JSON 输出能力判断
- reasoning/thinking 参数处理
- Token 限制和上下文长度
- 错误码翻译、重试和退避
- 连通性测试

### 3.5 上传资源限制

建议补充：

- 单文件大小、总上传大小和文件数量限制
- 解压后总大小和压缩比限制
- 最大目录深度
- 文件类型白名单和二进制文件过滤
- 用户磁盘配额
- 过期上传和报告定时清理

## 4. P1：产品能力升级

### 4.1 审计结果处置流程

为 Finding 增加：

- `new / confirmed / false_positive / fixed / accepted`
- 负责人、备注、处置时间
- 风险等级人工调整
- 批量处置
- 修复前后证据

### 4.2 增量审计与结果对比

- 基于 Git commit 只扫描变化文件
- 新增、消失、持续存在的漏洞对比
- 基线版本管理
- 修复复测
- 报告差异导出

### 4.3 调用链与数据流分析

- Controller 到 Service、DAO、Sink 的调用链
- Source、Sanitizer、Sink 标记
- 跨文件污点传播
- Java、Python、JavaScript 分语言实现
- 调用链图形化展示

### 4.4 成本与配额管理

- 每次任务记录请求次数、输入输出 Token 和耗时
- 用户日/月额度
- 单任务预算上限
- 超额自动终止
- 管理员成本看板

### 4.5 通知系统

- 站内通知
- 邮件、Webhook、企业微信或钉钉
- 审计完成、审计失败、高危漏洞、任务停止事件

## 5. P1：安全与运维加固

### 5.1 自定义 API Base URL 控制

模型发现和模型调用会访问用户填写的地址，建议增加：

- 域名/IP 策略
- DNS 解析后地址检查
- 私网地址访问开关
- 重定向目标复查
- 管理员平台白名单
- 请求审计日志

### 5.2 API Key 生命周期

- Key 最后验证时间
- Key 掩码指纹
- 连通性状态
- 主动轮换
- 旧密钥重新加密
- 加密密钥备份与恢复

### 5.3 登录会话管理

- Access Token + Refresh Token
- 会话列表和单设备退出
- 管理员强制下线
- Token 撤销和密码修改后失效
- 避免在报告下载和 WebSocket URL 中长期携带访问令牌

### 5.4 管理员操作审计日志

记录：

- 操作管理员
- 操作对象
- 操作类型
- 操作前后状态
- 时间、IP、User-Agent
- 停止任务原因

## 6. P2：高级审计能力

### 6.1 多 Agent 编排

- 路由提取 Agent
- 鉴权审计 Agent
- SQL/文件/命令/SSRF/反序列化专项 Agent
- 交叉验证 Agent
- 误报过滤 Agent
- 报告 Agent

### 6.2 项目知识库

- 代码切片和符号索引
- 函数、类、路由和依赖关系
- 向量检索与结构化检索组合
- 同项目历史审计记忆
- 只把相关上下文发送给模型

### 6.3 CI/CD 集成

- CLI 客户端
- GitHub Actions、GitLab CI、Jenkins 示例
- SARIF 输出
- 高危漏洞阻断规则
- Pull Request 注释

### 6.4 团队与组织

- Workspace、项目组和成员
- RBAC 权限
- 项目共享
- 团队 API Key 与个人 API Key 优先级
- 审批和复核流程

## 7. 测试体系升级

当前后端 27 项单元测试已通过。后续建议增加：

- LLM Provider 合同测试
- 模型发现各种响应格式测试
- API Key 加密、轮换和恢复测试
- 任务停止竞态测试
- 服务重启后的任务恢复测试
- 上传大小、数量、压缩比测试
- 管理员权限矩阵测试
- Playwright 前端端到端测试
- MySQL/PostgreSQL CI 测试矩阵

## 8. 推荐的三个开发迭代

### 迭代一：任务中心

1. 普通用户任务列表接口
2. 任务历史页面
3. 状态筛选、分页、重新执行
4. 任务清理和磁盘配额

### 迭代二：可靠任务执行

1. Redis 持久化队列
2. 独立 Worker
3. 分布式停止标志
4. 超时、重试、并发限制
5. 重启恢复测试

### 迭代三：模型适配层

1. Provider Adapter 接口
2. OpenAI、DeepSeek、自定义平台实现
3. 连通性和模型能力检测
4. Token/费用统计
5. Provider 合同测试

## 9. 推荐优先级结论

下一项最值得直接开写的是“普通用户任务中心 + 持久化任务队列”。它们决定项目能否从单次演示工具升级成持续使用的审计平台。之后再做 Provider Adapter 和增量审计，投入产出最高。
