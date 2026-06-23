# AuditPilot 安全审查与修复说明

更新时间：2026-06-16

## 1. 文档目的

本文档将本次项目安全审查结果、漏洞修复方案、实际代码修改内容与验证结果合并到同一个文件中，便于留档、汇报与后续复核。

## 2. 审查范围

本次审查重点覆盖以下高风险链路：

- 用户注册与登录认证
- 启动初始化与管理员引导逻辑
- 上传压缩包解压与项目提取流程
- 前端滑块人机校验与后端注册接口闭环

## 3. 审查结论总览

本次共确认 3 个有效安全问题，均已完成修复：

| 编号 | 漏洞名称 | 漏洞类型 | 风险等级 | 状态 |
| --- | --- | --- | --- | --- |
| V-01 | 默认认证密钥与默认管理员口令风险 | 身份认证失效 / 安全配置错误 | 高危 | 已修复 |
| V-02 | 恶意压缩包解压目录穿越 | 路径穿越 / 任意文件写入 | 高危 | 已修复 |
| V-03 | 前端滑块校验可被直接绕过 | 业务逻辑绕过 / 人机校验缺失 | 中危 | 已修复 |

## 4. 漏洞明细与修复说明

### V-01 默认认证密钥与默认管理员口令风险

- 漏洞类型：
  - OWASP A07:2021 身份认证失效
  - OWASP A05:2021 安全配置错误
  - CWE-287 Improper Authentication
  - CWE-798 Use of Hard-coded Credentials
- 风险等级：高危
- 影响位置：
  - `backend/app/core/config.py`
  - `backend/app/core/database.py`
  - `backend/app/services/auth_service.py`
- 问题描述：
  - 系统原先内置固定认证签名密钥 `change-me-local-auth-secret`
  - 系统原先内置固定管理员账号初始化信息
  - 启动时会自动创建或提权管理员账号
- 安全影响：
  - 在未修改默认配置的场景下，攻击者可预测签名密钥并伪造访问令牌
  - 攻击者可利用默认管理员口令直接接管后台管理员账号
- 修复方案：
  - 将默认 `AUTH_SECRET_KEY` 改为必须显式配置
  - 当未配置或使用占位值时，回退为进程级随机密钥，避免固定密钥被复用
  - 将管理员引导账号改为默认关闭
  - 仅在显式配置用户名、邮箱、强口令且口令不是占位值时，才允许初始化管理员
- 实际修改：
  - `backend/app/core/config.py`
    - 新增不安全占位密钥和占位口令识别
    - 新增 `resolved_auth_secret_key`
    - 新增 `bootstrap_admin_credentials`
  - `backend/app/core/database.py`
    - `_ensure_bootstrap_admin()` 改为仅在安全配置存在时执行
  - `backend/app/services/auth_service.py`
    - token 签名改为优先使用安全配置，否则使用进程内随机密钥
- 修复结果：
  - 默认配置下不再存在可预测签名密钥
  - 默认配置下不再自动生成可预测管理员账号

### V-02 恶意压缩包解压目录穿越

- 漏洞类型：
  - OWASP A01:2021 访问控制失效
  - CWE-22 Path Traversal
  - CWE-73 External Control of File Name or Path
- 风险等级：高危
- 影响位置：
  - `backend/app/services/files.py`
- 问题描述：
  - 原实现使用通用解压逻辑直接处理用户上传压缩包
  - 对压缩包内部文件名未进行路径安全校验
  - 恶意 `.tar` 可利用 `../` 条目写出到目标目录之外
- 安全影响：
  - 攻击者可通过构造恶意压缩包覆盖项目目录外文件
  - 在特定部署场景中，可能进一步导致配置污染、持久化植入或服务破坏
- 修复方案：
  - 替换为受控解压流程
  - 对每个压缩包成员路径执行安全校验
  - 拦截以下非法条目：
    - 绝对路径
    - `../` 路径穿越
    - 盘符路径
    - 符号链接
    - 特殊设备条目
- 实际修改：
  - `backend/app/services/files.py`
    - 新增 `_archive_member_destination()`
    - 新增 `_extract_zip_archive()`
    - 新增 `_extract_tar_archive()`
    - 新增 `_extract_archive()`
    - `extract_project()` 改为走安全解压逻辑
- 修复结果：
  - 恶意 tar/zip 条目无法再跳出项目目录
  - 解压行为已限制在任务项目目录内部

### V-03 前端滑块校验可被直接绕过

- 漏洞类型：
  - OWASP A04:2021 不安全设计
  - OWASP A01:2021 访问控制失效
  - CWE-602 Client-Side Enforcement of Server-Side Security
- 风险等级：中危
- 影响位置：
  - `frontend/assets/app.js`
  - `backend/app/api/routes/auth.py`
  - `backend/app/schemas/auth.py`
  - `backend/app/services/human_check.py`
- 问题描述：
  - 原滑块验证仅在前端页面内控制按钮可用状态
  - 后端注册接口未校验任何服务端签发的人机验证凭证
  - 攻击者可以跳过页面，直接调用 `/auth/register`
- 安全影响：
  - 可批量绕过“真人校验”限制
  - 会削弱注册风控能力，增加脚本注册和滥用风险
- 修复方案：
  - 新增服务端 challenge/proof 双阶段校验
  - challenge 由后端签发并带过期时间
  - proof 由 challenge 换取，且为一次性令牌
  - 注册接口强制校验 `human_check_proof`
  - 前端滑块通过后，不再只改本地状态，而是必须向后端换取 proof
- 实际修改：
  - `backend/app/services/human_check.py`
    - 新增人机校验签发、核验、一次性消费逻辑
  - `backend/app/api/routes/auth.py`
    - 新增 `/auth/human-check/challenge`
    - 新增 `/auth/human-check/verify`
    - 注册接口新增 proof 消费校验
  - `backend/app/schemas/auth.py`
    - `RegisterRequest` 新增 `human_check_proof`
    - 新增 challenge/proof 请求与响应模型
  - `frontend/assets/app.js`
    - 滑块成功后改为调用后端换取 proof
    - 注册提交时附带 `human_check_proof`
    - 增加失败重试、重置、challenge 未就绪时的交互保护
- 修复结果：
  - 直接调用注册接口将无法绕过人机校验
  - proof 为一次性令牌，复用会失败

## 5. 修改文件清单

本次与安全修复直接相关的文件如下：

| 文件路径 | 修改用途 |
| --- | --- |
| `backend/app/core/config.py` | 安全配置收口，禁用默认高风险认证配置 |
| `backend/app/core/database.py` | 限制管理员引导逻辑 |
| `backend/app/services/auth_service.py` | 修复 token 签名密钥使用逻辑 |
| `backend/app/services/files.py` | 修复压缩包安全解压 |
| `backend/app/services/human_check.py` | 新增服务端人机校验模块 |
| `backend/app/api/routes/auth.py` | 注册接口接入服务端人机校验 |
| `backend/app/schemas/auth.py` | 新增注册 proof 与 challenge/proof 数据模型 |
| `frontend/assets/app.js` | 前端滑块改为服务端闭环校验 |
| `scripts/smoke_test.py` | 兼容新的人机校验注册流程 |
| `.env.example` | 更新安全配置示例 |
| `README.md` | 更新安全配置与使用说明 |
| `backend/tests/test_security_hardening.py` | 新增安全回归测试 |

## 6. 验证与测试结果

已执行验证：

### 单元测试

```bash
python -m unittest backend.tests.test_security_hardening
python -m unittest discover backend/tests
```

结果：

- 新增安全回归测试通过
- 后端测试集共 27 项，全部通过

### 端到端验证

```bash
python dev.py restart
python scripts/smoke_test.py
```

结果：

- 开发栈重启成功
- 注册、上传、启动审计、生成报告全链路验证通过
- 修复未破坏主业务流程

## 7. 当前修复后的安全状态

本次已完成以下安全收口：

- 默认部署不再暴露固定签名密钥
- 默认部署不再自动创建可预测管理员账号
- 上传压缩包无法再通过目录穿越写出到项目目录之外
- 注册滑块已从“纯前端限制”升级为“服务端一次性令牌校验”

## 8. 后续加固建议

虽然本次核心问题已修复，但如果项目后续需要公网部署，建议继续补强以下能力：

- 为注册和登录接口增加频率限制
- 增加 IP、设备指纹或行为层风控
- 在公网场景下接入成熟的人机验证服务，例如 Turnstile 或 hCaptcha
- 为管理员操作增加审计日志与告警
- 将 `AUTH_SECRET_KEY` 配置为高强度随机值，避免重启后本地登录态失效

## 9. 文档结论

本次审查确认的 3 个有效安全问题均已完成修复，并已通过单元测试与端到端流程验证。当前版本相较修复前，在认证安全、上传解压安全与注册风控闭环方面均有明显提升。
