# AuditPilot - 基于 LangGraph 的智能代码审计平台

## 1. 项目简介

### 1.1 项目名称

**AuditPilot**

### 1.2 项目定位

AuditPilot 是一套基于 LangGraph 的智能代码审计平台。

系统支持上传源码、压缩包、Git 仓库以及容器镜像，通过多 Agent 协作完成代码安全分析、依赖漏洞检测、敏感信息发现、业务逻辑漏洞分析以及审计报告生成。

---

## 2. 核心能力

### 代码审计

* 静态代码分析（SAST）
* AI 智能审计
* 依赖漏洞分析
* 敏感信息检测
* 安全配置检查

### 文件支持

* ZIP
* TAR.GZ
* Python
* Java
* Go
* PHP
* JavaScript
* TypeScript
* Rust

### Git 集成

* GitHub Repository
* GitLab Repository
* Gitee Repository

### 报告生成

* Markdown
* HTML
* PDF
* JSON

---

# 3. 技术架构

```text
┌─────────────────────┐
│      Frontend       │
│      Next.js        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│      FastAPI        │
│      Gateway        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     LangGraph       │
│   Workflow Engine   │
└──────────┬──────────┘
           │
           ▼
 ┌───────────────────┐
 │  File Agent       │
 ├───────────────────┤
 │  Scan Agent       │
 ├───────────────────┤
 │  LLM Agent        │
 ├───────────────────┤
 │  Verify Agent     │
 ├───────────────────┤
 │  Report Agent     │
 └───────────────────┘
           │
           ▼
┌─────────────────────┐
│ Docker Sandbox      │
└─────────────────────┘
           │
           ▼
┌─────────────────────┐
│ PostgreSQL          │
│ Redis               │
│ MinIO               │
└─────────────────────┘
```

---

# 4. 技术选型

## 前端

| 模块        | 技术            |
| --------- | ------------- |
| Framework | Next.js 15    |
| UI        | Shadcn UI     |
| CSS       | TailwindCSS   |
| 状态管理      | Zustand       |
| 请求管理      | React Query   |
| 编辑器       | Monaco Editor |
| 流程图       | ReactFlow     |

## 后端

| 模块        | 技术                |
| --------- | ----------------- |
| API       | FastAPI           |
| ORM       | SQLAlchemy        |
| 数据验证      | Pydantic          |
| 数据迁移      | Alembic           |
| WebSocket | FastAPI WebSocket |

## Agent

| 模块              | 技术        |
| --------------- | --------- |
| Agent Workflow  | LangGraph |
| Agent Framework | LangChain |
| Observability   | LangSmith |

## 存储

| 模块           | 技术  |
| -------------- | ----- |
| Database       | mysql |
| Cache          | Redis |
| Object Storage | MinIO |

## 容器

| 模块      | 技术                  |
| ------- | ------------------- |
| Runtime | Docker              |
| SDK     | Docker SDK          |
| Sandbox | Container Isolation |

---

# 5. 系统目录结构

```text
auditpilot/

├── frontend/
│
├── backend/
│
├── docker/
│
├── docs/
│
├── scripts/
│
└── deployments/
```

详细结构：

```text
backend/

├── api/
│   ├── upload.py
│   ├── audit.py
│   ├── report.py
│
├── agent/
│   ├── graph.py
│   ├── state.py
│   │
│   └── nodes/
│       ├── extract.py
│       ├── detect_stack.py
│       ├── create_container.py
│       ├── static_scan.py
│       ├── llm_review.py
│       ├── risk_validate.py
│       └── report.py
│
├── scanners/
│   ├── semgrep.py
│   ├── bandit.py
│   ├── gitleaks.py
│   └── trivy.py
│
├── sandbox/
│   ├── docker_runner.py
│   └── security_policy.py
│
└── storage/
    ├── postgres.py
    ├── redis.py
    └── minio.py
```

---

# 6. LangGraph 工作流设计

## Agent Workflow

```text
START

↓

UploadFile

↓

ExtractProject

↓

DetectStack

↓

CreateSandbox

↓

StaticScan

↓

LLMReview

↓

RiskValidate

↓

GenerateReport

↓

END
```

---

## State 设计

```python
from typing import TypedDict

class AuditState(TypedDict):
    task_id: str
    user_id: str

    file_path: str
    project_path: str

    language: str
    framework: str

    scan_results: list
    llm_results: list

    findings: list

    report_path: str

    status: str

    logs: list
```

---

# 7. Agent 设计

## File Agent

### 职责

解析项目结构

识别：

* 编程语言
* 框架
* 配置文件
* 项目入口

### 输出

```json
{
  "language": "python",
  "framework": "django",
  "entry": "manage.py"
}
```

---

## Static Scan Agent

### 工具

* Semgrep
* Bandit
* Trivy
* Gitleaks

### 输出

```json
{
  "severity": "HIGH",
  "rule": "SQL Injection",
  "file": "views.py",
  "line": 123
}
```

---

## LLM Review Agent

### 检测能力

* SQL注入
* SSRF
* XXE
* RCE
* 命令执行
* 权限绕过
* 越权访问
* 认证逻辑缺陷
* 业务逻辑漏洞

### 输出

```json
{
  "risk": "HIGH",
  "title": "SQL Injection",
  "description": "用户输入未经过滤直接拼接SQL语句"
}
```

---

## Risk Validation Agent

### 职责

合并：

* Semgrep
* Bandit
* Trivy
* LLM结果

执行：

* 去重
* 风险评级
* CVSS计算

---

## Report Agent

生成：

* Markdown
* HTML
* PDF
* JSON

---

# 8. 容器沙箱设计

## 生命周期

```text
创建容器

↓

挂载项目

↓

执行扫描

↓

收集结果

↓

销毁容器
```

---

## 安全策略

```python
docker.containers.run(
    image="audit-sandbox",
    network_disabled=True,
    read_only=True,
    mem_limit="1g",
    cpu_quota=50000,
    pids_limit=256,
    security_opt=["no-new-privileges"],
    cap_drop=["ALL"]
)
```

---

# 9. 数据库设计

## users

```sql
CREATE TABLE users(
    id UUID PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(255),
    created_at TIMESTAMP
);
```

---

## audit_tasks

```sql
CREATE TABLE audit_tasks(
    id UUID PRIMARY KEY,
    user_id UUID,
    task_name VARCHAR(255),
    status VARCHAR(50),
    language VARCHAR(50),
    framework VARCHAR(50),
    created_at TIMESTAMP
);
```

---

## findings

```sql
CREATE TABLE findings(
    id UUID PRIMARY KEY,
    task_id UUID,
    severity VARCHAR(20),
    title VARCHAR(255),
    description TEXT,
    file_path TEXT,
    line_number INT
);
```

---

# 10. API 设计

## 上传代码

```http
POST /api/v1/upload
```

请求：

```multipart
file=project.zip
```

响应：

```json
{
  "task_id":"xxx"
}
```

---

## 创建审计任务

```http
POST /api/v1/audit/start
```

响应：

```json
{
  "status":"running"
}
```

---

## 获取审计结果

```http
GET /api/v1/audit/{task_id}
```

---

## 下载报告

```http
GET /api/v1/report/{task_id}
```

---

# 11. WebSocket 实时日志

连接：

```text
/ws/audit/{task_id}
```

日志：

```json
{
  "event":"log",
  "message":"Semgrep Scan Started"
}
```

Agent状态：

```json
{
  "event":"agent",
  "agent":"LLMReview",
  "status":"running"
}
```

进度：

```json
{
  "event":"progress",
  "value":75
}
```

---

# 12. 前端页面设计

## Dashboard

显示：

* 总任务数
* 高危漏洞
* 中危漏洞
* 低危漏洞

---

## New Audit

功能：

* 上传源码
* 配置扫描规则
* 选择模型
* 启动任务

---

## Audit Detail

显示：

* 实时日志
* Agent执行状态
* 风险统计
* 漏洞列表

---

## Reports

支持：

* PDF下载
* HTML预览
* Markdown导出

---

## Settings

配置：

* 模型
* API Key
* 扫描规则
* 用户权限

---

# 13. Docker Compose

```yaml
services:

  frontend:

  backend:

  postgres:

  redis:

  minio:

  sandbox:
```

---

# 14. 部署架构

```text
Internet

↓

Nginx

↓

Frontend

↓

FastAPI

↓

LangGraph

↓

Docker Sandbox

↓

PostgreSQL
Redis
MinIO
```

---

# 15. 后续规划

## V2

* GitHub 集成
* GitLab 集成
* Jira 集成
* LDAP 登录
* 企业 SSO

## V3

* 多Agent协作
* 自动修复代码
* 漏洞复现
* PoC生成
* CI/CD集成
* DevSecOps流水线

## V4

* MCP工具生态
* 企业知识库
* RAG增强审计
* 私有模型部署
* 安全运营中心联动
* SIEM联动
* 自动告警系统
