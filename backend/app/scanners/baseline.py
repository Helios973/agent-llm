from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from backend.app.scanners.utils import should_skip_text_scan


COMMON_SOURCE_TOKENS = (
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_FILES",
    "php://input",
    "request.args",
    "request.form",
    "request.values",
    "request.get_json(",
    "request.json",
    "req.query",
    "req.body",
    "req.params",
    "ctx.query",
    "ctx.request.body",
    "input(",
    "argv[",
    "location.search",
    "location.hash",
    "document.cookie",
    "window.name",
    "localstorage",
    "sessionstorage",
)

URL_SOURCE_TOKENS = COMMON_SOURCE_TOKENS + (
    "url",
    "uri",
    "target",
    "endpoint",
    "next",
    "redirect",
)

PATH_SOURCE_TOKENS = COMMON_SOURCE_TOKENS + (
    "path",
    "filepath",
    "filename",
    "file",
    "page",
    "template",
    "download",
    "../",
)


@dataclass(frozen=True)
class BaselineRule:
    rule_id: str
    title: str
    description: str
    severity: str
    sink_tokens: tuple[str, ...]
    source_tokens: tuple[str, ...] = ()
    required_context_tokens: tuple[str, ...] = ()
    sanitizer_tokens: tuple[str, ...] = ()
    path_tokens: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()
    window_radius: int = 2


RULES = (
    BaselineRule(
        rule_id="php-unserialize",
        title="Unsafe PHP Deserialization",
        description="检测到 PHP `unserialize` 反序列化入口，若处理不可信输入，可能触发对象注入或代码执行。",
        severity="HIGH",
        sink_tokens=("unserialize(",),
        suffixes=(".php",),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="xss-php-output",
        title="Potential Cross-Site Scripting (XSS)",
        description="检测到 PHP 直接输出外部输入，若未做 HTML 编码或模板转义，可能形成反射型或存储型 XSS。",
        severity="HIGH",
        sink_tokens=("echo", "print", "<?="),
        source_tokens=("$__invalid__",),  # placeholder replaced in matcher
        sanitizer_tokens=("htmlspecialchars", "htmlentities", "strip_tags", "twig_escape_filter"),
        suffixes=(".php",),
        window_radius=0,
    ),
    BaselineRule(
        rule_id="xss-dom",
        title="Potential Cross-Site Scripting (XSS)",
        description="检测到前端将不可信内容写入 HTML 解析型 DOM sink，可能形成 DOM XSS。",
        severity="HIGH",
        sink_tokens=("innerhtml =", "outerhtml =", "document.write(",),
        source_tokens=("location.search", "location.hash", "document.cookie", "window.name", "localstorage", "sessionstorage"),
        sanitizer_tokens=("dompurify.sanitize", ".textcontent", "innertext", "escapehtml", "sanitizehtml"),
        suffixes=(".js", ".jsx", ".ts", ".tsx", ".html", ".vue"),
        window_radius=1,
    ),
    BaselineRule(
        rule_id="xss-framework-html",
        title="Potential Cross-Site Scripting (XSS)",
        description="检测到显式启用原始 HTML 渲染能力，若渲染内容可被用户控制，容易形成 XSS。",
        severity="MEDIUM",
        sink_tokens=("dangerouslysetinnerhtml", "v-html"),
        sanitizer_tokens=("dompurify.sanitize", "sanitizehtml"),
        suffixes=(".js", ".jsx", ".ts", ".tsx", ".html", ".vue"),
        window_radius=1,
    ),
    BaselineRule(
        rule_id="sql-injection",
        title="Potential SQL Injection",
        description="检测到 SQL 执行 sink 附近存在外部输入，若未使用参数化查询，可能形成 SQL 注入。",
        severity="HIGH",
        sink_tokens=("mysqli_query(", "mysql_query(", "->query(", "->exec(", ".execute(", "connection.query(", "db.query("),
        source_tokens=COMMON_SOURCE_TOKENS,
        required_context_tokens=("select ", "insert ", "update ", "delete ", "sql", "query"),
        suffixes=(".php", ".py", ".js", ".ts", ".java", ".go"),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="mybatis-xml-sql-injection",
        title="Potential SQL Injection",
        description="检测到 MyBatis XML 中使用 `${...}` 拼接 SQL 片段，若参数可被外部控制，可能形成 SQL 注入。",
        severity="HIGH",
        sink_tokens=("${",),
        required_context_tokens=("<select", "<update", "<delete", "<insert", "select ", "update ", "delete ", "insert ", " from ", " where ", " order by "),
        path_tokens=("mapper",),
        suffixes=(".xml",),
        window_radius=6,
    ),
    BaselineRule(
        rule_id="command-injection",
        title="Potential Command Injection",
        description="检测到命令执行 sink，若参数受外部输入影响，可能触发系统命令注入。",
        severity="HIGH",
        sink_tokens=(
            "system(",
            "exec(",
            "shell_exec(",
            "passthru(",
            "popen(",
            "proc_open(",
            "os.system(",
            "subprocess.run(",
            "subprocess.popen(",
            "child_process.exec(",
            "runtime.getruntime().exec(",
        ),
        source_tokens=COMMON_SOURCE_TOKENS,
        suffixes=(".php", ".py", ".js", ".ts", ".java"),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="ssrf",
        title="Potential SSRF",
        description="检测到服务端发起外部请求的 sink 附近存在可控 URL 或目标参数，可能形成 SSRF。",
        severity="HIGH",
        sink_tokens=("requests.get(", "requests.post(", "requests.request(", "httpx.get(", "httpx.post(", "curl_init(", "axios.get(", "axios.post(", "fetch("),
        source_tokens=URL_SOURCE_TOKENS,
        required_context_tokens=("url", "uri", "endpoint", "target", "fetch", "http"),
        suffixes=(".php", ".py", ".js", ".ts"),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="path-traversal",
        title="Potential Path Traversal / File Inclusion",
        description="检测到文件读取、下载或包含 sink 附近存在可控路径，可能导致目录穿越、本地文件包含或任意文件读取。",
        severity="HIGH",
        sink_tokens=("include(", "include_once(", "require(", "require_once(", "file_get_contents(", "readfile(", "fopen(", "open(", "send_file(", "fs.readfile(", "fileutils.writebytes(", "files.copy(", "readallbytes(", "new fileinputstream("),
        source_tokens=PATH_SOURCE_TOKENS,
        required_context_tokens=("path", "file", "page", "template", "download", "filepath", "filename", "downloadpath", "../"),
        suffixes=(".php", ".py", ".js", ".ts", ".java"),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="open-redirect",
        title="Potential Open Redirect",
        description="检测到跳转 sink 附近存在外部可控目标地址，可能导致开放重定向或钓鱼跳转。",
        severity="MEDIUM",
        sink_tokens=("header(\"location:", "header('location:", "res.redirect(", "redirect(", "window.location =", "location.href ="),
        source_tokens=URL_SOURCE_TOKENS,
        required_context_tokens=("url", "next", "redirect", "returnto", "callback"),
        suffixes=(".php", ".py", ".js", ".ts"),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="xxe",
        title="Potential XXE",
        description="检测到 XML 解析 sink，若处理外部可控 XML 且未禁用外部实体，可能形成 XXE、SSRF 或文件读取。",
        severity="HIGH",
        sink_tokens=("simplexml_load_string(", "simplexml_load_file(", "domdocument->loadxml(", "domdocument->load(", "xmlreader::xml(", "lxml.etree.fromstring(", "lxml.etree.parse(", "documentbuilderfactory.newinstance("),
        suffixes=(".php", ".py", ".java"),
        window_radius=1,
    ),
    BaselineRule(
        rule_id="ssti",
        title="Potential Server-Side Template Injection",
        description="检测到服务端模板动态渲染 sink，若模板内容或片段来自外部输入，可能触发模板注入。",
        severity="HIGH",
        sink_tokens=("render_template_string(", "jinja2.template(", "template("),
        source_tokens=COMMON_SOURCE_TOKENS,
        required_context_tokens=("template", "render", "html"),
        suffixes=(".py", ".php", ".js", ".ts"),
        window_radius=2,
    ),
    BaselineRule(
        rule_id="eval-injection",
        title="Potential Code Injection via Eval",
        description="检测到动态求值或解释执行 sink，若内容可由外部输入控制，可能直接触发代码执行。",
        severity="HIGH",
        sink_tokens=("eval(", "assert(", "new function(",),
        source_tokens=COMMON_SOURCE_TOKENS,
        suffixes=(".php", ".py", ".js", ".ts"),
        window_radius=2,
    ),
)

PHP_DIRECT_XSS_SOURCES = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER")


def _applies_to_file(rule: BaselineRule, file_path: Path) -> bool:
    return not rule.suffixes or file_path.suffix.lower() in rule.suffixes


def _window_text(lines: list[str], index: int, radius: int) -> str:
    start = max(index - radius, 0)
    end = min(index + radius + 1, len(lines))
    return "\n".join(lines[start:end]).lower()


def _token_present(text: str, token: str) -> bool:
    normalized = token.lower()
    if any(char for char in normalized if not (char.isalnum() or char == "_")):
        return normalized in text
    return re.search(rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])", text) is not None


def _contains_any_token(text: str, tokens: tuple[str, ...]) -> bool:
    return any(_token_present(text, token) for token in tokens)


def _path_contains_any_token(path: str, tokens: tuple[str, ...]) -> bool:
    lowered_path = path.lower()
    return any(token.lower() in lowered_path for token in tokens)


def _build_finding(
    *,
    rule: BaselineRule,
    relative_path: str,
    line_number: int,
    evidence: str,
    sink_token: str,
) -> dict[str, object]:
    return {
        "source": "BaselineHeuristic",
        "severity": rule.severity,
        "title": rule.title,
        "description": rule.description,
        "file_path": relative_path,
        "line_number": line_number,
        "cvss_score": 0.0,
        "metadata": {
            "needle": sink_token,
            "rule_id": rule.rule_id,
            "scanner": "baseline",
        },
    }


def _php_direct_xss_match(line: str) -> bool:
    lowered_line = line.lower()
    if not any(token in lowered_line for token in ("echo", "print", "<?=")):
        return False
    return any(source.lower() in lowered_line for source in PHP_DIRECT_XSS_SOURCES)


def run(project_path: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []

    for file_path in project_path.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if should_skip_text_scan(file_path, content):
            continue

        lines = content.splitlines()
        lowered_lines = [line.lower() for line in lines]
        relative_path = file_path.relative_to(project_path).as_posix()

        for index, line in enumerate(lines, start=1):
            lowered_line = lowered_lines[index - 1]

            for rule in RULES:
                if not _applies_to_file(rule, file_path):
                    continue
                if rule.path_tokens and not _path_contains_any_token(relative_path, rule.path_tokens):
                    continue

                matched_sink = next((token for token in rule.sink_tokens if token.lower() in lowered_line), None)
                if matched_sink is None:
                    continue

                if rule.rule_id == "xss-php-output" and not _php_direct_xss_match(line):
                    continue

                window = _window_text(lines, index - 1, rule.window_radius)
                if rule.rule_id == "xss-php-output":
                    if _contains_any_token(window, rule.sanitizer_tokens):
                        continue
                else:
                    if rule.source_tokens and not _contains_any_token(window, rule.source_tokens):
                        continue
                    if rule.required_context_tokens and not _contains_any_token(window, rule.required_context_tokens):
                        continue
                    if rule.sanitizer_tokens and _contains_any_token(window, rule.sanitizer_tokens):
                        continue

                results.append(
                    _build_finding(
                        rule=rule,
                        relative_path=relative_path,
                        line_number=index,
                        evidence=line.strip(),
                        sink_token=matched_sink,
                    )
                )

    return results
