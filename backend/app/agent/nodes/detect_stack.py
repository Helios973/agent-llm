from __future__ import annotations

import json
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.app.agent.nodes.helpers import append_log, publish_agent_state
from backend.app.agent.state import AuditState


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "vendor",
    "coverage",
}
LANGUAGE_SUFFIXES = {
    "python": {".py"},
    "typescript": {".ts", ".tsx"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "php": {".php"},
    "go": {".go"},
    "java": {".java"},
    "rust": {".rs"},
    "ruby": {".rb"},
    "csharp": {".cs"},
}
GENERIC_FRAMEWORKS = {
    "python",
    "nodejs",
    "php",
    "go",
    "java",
    "rust",
    "ruby",
    "csharp",
    "unknown",
}


@dataclass(frozen=True)
class StackDetection:
    language: str
    framework: str
    entrypoint: str
    score: int


class DetectionContext:
    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path
        self.files = sorted(self._iter_files(project_path), key=lambda path: self.relative(path))
        self.by_name: dict[str, list[Path]] = defaultdict(list)
        self.by_relative_lower: dict[str, Path] = {}
        self.text_cache: dict[Path, str] = {}
        self.suffix_counts: Counter[str] = Counter()

        for path in self.files:
            relative_path = self.relative(path)
            self.by_name[path.name.lower()].append(path)
            self.by_relative_lower[relative_path.lower()] = path
            self.suffix_counts[path.suffix.lower()] += 1

    def _iter_files(self, project_path: Path) -> list[Path]:
        paths: list[Path] = []
        for path in project_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            paths.append(path)
        return paths

    def relative(self, path: Path) -> str:
        return path.relative_to(self.project_path).as_posix()

    def read_text(self, path: Path) -> str:
        if path not in self.text_cache:
            try:
                self.text_cache[path] = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                self.text_cache[path] = ""
        return self.text_cache[path]

    def find_path(self, relative_path: str) -> Path | None:
        normalized = relative_path.replace("\\", "/").strip("/").lower()
        return self.by_relative_lower.get(normalized)

    def find_first_existing(self, candidates: list[str]) -> str:
        for candidate in candidates:
            path = self.find_path(candidate)
            if path is not None:
                return self.relative(path)
        return ""

    def find_first_named(self, names: list[str]) -> str:
        for name in names:
            matches = self.by_name.get(name.lower(), [])
            if matches:
                return self.relative(matches[0])
        return ""

    def files_for_language(self, language: str) -> list[Path]:
        suffixes = LANGUAGE_SUFFIXES.get(language, set())
        return [path for path in self.files if path.suffix.lower() in suffixes]

    def dominant_language(self) -> str:
        language_counts = {
            language: sum(self.suffix_counts.get(suffix, 0) for suffix in suffixes)
            for language, suffixes in LANGUAGE_SUFFIXES.items()
        }
        language_counts = {language: count for language, count in language_counts.items() if count}
        if not language_counts:
            return "unknown"
        return max(language_counts, key=lambda language: (language_counts[language], language))

    def find_file_containing(self, language: str, needles: list[str]) -> str:
        lowered_needles = [needle.lower() for needle in needles]
        for path in self.files_for_language(language):
            content = self.read_text(path).lower()
            if any(needle in content for needle in lowered_needles):
                return self.relative(path)
        return ""

    def find_file_with_line(self, language: str, needles: list[str]) -> str:
        lowered_needles = [needle.lower() for needle in needles]
        for path in self.files_for_language(language):
            for line in self.read_text(path).splitlines():
                lowered_line = line.lower()
                if any(needle in lowered_line for needle in lowered_needles):
                    return self.relative(path)
        return ""

    def first_language_file(self, language: str) -> str:
        files = self.files_for_language(language)
        return self.relative(files[0]) if files else ""

    def count_for_language(self, language: str) -> int:
        return len(self.files_for_language(language))


def _load_json(context: DetectionContext, relative_path: str) -> dict[str, Any]:
    path = context.find_path(relative_path)
    if path is None:
        return {}
    try:
        data = json.loads(context.read_text(path))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _load_toml(context: DetectionContext, relative_path: str) -> dict[str, Any]:
    path = context.find_path(relative_path)
    if path is None:
        return {}
    try:
        data = tomllib.loads(context.read_text(path))
    except tomllib.TOMLDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _framework_bonus(framework: str) -> int:
    return 15 if framework not in GENERIC_FRAMEWORKS else 0


def _build_detection(language: str, framework: str, entrypoint: str, base_score: int, file_count: int) -> StackDetection:
    return StackDetection(
        language=language,
        framework=framework,
        entrypoint=entrypoint,
        score=base_score + min(file_count, 20) + _framework_bonus(framework),
    )


def _flatten_package_dependencies(package_data: dict[str, Any]) -> set[str]:
    dependency_keys: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        payload = package_data.get(key, {})
        if isinstance(payload, dict):
            dependency_keys.update(str(item).lower() for item in payload.keys())
    return dependency_keys


def _detect_node_or_typescript(context: DetectionContext) -> StackDetection | None:
    package_path = context.find_path("package.json")
    js_count = context.count_for_language("javascript")
    ts_count = context.count_for_language("typescript")
    if package_path is None and js_count == 0 and ts_count == 0:
        return None

    package_data = _load_json(context, "package.json")
    dependency_keys = _flatten_package_dependencies(package_data)
    package_text = context.read_text(package_path).lower() if package_path is not None else ""

    framework = "nodejs"
    for dependency, framework_name in (
        ("next", "nextjs"),
        ("nuxt", "nuxt"),
        ("@nestjs/core", "nestjs"),
        ("express", "express"),
        ("koa", "koa"),
        ("fastify", "fastify"),
        ("react", "react"),
        ("vue", "vue"),
        ("@angular/core", "angular"),
        ("svelte", "svelte"),
        ("@remix-run/node", "remix"),
    ):
        if dependency in dependency_keys or dependency in package_text:
            framework = framework_name
            break

    language = "typescript" if ts_count > js_count or "typescript" in dependency_keys or context.find_path("tsconfig.json") else "javascript"
    entrypoint_candidates: list[str] = []

    main_field = package_data.get("main")
    if isinstance(main_field, str) and context.find_path(main_field):
        entrypoint_candidates.append(main_field)

    if framework == "nextjs":
        entrypoint_candidates.extend(["app/page.tsx", "app/page.jsx", "pages/index.tsx", "pages/index.jsx", "pages/index.ts", "pages/index.js"])
    elif framework == "nuxt":
        entrypoint_candidates.extend(["app.vue", "pages/index.vue", "server/api/index.ts", "server/api/index.js"])
    elif framework == "nestjs":
        entrypoint_candidates.extend(["src/main.ts", "src/main.js"])
    elif framework in {"react", "vue", "angular", "svelte", "remix"}:
        entrypoint_candidates.extend(["src/main.tsx", "src/main.jsx", "src/main.ts", "src/main.js", "src/App.tsx", "src/App.jsx"])
    else:
        entrypoint_candidates.extend(["server.ts", "server.js", "src/server.ts", "src/server.js", "index.ts", "index.js", "src/index.ts", "src/index.js", "app.ts", "app.js", "src/app.ts", "src/app.js"])

    entrypoint = context.find_first_existing(entrypoint_candidates)
    if not entrypoint:
        source_entrypoint = context.find_file_containing(
            language,
            ["express()", "fastify()", "new koa()", "nestfactory.create", "createapp(", "createroot(", "reactdom.render", "nextconfig", "defineNuxtConfig"],
        )
        entrypoint = source_entrypoint or ("package.json" if package_path is not None else context.first_language_file(language))

    base_score = 70 if package_path is not None else 35
    return _build_detection(language, framework, entrypoint, base_score, js_count + ts_count)


def _detect_python(context: DetectionContext) -> StackDetection | None:
    py_files = context.files_for_language("python")
    if not py_files:
        return None

    framework = "python"
    manifest_text = "\n".join(
        [
            context.read_text(path)
            for path in [
                context.find_path("pyproject.toml"),
                context.find_path("requirements.txt"),
                context.find_path("Pipfile"),
                context.find_path("setup.py"),
            ]
            if path is not None
        ]
    ).lower()

    for needles, framework_name in (
        (["fastapi", "from fastapi import", "fastapi("], "fastapi"),
        (["django", "manage.py", "from django", "django."], "django"),
        (["flask", "from flask import", "flask("], "flask"),
        (["starlette", "from starlette"], "starlette"),
        (["sanic", "from sanic import"], "sanic"),
        (["aiohttp", "from aiohttp import"], "aiohttp"),
        (["tornado", "from tornado"], "tornado"),
        (["bottle", "from bottle import"], "bottle"),
        (["pyramid", "from pyramid"], "pyramid"),
    ):
        if any(needle in manifest_text for needle in needles):
            framework = framework_name
            break
        source_hit = context.find_file_containing("python", needles)
        if source_hit:
            framework = framework_name
            break

    entrypoint_candidates = ["main.py", "app.py", "server.py", "run.py", "manage.py", "wsgi.py", "asgi.py", "src/main.py", "src/app.py"]
    if framework == "django":
        entrypoint_candidates = ["manage.py", "asgi.py", "wsgi.py"] + entrypoint_candidates

    entrypoint = context.find_first_existing(entrypoint_candidates)
    if not entrypoint:
        if framework == "fastapi":
            entrypoint = context.find_file_containing("python", ["fastapi(", "from fastapi import"])
        elif framework == "flask":
            entrypoint = context.find_file_containing("python", ["flask(", "from flask import"])
        elif framework == "django":
            entrypoint = context.find_file_containing("python", ["from django", "django."])

    if not entrypoint:
        entrypoint = context.find_file_containing("python", ["if __name__ == \"__main__\":", "if __name__ == '__main__':"])
    if not entrypoint:
        entrypoint = context.first_language_file("python")

    has_manifest = any(context.find_path(name) is not None for name in ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py"])
    base_score = 65 if has_manifest else 45
    return _build_detection("python", framework, entrypoint, base_score, len(py_files))


def _detect_php(context: DetectionContext) -> StackDetection | None:
    php_files = context.files_for_language("php")
    composer_path = context.find_path("composer.json")
    if composer_path is None and not php_files:
        return None

    composer_data = _load_json(context, "composer.json")
    require_keys: set[str] = set()
    for key in ("require", "require-dev"):
        payload = composer_data.get(key, {})
        if isinstance(payload, dict):
            require_keys.update(str(item).lower() for item in payload.keys())
    composer_text = context.read_text(composer_path).lower() if composer_path is not None else ""

    framework = "php"
    for needles, framework_name in (
        (["laravel/framework", "illuminate/"], "laravel"),
        (["symfony/framework-bundle", "symfony/"], "symfony"),
        (["codeigniter4/framework"], "codeigniter"),
        (["thinkphp/framework"], "thinkphp"),
        (["slim/slim"], "slim"),
        (["yiisoft/yii2", "yiisoft/yii2-app"], "yii2"),
    ):
        if any(needle in require_keys or needle in composer_text for needle in needles):
            framework = framework_name
            break

    entrypoint_candidates = ["public/index.php", "index.php", "artisan", "server.php", "bin/console"]
    if framework == "symfony":
        entrypoint_candidates = ["public/index.php", "bin/console"] + entrypoint_candidates
    entrypoint = context.find_first_existing(entrypoint_candidates) or context.first_language_file("php")

    base_score = 65 if composer_path is not None else 40
    return _build_detection("php", framework, entrypoint, base_score, len(php_files))


def _detect_go(context: DetectionContext) -> StackDetection | None:
    go_files = context.files_for_language("go")
    go_mod_path = context.find_path("go.mod")
    if go_mod_path is None and not go_files:
        return None

    go_mod_text = context.read_text(go_mod_path).lower() if go_mod_path is not None else ""
    framework = "go"
    for needle, framework_name in (
        ("github.com/gin-gonic/gin", "gin"),
        ("github.com/labstack/echo", "echo"),
        ("github.com/gofiber/fiber", "fiber"),
        ("github.com/go-chi/chi", "chi"),
        ("github.com/gorilla/mux", "gorilla"),
    ):
        if needle in go_mod_text or context.find_file_containing("go", [needle]):
            framework = framework_name
            break

    entrypoint = context.find_first_existing(["cmd/api/main.go", "cmd/server/main.go", "cmd/app/main.go", "main.go"])
    if not entrypoint:
        entrypoint = context.find_file_containing("go", ["func main()"])
    if not entrypoint:
        entrypoint = context.first_language_file("go")

    base_score = 65 if go_mod_path is not None else 40
    return _build_detection("go", framework, entrypoint, base_score, len(go_files))


def _detect_java(context: DetectionContext) -> StackDetection | None:
    java_files = context.files_for_language("java")
    build_file = context.find_first_existing(["pom.xml", "build.gradle", "build.gradle.kts"])
    if not build_file and not java_files:
        return None

    build_text = context.read_text(context.find_path(build_file)).lower() if build_file else ""
    framework = "java"
    for needles, framework_name in (
        (["spring-boot", "@springbootapplication", "springapplication.run"], "springboot"),
        (["quarkus"], "quarkus"),
        (["micronaut"], "micronaut"),
        (["struts"], "struts"),
    ):
        if any(needle in build_text for needle in needles):
            framework = framework_name
            break
        source_hit = context.find_file_containing("java", needles)
        if source_hit:
            framework = framework_name
            break

    entrypoint = context.find_file_containing("java", ["@springbootapplication", "public static void main", "springapplication.run"])
    if not entrypoint:
        entrypoint = context.find_first_named(["Application.java", "Main.java"])
    if not entrypoint:
        entrypoint = context.first_language_file("java")

    base_score = 65 if build_file else 40
    return _build_detection("java", framework, entrypoint, base_score, len(java_files))


def _detect_rust(context: DetectionContext) -> StackDetection | None:
    rust_files = context.files_for_language("rust")
    cargo_path = context.find_path("Cargo.toml")
    if cargo_path is None and not rust_files:
        return None

    cargo_data = _load_toml(context, "Cargo.toml")
    dependencies = cargo_data.get("dependencies", {})
    dependency_keys = {str(item).lower() for item in dependencies.keys()} if isinstance(dependencies, dict) else set()
    cargo_text = context.read_text(cargo_path).lower() if cargo_path is not None else ""

    framework = "rust"
    for needle, framework_name in (
        ("actix-web", "actix-web"),
        ("axum", "axum"),
        ("rocket", "rocket"),
        ("warp", "warp"),
    ):
        if needle in dependency_keys or needle in cargo_text:
            framework = framework_name
            break

    entrypoint = context.find_first_existing(["src/main.rs", "src/lib.rs"]) or context.first_language_file("rust")
    base_score = 65 if cargo_path is not None else 40
    return _build_detection("rust", framework, entrypoint, base_score, len(rust_files))


def _detect_ruby(context: DetectionContext) -> StackDetection | None:
    ruby_files = context.files_for_language("ruby")
    gemfile_path = context.find_path("Gemfile")
    if gemfile_path is None and not ruby_files:
        return None

    gemfile_text = context.read_text(gemfile_path).lower() if gemfile_path is not None else ""
    framework = "ruby"
    for needle, framework_name in (
        ("rails", "rails"),
        ("sinatra", "sinatra"),
        ("hanami", "hanami"),
    ):
        if needle in gemfile_text or context.find_file_containing("ruby", [needle]):
            framework = framework_name
            break

    entrypoint = context.find_first_existing(["config.ru", "bin/rails", "app.rb"]) or context.first_language_file("ruby")
    base_score = 60 if gemfile_path is not None else 35
    return _build_detection("ruby", framework, entrypoint, base_score, len(ruby_files))


def _detect_csharp(context: DetectionContext) -> StackDetection | None:
    cs_files = context.files_for_language("csharp")
    csproj = next((context.relative(path) for path in context.files if path.name.lower().endswith(".csproj")), "")
    if not csproj and not cs_files:
        return None

    framework = "csharp"
    csproj_text = context.read_text(context.find_path(csproj)).lower() if csproj else ""
    if "microsoft.aspnetcore" in csproj_text or context.find_file_containing("csharp", ["webapplication.createbuilder", "microsoft.aspnetcore"]):
        framework = "aspnetcore"

    entrypoint = context.find_first_existing(["Program.cs", "Startup.cs"]) or context.first_language_file("csharp")
    base_score = 60 if csproj else 35
    return _build_detection("csharp", framework, entrypoint, base_score, len(cs_files))


def _fallback_detection(context: DetectionContext) -> StackDetection:
    language = context.dominant_language()
    if language == "unknown":
        return StackDetection(language="unknown", framework="unknown", entrypoint="", score=0)

    framework = "nodejs" if language in {"javascript", "typescript"} else language
    entrypoint_candidates = {
        "javascript": ["index.js", "main.js", "app.js"],
        "typescript": ["index.ts", "main.ts", "app.ts", "src/main.ts"],
        "python": ["main.py", "app.py"],
        "php": ["public/index.php", "index.php"],
        "go": ["main.go"],
        "java": ["Application.java", "Main.java"],
        "rust": ["src/main.rs"],
        "ruby": ["app.rb"],
        "csharp": ["Program.cs"],
    }
    entrypoint = context.find_first_existing(entrypoint_candidates.get(language, [])) or context.first_language_file(language)
    return _build_detection(language, framework, entrypoint, 20, context.count_for_language(language))


def detect_stack(project_path: Path) -> tuple[str, str, str]:
    context = DetectionContext(project_path)
    candidates = [
        detector(context)
        for detector in (
            _detect_node_or_typescript,
            _detect_python,
            _detect_php,
            _detect_go,
            _detect_java,
            _detect_rust,
            _detect_ruby,
            _detect_csharp,
        )
    ]
    valid_candidates = [candidate for candidate in candidates if candidate is not None]
    if not valid_candidates:
        fallback = _fallback_detection(context)
        return fallback.language, fallback.framework, fallback.entrypoint

    best = max(
        valid_candidates,
        key=lambda item: (
            item.score,
            item.framework not in GENERIC_FRAMEWORKS,
            bool(item.entrypoint),
            item.language,
        ),
    )
    return best.language, best.framework, best.entrypoint


async def run(state: AuditState) -> dict[str, object]:
    await publish_agent_state(state["task_id"], "DetectStack", "running", "正在识别项目语言、框架和入口文件", 30)

    language, framework, entrypoint = detect_stack(Path(state["project_path"]))
    message = f"识别结果：语言={language}，框架={framework}，入口={entrypoint or '无'}"

    await publish_agent_state(state["task_id"], "DetectStack", "completed", message, 35)
    return {
        "language": language,
        "framework": framework,
        "entrypoint": entrypoint,
        "logs": append_log(state, message),
    }
