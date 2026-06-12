from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
FRONTEND_ROOT = ROOT / "frontend"
STATE_FILE = ROOT / "scripts" / "dev-processes.json"
RUNTIME_DIR = ROOT / "backend" / "data" / "runtime"
BACKEND_OUT = RUNTIME_DIR / "backend.out.log"
BACKEND_ERR = RUNTIME_DIR / "backend.err.log"
FRONTEND_OUT = RUNTIME_DIR / "frontend.out.log"
FRONTEND_ERR = RUNTIME_DIR / "frontend.err.log"
RUNTIME_CONFIG = FRONTEND_ROOT / "assets" / "runtime-config.js"


def has_value(value: str | None) -> bool:
    return value is not None and value.strip() != ""


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        values[key] = value
        os.environ.setdefault(key, value)

    return values


def env_value(name: str, default: str = "") -> str:
    value = os.environ.get(name, "")
    return value if has_value(value) else default


def env_int(name: str, default: int) -> int:
    value = env_value(name)
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a positive integer, got {value!r}.") from exc
    if parsed <= 0:
        raise SystemExit(f"{name} must be a positive integer, got {value!r}.")
    return parsed


def normalize_path(value: str, default: str) -> str:
    path = value.strip() or default
    if not path.startswith("/"):
        path = f"/{path}"
    return path.rstrip("/") if len(path) > 1 else path


def client_host(host: str) -> str:
    return "127.0.0.1" if host in {"0.0.0.0", "::", "[::]"} else host


def join_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def python_executable(venv_root: Path) -> Path:
    if platform.system() == "Windows":
        return venv_root / "Scripts" / "python.exe"
    return venv_root / "bin" / "python"


def is_runnable_python(candidate: Path | str) -> bool:
    try:
        result = subprocess.run(
            [str(candidate), "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, ValueError):
        return False
    return result.returncode == 0


def find_base_python(explicit: str = "") -> str:
    if has_value(explicit):
        if is_runnable_python(explicit):
            return explicit
        raise SystemExit(f"Configured Python is not runnable: {explicit}")

    for candidate in [sys.executable, shutil.which("python3"), shutil.which("python"), shutil.which("py")]:
        if candidate and is_runnable_python(candidate):
            return str(candidate)

    raise SystemExit("No runnable Python was found. Set PYTHON_EXECUTABLE in .env.")


def managed_python(explicit: str = "") -> Path:
    candidate = python_executable(ROOT / ".venv")
    if is_runnable_python(candidate):
        return candidate

    target_root = ROOT / ".venv"
    base_python = find_base_python(explicit)
    print(f"Creating virtual environment: {target_root}")
    subprocess.run([base_python, "-m", "venv", str(target_root)], cwd=ROOT, check=True)

    candidate = python_executable(target_root)
    if not is_runnable_python(candidate):
        raise SystemExit(f"Virtual environment Python is not runnable: {candidate}")
    return candidate


def dependencies_ready(python: Path) -> bool:
    result = subprocess.run(
        [str(python), "-c", "import fastapi, httpx, uvicorn"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def ensure_dependencies(python: Path) -> None:
    if dependencies_ready(python):
        return

    requirements = ROOT / "requirements.txt"
    if not requirements.exists():
        raise SystemExit(f"Requirements file not found: {requirements}")

    print("Installing Python dependencies from requirements.txt...")
    pip_check = subprocess.run([str(python), "-m", "pip", "--version"], check=False)
    if pip_check.returncode != 0:
        subprocess.run([str(python), "-m", "ensurepip", "--upgrade"], check=True)
    subprocess.run([str(python), "-m", "pip", "install", "-r", str(requirements)], cwd=ROOT, check=True)


def assert_port_free(host: str, port: int, name: str) -> None:
    probe_host = client_host(host)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((probe_host, port))
        except OSError as exc:
            raise SystemExit(f"{name} port {port} is already in use.") from exc


def process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if platform.system() == "Windows":
        process_query_limited_information = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False

    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def stop_process_tree(pid: int) -> None:
    if pid <= 0:
        return

    if platform.system() == "Windows":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return

    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return

    deadline = time.time() + 5
    while time.time() < deadline and process_running(pid):
        time.sleep(0.1)
    if process_running(pid):
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass


def read_state() -> dict[str, object] | None:
    if not STATE_FILE.exists():
        return None
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def build_config(args: argparse.Namespace) -> dict[str, object]:
    backend_host = args.backend_host or env_value("BACKEND_HOST", "127.0.0.1")
    frontend_host = args.frontend_host or env_value("FRONTEND_HOST", "127.0.0.1")
    backend_port = args.backend_port or env_int("BACKEND_PORT", 8000)
    frontend_port = args.frontend_port or env_int("FRONTEND_PORT", 3000)
    backend_scheme = env_value("BACKEND_SCHEME", "http")
    frontend_scheme = env_value("FRONTEND_SCHEME", "http")
    api_prefix = normalize_path(env_value("API_V1_PREFIX", "/api/v1"), "/api/v1")

    backend_public_url = env_value(
        "BACKEND_PUBLIC_URL",
        f"{backend_scheme}://{env_value('BACKEND_CLIENT_HOST', client_host(backend_host))}:{backend_port}",
    ).rstrip("/")
    frontend_public_url = env_value(
        "FRONTEND_PUBLIC_URL",
        f"{frontend_scheme}://{env_value('FRONTEND_CLIENT_HOST', client_host(frontend_host))}:{frontend_port}",
    ).rstrip("/")
    api_base_url = env_value("FRONTEND_API_BASE_URL", join_url(backend_public_url, api_prefix)).rstrip("/")

    return {
        "backend_host": backend_host,
        "frontend_host": frontend_host,
        "backend_port": backend_port,
        "frontend_port": frontend_port,
        "backend_public_url": backend_public_url,
        "frontend_public_url": frontend_public_url,
        "api_prefix": api_prefix,
        "api_base_url": api_base_url,
        "docs_url": join_url(backend_public_url, "docs"),
    }


def write_runtime_config(config: dict[str, object]) -> None:
    payload = {
        "apiBaseUrl": config["api_base_url"],
        "apiPrefix": config["api_prefix"],
        "backendUrl": config["backend_public_url"],
        "docsUrl": config["docs_url"],
    }
    RUNTIME_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    RUNTIME_CONFIG.write_text(
        f"window.AUDITPILOT_CONFIG = Object.freeze({json.dumps(payload, separators=(',', ':'))});\n",
        encoding="utf-8",
    )


def prepare_child_env(config: dict[str, object]) -> dict[str, str]:
    child_env = os.environ.copy()
    if not has_value(child_env.get("CORS_ORIGINS")):
        origins = [str(config["frontend_public_url"])]
        frontend_public_url = str(config["frontend_public_url"])
        frontend_port = int(config["frontend_port"])
        if frontend_public_url.startswith("http://127.0.0.1:"):
            origins.append(f"http://localhost:{frontend_port}")
        child_env["CORS_ORIGINS"] = json.dumps(list(dict.fromkeys(origins)), separators=(",", ":"))
    return child_env


def start_process(args: list[str], cwd: Path, stdout_path: Path, stderr_path: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout = stdout_path.open("ab")
    stderr = stderr_path.open("ab")
    kwargs: dict[str, object] = {
        "cwd": cwd,
        "stdout": stdout,
        "stderr": stderr,
        "env": env,
    }
    if platform.system() == "Windows":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(args, **kwargs)


def assert_started(process: subprocess.Popen[bytes], name: str, error_log: Path) -> None:
    time.sleep(1.5)
    if process.poll() is None:
        return
    details = ""
    if error_log.exists():
        details = "\n".join(error_log.read_text(encoding="utf-8", errors="replace").splitlines()[-30:])
    raise SystemExit(f"{name} process exited during startup.\n{details}")


def start(args: argparse.Namespace) -> None:
    load_dotenv(ENV_FILE)
    if not (FRONTEND_ROOT / "index.html").exists():
        raise SystemExit(f"Frontend entry not found: {FRONTEND_ROOT / 'index.html'}")

    existing = read_state()
    if existing:
        backend_pid = int(existing.get("backend_pid") or 0)
        frontend_pid = int(existing.get("frontend_pid") or 0)
        if process_running(backend_pid) or process_running(frontend_pid):
            raise SystemExit(f"Existing dev state found at {STATE_FILE}. Run `python dev.py stop` first.")
        STATE_FILE.unlink(missing_ok=True)

    config = build_config(args)
    assert_port_free(str(config["backend_host"]), int(config["backend_port"]), "Backend")
    assert_port_free(str(config["frontend_host"]), int(config["frontend_port"]), "Frontend")

    python = managed_python(args.python or env_value("PYTHON_EXECUTABLE"))
    ensure_dependencies(python)
    write_runtime_config(config)
    child_env = prepare_child_env(config)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

    backend = start_process(
        [
            str(python),
            "-m",
            "uvicorn",
            "backend.app.main:app",
            "--host",
            str(config["backend_host"]),
            "--port",
            str(config["backend_port"]),
            "--reload",
        ],
        ROOT,
        BACKEND_OUT,
        BACKEND_ERR,
        child_env,
    )
    frontend = start_process(
        [
            str(python),
            "-m",
            "http.server",
            str(config["frontend_port"]),
            "--bind",
            str(config["frontend_host"]),
        ],
        FRONTEND_ROOT,
        FRONTEND_OUT,
        FRONTEND_ERR,
        child_env,
    )

    try:
        assert_started(backend, "Backend", BACKEND_ERR)
        assert_started(frontend, "Frontend", FRONTEND_ERR)
    except BaseException:
        stop_process_tree(backend.pid)
        stop_process_tree(frontend.pid)
        raise

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(
            {
                "backend_pid": backend.pid,
                "frontend_pid": frontend.pid,
                "backend_url": config["backend_public_url"],
                "frontend_url": config["frontend_public_url"],
                "api_base_url": config["api_base_url"],
                "python": str(python),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\nAuditPilot dev stack started.")
    print(f"Frontend: {config['frontend_public_url']}")
    print(f"Backend:  {config['backend_public_url']}")
    print(f"API:      {config['api_base_url']}")
    print(f"Swagger:  {config['docs_url']}")
    print(f"Python:   {python}")
    print("\nLog files:")
    print(f"  {BACKEND_OUT}")
    print(f"  {BACKEND_ERR}")
    print(f"  {FRONTEND_OUT}")
    print(f"  {FRONTEND_ERR}")
    print("\nStop command: python dev.py stop")

    if args.open_browser:
        webbrowser.open(str(config["frontend_public_url"]))


def stop(_: argparse.Namespace) -> None:
    state = read_state()
    if not state:
        print("No running dev state found.")
        return

    for key in ("backend_pid", "frontend_pid"):
        pid = int(state.get(key) or 0)
        if pid:
            stop_process_tree(pid)
            print(f"Stopped process tree {pid}")

    STATE_FILE.unlink(missing_ok=True)
    print("AuditPilot dev stack stopped.")


def status(_: argparse.Namespace) -> None:
    state = read_state()
    if not state:
        print("No running dev state found.")
        return

    backend_pid = int(state.get("backend_pid") or 0)
    frontend_pid = int(state.get("frontend_pid") or 0)
    print(f"Frontend: {state.get('frontend_url')} ({'running' if process_running(frontend_pid) else 'stopped'})")
    print(f"Backend:  {state.get('backend_url')} ({'running' if process_running(backend_pid) else 'stopped'})")
    print(f"API:      {state.get('api_base_url')}")


def restart(args: argparse.Namespace) -> None:
    stop(args)
    start(args)


def parse_args() -> argparse.Namespace:
    if len(sys.argv) == 1:
        sys.argv.append("start")

    parser = argparse.ArgumentParser(description="Cross-platform AuditPilot dev stack controller.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_start_options(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--backend-port", type=int, default=0)
        subparser.add_argument("--frontend-port", type=int, default=0)
        subparser.add_argument("--backend-host", default="")
        subparser.add_argument("--frontend-host", default="")
        subparser.add_argument("--python", default="", help="Python executable used to create/manage the virtualenv.")
        subparser.add_argument("--open-browser", action="store_true")

    start_parser = subparsers.add_parser("start", help="Start frontend and backend.")
    add_start_options(start_parser)
    start_parser.set_defaults(func=start)

    stop_parser = subparsers.add_parser("stop", help="Stop frontend and backend.")
    stop_parser.set_defaults(func=stop)

    restart_parser = subparsers.add_parser("restart", help="Restart frontend and backend.")
    add_start_options(restart_parser)
    restart_parser.set_defaults(func=restart)

    status_parser = subparsers.add_parser("status", help="Show frontend/backend status.")
    status_parser.set_defaults(func=status)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
