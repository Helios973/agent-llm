from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.agent.nodes.detect_stack import detect_stack


class DetectStackTests(unittest.TestCase):
    def test_detects_python_fastapi(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "main.py").write_text(
                "from fastapi import FastAPI\napp = FastAPI()\n",
                encoding="utf-8",
            )

            language, framework, entrypoint = detect_stack(project_path)

        self.assertEqual((language, framework, entrypoint), ("python", "fastapi", "main.py"))

    def test_detects_nextjs_typescript(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "package.json").write_text(
                json.dumps(
                    {
                        "name": "demo-next",
                        "dependencies": {"next": "14.0.0", "react": "18.0.0"},
                        "devDependencies": {"typescript": "5.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            (project_path / "tsconfig.json").write_text("{}", encoding="utf-8")
            (project_path / "app").mkdir()
            (project_path / "app" / "page.tsx").write_text("export default function Page(){ return <div/>; }\n", encoding="utf-8")

            language, framework, entrypoint = detect_stack(project_path)

        self.assertEqual((language, framework, entrypoint), ("typescript", "nextjs", "app/page.tsx"))

    def test_detects_php_laravel(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "composer.json").write_text(
                json.dumps({"require": {"laravel/framework": "^11.0"}}),
                encoding="utf-8",
            )
            (project_path / "public").mkdir()
            (project_path / "public" / "index.php").write_text("<?php echo 'ok';\n", encoding="utf-8")

            language, framework, entrypoint = detect_stack(project_path)

        self.assertEqual((language, framework, entrypoint), ("php", "laravel", "public/index.php"))

    def test_detects_go_gin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "go.mod").write_text(
                "module demo\n\nrequire github.com/gin-gonic/gin v1.10.0\n",
                encoding="utf-8",
            )
            (project_path / "cmd" / "api").mkdir(parents=True)
            (project_path / "cmd" / "api" / "main.go").write_text(
                "package main\nimport \"github.com/gin-gonic/gin\"\nfunc main() {}\n",
                encoding="utf-8",
            )

            language, framework, entrypoint = detect_stack(project_path)

        self.assertEqual((language, framework, entrypoint), ("go", "gin", "cmd/api/main.go"))

    def test_detects_java_springboot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "pom.xml").write_text(
                "<project><artifactId>demo</artifactId><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
                encoding="utf-8",
            )
            source_dir = project_path / "src" / "main" / "java" / "demo"
            source_dir.mkdir(parents=True)
            (source_dir / "DemoApplication.java").write_text(
                "import org.springframework.boot.autoconfigure.SpringBootApplication;\n"
                "@SpringBootApplication\n"
                "public class DemoApplication { public static void main(String[] args) {} }\n",
                encoding="utf-8",
            )

            language, framework, entrypoint = detect_stack(project_path)

        self.assertEqual((language, framework, entrypoint), ("java", "springboot", "src/main/java/demo/DemoApplication.java"))


if __name__ == "__main__":
    unittest.main()
