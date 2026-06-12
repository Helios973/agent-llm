from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from backend.app.core.config import settings
from backend.app.scanners import java_dependencies


class JavaDependencyScannerTests(unittest.TestCase):
    def test_resolves_parent_pom_properties_for_java_skill_rules(self) -> None:
        original_root = settings.java_audit_skills_root
        original_enabled = settings.java_audit_skills_enabled

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            skill_root = temp_path / "skills"
            rules_dir = skill_root / "java-vuln-scanner" / "references"
            rules_dir.mkdir(parents=True)
            (rules_dir / "java-vulnerability.yaml").write_text(
                textwrap.dedent(
                    r"""
                    rules:
                      critical:
                        - name: "Apache Shiro 认证绕过漏洞 (CVE-2020-13933)"
                          description: "Shiro 低版本存在认证绕过风险"
                          pattern: 'shiro-core["'']?\s*[:_-]\s*["'']?1\.4\.0'
                        - name: "Apache Shiro RememberMe 反序列化漏洞 (CVE-2019-12422)"
                          description: "RememberMe 低版本存在反序列化风险"
                          pattern: 'shiro-core["'']?\s*[:_-]\s*["'']?1\.4\.0'
                        - name: "Commons FileUpload DOS漏洞 (CVE-2023-24998)"
                          description: "Commons FileUpload 1.3.3 存在拒绝服务风险"
                          pattern: 'commons-fileupload["'']?\s*[:_-]\s*["'']?1\.3\.3'
                    """
                ).strip(),
                encoding="utf-8",
            )

            project_path = temp_path / "project"
            framework_dir = project_path / "ruoyi-framework"
            common_dir = project_path / "ruoyi-common"
            framework_dir.mkdir(parents=True)
            common_dir.mkdir(parents=True)

            (project_path / "pom.xml").write_text(
                textwrap.dedent(
                    """
                    <project xmlns="http://maven.apache.org/POM/4.0.0">
                      <modelVersion>4.0.0</modelVersion>
                      <groupId>com.example</groupId>
                      <artifactId>demo-parent</artifactId>
                      <version>1.0.0</version>
                      <properties>
                        <shiro.version>1.4.0</shiro.version>
                      </properties>
                    </project>
                    """
                ).strip(),
                encoding="utf-8",
            )
            (framework_dir / "pom.xml").write_text(
                textwrap.dedent(
                    """
                    <project xmlns="http://maven.apache.org/POM/4.0.0">
                      <parent>
                        <groupId>com.example</groupId>
                        <artifactId>demo-parent</artifactId>
                        <version>1.0.0</version>
                      </parent>
                      <modelVersion>4.0.0</modelVersion>
                      <artifactId>ruoyi-framework</artifactId>
                      <dependencies>
                        <dependency>
                          <groupId>org.apache.shiro</groupId>
                          <artifactId>shiro-core</artifactId>
                          <version>${shiro.version}</version>
                        </dependency>
                      </dependencies>
                    </project>
                    """
                ).strip(),
                encoding="utf-8",
            )
            (common_dir / "pom.xml").write_text(
                textwrap.dedent(
                    """
                    <project xmlns="http://maven.apache.org/POM/4.0.0">
                      <parent>
                        <groupId>com.example</groupId>
                        <artifactId>demo-parent</artifactId>
                        <version>1.0.0</version>
                      </parent>
                      <modelVersion>4.0.0</modelVersion>
                      <artifactId>ruoyi-common</artifactId>
                      <properties>
                        <commons.fileupload.version>1.3.3</commons.fileupload.version>
                      </properties>
                      <dependencies>
                        <dependency>
                          <groupId>commons-fileupload</groupId>
                          <artifactId>commons-fileupload</artifactId>
                          <version>${commons.fileupload.version}</version>
                        </dependency>
                      </dependencies>
                    </project>
                    """
                ).strip(),
                encoding="utf-8",
            )

            settings.java_audit_skills_root = skill_root
            settings.java_audit_skills_enabled = True
            java_dependencies._load_rules.cache_clear()
            java_dependencies._parse_pom.cache_clear()

            findings = java_dependencies.run(project_path)

        settings.java_audit_skills_root = original_root
        settings.java_audit_skills_enabled = original_enabled
        java_dependencies._load_rules.cache_clear()
        java_dependencies._parse_pom.cache_clear()

        titles = {item["title"] for item in findings}
        self.assertIn("Apache Shiro 认证绕过漏洞 (CVE-2020-13933)", titles)
        self.assertIn("Apache Shiro RememberMe 反序列化漏洞 (CVE-2019-12422)", titles)
        self.assertIn("Commons FileUpload DOS漏洞 (CVE-2023-24998)", titles)

        shiro_findings = [item for item in findings if "Shiro" in item["title"]]
        self.assertTrue(all(item["file_path"] == "ruoyi-framework/pom.xml" for item in shiro_findings))
        self.assertTrue(all(item["owasp_id"] in {"A07:2021", "A08:2021"} for item in shiro_findings))


if __name__ == "__main__":
    unittest.main()
