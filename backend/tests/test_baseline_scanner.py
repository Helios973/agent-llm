from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.app.scanners import baseline, gitleaks
from backend.app.services.vulnerability_catalog import enrich_finding, extract_code_snippet


class BaselineScannerTests(unittest.TestCase):
    def test_detects_php_unserialize(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "index.php").write_text(
                "<?php\n$payload = $_POST['payload'];\n$data = unserialize($payload);\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)
            titles = [item["title"] for item in findings]
            self.assertIn("Unsafe PHP Deserialization", titles)

            finding = next(item for item in findings if item["title"] == "Unsafe PHP Deserialization")
            enriched = enrich_finding(finding, project_path)
            self.assertEqual(enriched["cwe_id"], "CWE-502")

    def test_detects_dom_xss_and_maps_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "app.js").write_text(
                "const target = document.getElementById('out');\n"
                "target.innerHTML = location.search;\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)
            xss_finding = next(item for item in findings if item["title"] == "Potential Cross-Site Scripting (XSS)")
            enriched = enrich_finding(xss_finding, project_path)
            self.assertEqual(enriched["cwe_id"], "CWE-79")
            self.assertEqual(enriched["owasp_id"], "A03:2021")

    def test_detects_path_traversal_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "download.php").write_text(
                "<?php\n$file = $_GET['file'];\nreadfile($file);\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)
            self.assertTrue(any(item["title"] == "Potential Path Traversal / File Inclusion" for item in findings))

    def test_detects_mybatis_xml_sql_injection_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            mapper_dir = project_path / "mapper"
            mapper_dir.mkdir()
            (mapper_dir / "SysRoleMapper.xml").write_text(
                "<mapper namespace=\"demo.SysRoleMapper\">\n"
                "<select id=\"selectRoleList\" resultType=\"SysRole\">\n"
                "  select * from sys_role\n"
                "  <where>\n"
                "    ${params.dataScope}\n"
                "  </where>\n"
                "</select>\n"
                "</mapper>\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)

            sql_finding = next(item for item in findings if item["title"] == "Potential SQL Injection")
            enriched = enrich_finding(sql_finding, project_path)
            self.assertEqual(sql_finding["file_path"], "mapper/SysRoleMapper.xml")
            self.assertEqual(enriched["cwe_id"], "CWE-89")

    def test_detects_java_download_path_traversal_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "CommonController.java").write_text(
                "public class CommonController {\n"
                "    public void fileDownload(String fileName, HttpServletResponse response) throws Exception {\n"
                "        String realFileName = System.currentTimeMillis() + fileName.substring(fileName.indexOf(\"_\") + 1);\n"
                "        String filePath = Global.getDownloadPath() + fileName;\n"
                "        FileUtils.writeBytes(filePath, response.getOutputStream());\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)

        self.assertTrue(any(item["title"] == "Potential Path Traversal / File Inclusion" for item in findings))

    def test_does_not_match_file_substring_inside_profile_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "index.php").write_text(
                "<?php\nrequire_once('class.php');\nheader('Location: profile.php');\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)

        self.assertFalse(any(item["title"] == "Potential Path Traversal / File Inclusion" for item in findings))

    def test_skips_minified_vendor_like_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "jquery.min.js").write_text(
                "function x(){return /a/.exec(location.search)};" * 400,
                encoding="utf-8",
            )

            findings = baseline.run(project_path)

        self.assertEqual(findings, [])

    def test_skips_target_build_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            target_dir = project_path / "target" / "classes"
            target_dir.mkdir(parents=True)
            (target_dir / "download.php").write_text(
                "<?php\n$file = $_GET['file'];\nreadfile($file);\n",
                encoding="utf-8",
            )

            findings = baseline.run(project_path)

        self.assertEqual(findings, [])

    def test_gitleaks_ignores_password_variables_from_request_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "index.php").write_text(
                "<?php\n$password = $_POST['password'];\n$pwd = $_REQUEST['pwd'];\n",
                encoding="utf-8",
            )

            findings = gitleaks.run(project_path)

        self.assertEqual(findings, [])

    def test_gitleaks_detects_literal_password_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "config.php").write_text(
                "<?php\n$password = 'admin1234';\n",
                encoding="utf-8",
            )

            findings = gitleaks.run(project_path)

        self.assertTrue(any(item["title"] == "Hardcoded Password" for item in findings))

    def test_extract_code_snippet_truncates_minified_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "static").mkdir()
            file_path = project_path / "static" / "app.min.js"
            file_path.write_text("var a='" + ("x" * 6000) + "';", encoding="utf-8")

            snippet = extract_code_snippet(project_path, "static/app.min.js", 1)

        self.assertIn("压缩/第三方静态资源已省略长行预览", snippet)


if __name__ == "__main__":
    unittest.main()
