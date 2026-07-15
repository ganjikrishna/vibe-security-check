import tempfile
import unittest
from pathlib import Path

from vibe_security_check import markdown, scan


class SecurityCheckTests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        (root / ".gitignore").write_text(".env\n", encoding="utf-8")
        return temp, root

    def test_safe_project_has_clear_result(self):
        temp, root = self.project()
        self.addCleanup(temp.cleanup)
        (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
        result = scan(root)
        self.assertEqual(result["risk"], "clear")
        self.assertEqual(result["score"], 100)

    def test_dynamic_execution_and_debug_are_flagged(self):
        temp, root = self.project()
        self.addCleanup(temp.cleanup)
        (root / "app.py").write_text("DEBUG = True\nresult = eval(user_input)\n", encoding="utf-8")
        result = scan(root)
        self.assertEqual({x["rule_id"] for x in result["findings"]}, {"DEBUG-PRODUCTION", "PY-DYNAMIC-EXEC"})
        self.assertEqual(result["risk"], "high")

    def test_sensitive_file_is_critical(self):
        temp, root = self.project()
        self.addCleanup(temp.cleanup)
        (root / ".env").write_text("APP_MODE=demo\n", encoding="utf-8")
        result = scan(root)
        self.assertEqual(result["counts"]["critical"], 1)

    def test_secret_evidence_is_redacted(self):
        temp, root = self.project()
        self.addCleanup(temp.cleanup)
        (root / "settings.py").write_text("api_key = 'sample-value-12345'\n", encoding="utf-8")
        evidence = scan(root)["findings"][0]["evidence"]
        self.assertNotIn("sample-value-12345", evidence)

    def test_markdown_contains_location_and_limitations(self):
        temp, root = self.project()
        self.addCleanup(temp.cleanup)
        (root / "app.js").write_text("element.innerHTML = input;\n", encoding="utf-8")
        output = markdown(scan(root))
        self.assertIn("WEB-UNSAFE-HTML", output)
        self.assertIn("## Limitations", output)


if __name__ == "__main__":
    unittest.main()

