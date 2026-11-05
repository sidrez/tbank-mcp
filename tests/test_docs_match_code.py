"""Read-only documentation and distribution metadata must match the live registry."""
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tbank_mcp import server
from tbank_mcp.readonly import READONLY_TOOLS


class DocsTests(unittest.TestCase):
    def test_readme_lists_exact_live_tools(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        names = set(re.findall(r"^\| `([a-z_]+)`", readme, re.M))
        self.assertEqual(names, READONLY_TOOLS)
        self.assertEqual(names, {t.name for t in server.mcp._tool_manager.list_tools()})

    def test_catalog_cannot_install_original_pypi(self):
        metadata = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertNotIn("packages", metadata)
        self.assertEqual(metadata["repository"]["url"], "https://github.com/sidrez/tbank-mcp")
        catalog = json.loads((ROOT / "lhm.plugin.json").read_text(encoding="utf-8"))
        self.assertEqual({t["name"] for t in catalog["tools"]}, READONLY_TOOLS)

    def test_shipped_instructions_name_only_published_tools(self):
        files = list((ROOT / "tbank_mcp/skills").rglob("SKILL.md"))
        files.append(ROOT / "tbank_mcp/docs/FLOWS.md")
        for file in files:
            text = file.read_text(encoding="utf-8")
            for name in re.findall(r"\b([a-z][a-z_]+)\(", text):
                self.assertIn(name, READONLY_TOOLS, str(file))
            self.assertIn("tbank-mcp-login", text)

    def test_guide_and_template_exist_and_link(self):
        guide = (ROOT / "docs/CHATGPT_RU.md").read_text(encoding="utf-8")
        for expected in ["Secure MCP Tunnel", "TBANK_SESSION", "несколько", "No authentication"]:
            self.assertIn(expected.lower(), guide.lower())
        self.assertTrue((ROOT / "deploy/tbank-readonly-tunnel.service.example").is_file())


if __name__ == "__main__":
    unittest.main()
