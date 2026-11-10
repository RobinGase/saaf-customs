"""Run: python3 -I -m unittest discover -s tests  (from the saaf-customs directory)"""
import json, subprocess, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "skills/saaf-customs/scripts/customs.py"
FX = ROOT / "tests/fixtures"

def scan(name, *extra):
    out = subprocess.run([sys.executable, "-I", str(CLI), "scan", str(FX / name), "--json", "--fail-on", "never", *extra],
                         capture_output=True, text=True, check=True).stdout
    d = json.loads(out)
    return d["verdict"], {f["rule"] for f in d["findings"]}

class Customs(unittest.TestCase):
    def test_evil_skill_blocked(self):
        v, r = scan("evil-skill")
        self.assertEqual(v, "BLOCK")
        self.assertTrue({"UNI-TAG-CHARS", "PI-OVERRIDE", "PI-CONCEAL", "PI-HIDDEN-TAG", "PI-HTML-COMMENT", "EXEC-PIPE-SHELL"} <= r, r)

    def test_evil_plugin_blocked(self):
        v, r = scan("evil-plugin")
        self.assertEqual(v, "BLOCK")
        self.assertTrue({"HOOK-AUTO-COMMAND", "PERM-WIDE-ALLOW", "PERM-BYPASS", "PERM-ALL-MCP", "EXFIL-KNOWN-SINK"} <= r, r)

    def test_evil_mcp_blocked_and_mandate(self):
        v, r = scan("evil-mcp", "--mandate", str(FX / "agent.yaml"))
        self.assertEqual(v, "BLOCK")
        self.assertTrue({"EXFIL-ENV-TO-NET", "EXEC-DECODE-EVAL", "CRED-FILE-ACCESS", "PI-CROSS-TOOL", "PERSIST-AGENT-CONFIG",
                         "MCP-UNPINNED-LAUNCH", "MCP-INLINE-SECRET", "MANDATE-CONFLICT"} <= r, r)

    def test_evil_npm_blocked(self):
        v, r = scan("evil-npm")
        self.assertEqual(v, "BLOCK")
        self.assertTrue({"INSTALL-NPM-HOOK", "DEP-TYPOSQUAT"} <= r, r)

    def test_clean_skill_allowed(self):
        self.assertEqual(scan("clean-skill"), ("ALLOW", set()))

if __name__ == "__main__":
    unittest.main()
