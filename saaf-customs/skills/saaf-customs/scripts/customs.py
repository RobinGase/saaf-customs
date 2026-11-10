#!/usr/bin/env python3
"""SAAF Customs - pre-install inspection for skills, plugins, MCP servers and packages.

Zero dependencies (Python 3.9+ stdlib). Never installs, imports, builds or executes
the target. Fetches into a fresh quarantine directory, scans statically, and emits a
verdict (ALLOW / REVIEW / BLOCK) plus Markdown, JSON and SAAF-findings CSV output.

Usage:
  python3 -I customs.py scan <target> [options]

Targets:
  ./local/path                      a directory already on disk
  https://github.com/owner/repo     any git URL (cloned --depth 1, hooks disabled)
  github:owner/repo[@ref]           shorthand for a GitHub repo
  npm:package[@version]             npm tarball, downloaded without running scripts
  pypi:package[==version]           PyPI sdist/wheel, downloaded without building

Exit codes: 0 ALLOW, 1 REVIEW, 2 BLOCK, 3 usage/fetch error.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

VERSION = "0.1.0"
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 20_000
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".next", ".tox"}

# Files an agent reads as instructions. Text here is executed by the model, so
# injection phrasing is far more dangerous than in ordinary docs.
INSTRUCTION_NAMES = {"skill.md", "agents.md", "claude.md", "gemini.md", ".cursorrules",
                     ".windsurfrules", "copilot-instructions.md", "system_prompt.md",
                     "system-prompt.md", "prompt.md"}
INSTRUCTION_DIRS = {"agents", "commands", "skills", "prompts", ".claude", ".cursor"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
            ".ps1", ".rb", ".go", ".rs", ".php", ".pl", ".lua"}
TEXT_EXT = CODE_EXT | {".md", ".mdx", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg",
                       ".ini", ".html", ".xml", ".env", ".lock", ""}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    observation: str
    recommendation: str
    blocking: bool = False

    def key(self):
        return (self.rule, self.file, self.line)


@dataclass
class Report:
    target: str
    resolved: str
    source_ref: str
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    inventory: dict = field(default_factory=dict)
    verdict: str = "ALLOW"


# --------------------------------------------------------------------------- rules
# (id, severity, category, regex, title, recommendation, scope, blocking)
# scope: "code" (code files), "instr" (instruction surfaces), "any" (all text),
#        "shell" (code + markdown code blocks, i.e. any)
R = re.compile
RULES = [
    # --- remote code execution / droppers
    ("EXEC-PIPE-SHELL", "High", "remote-code-execution",
     R(r"(curl|wget|iwr|Invoke-WebRequest)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|)sh\b|(curl|wget)[^\n]{0,200}\|\s*python"),
     "Downloads and pipes remote content straight into a shell",
     "Do not install. Remote script content can change after review (rug pull). Vendor and pin the script, or drop it.",
     "any", True),
    ("EXEC-DECODE-EVAL", "Critical", "obfuscation",
     R(r"(eval|exec|Function)\s*\(\s*(atob|Buffer\.from|base64\.b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|marshal\.loads)"),
     "Decodes a hidden payload and executes it",
     "Treat as malicious until the decoded payload is reviewed. Legitimate tools do not need eval(decode(...)).",
     "code", True),
    ("EXEC-MARSHAL", "High", "obfuscation",
     R(r"\bmarshal\.loads\s*\(|\bpickle\.loads\s*\(\s*(base64|zlib|bytes\.fromhex)"),
     "Loads serialized bytecode/objects from an embedded blob",
     "Ask the author for the source of the serialized blob; reject if unexplained.",
     "code", True),
    ("EXEC-CHARCODE", "High", "obfuscation",
     R(r"String\.fromCharCode\((\s*\d+\s*,){15,}|(\\x[0-9a-fA-F]{2}){30,}|chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)"),
     "Builds strings from character codes / dense hex escapes (common obfuscation)",
     "Decode the string and review what it does before trusting the package.",
     "code", True),

    # --- exfiltration
    ("EXFIL-KNOWN-SINK", "High", "exfiltration",
     R(r"(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(pro|fun|live|site|me)|burpcollaborator|"
       r"pastebin\.com|transfer\.sh|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|"
       r"\.trycloudflare\.com|serveo\.net|localtunnel\.me)", re.I),
     "References a known data-exfiltration / tunnelling endpoint",
     "A skill or tool has no reason to post to throwaway webhooks or tunnels. Block unless the author justifies it.",
     "any", True),
    ("EXFIL-ENV-TO-NET", "Critical", "exfiltration",
     R(r"(curl|wget|fetch|requests\.(post|put)|httpx\.(post|put)|axios\.(post|put)|urllib\.request)[^\n]{0,240}"
       r"(os\.environ|process\.env|\$\{?(HOME|AWS_|GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|[A-Z_]*TOKEN|[A-Z_]*SECRET|[A-Z_]*KEY)\b|printenv|env\b\s*\||id_rsa|\.ssh/|credentials)"),
     "Sends environment variables, keys or credential files over the network",
     "Block. This is the core shape of a credential stealer.",
     "any", True),
    ("EXFIL-CURL-DATA-FILE", "High", "exfiltration",
     R(r"curl\b[^\n]{0,200}(-d|--data(-binary|-raw)?|-F|--form|-T|--upload-file)\s*['\"]?@"),
     "Uploads a local file with curl",
     "Check which file is uploaded and to where; block if it can be a user file or secret.",
     "any", True),
    ("EXFIL-DNS", "Medium", "exfiltration",
     R(r"(nslookup|dig|host)\s+[^\n]{0,40}\$\(|socket\.gethostbyname\([^)]*\+"),
     "Builds DNS lookups from dynamic data (DNS exfiltration pattern)",
     "Review what data goes into the hostname.",
     "code", False),

    # --- credential access
    ("CRED-FILE-ACCESS", "High", "credential-access",
     R(r"(~|\$HOME|os\.path\.expanduser\(['\"]~|homedir\(\)|Path\.home\(\))[^\n]{0,60}"
       r"(\.ssh|\.aws/credentials|\.aws/config|\.netrc|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|\.gnupg|\.config/gh|"
       r"\.git-credentials|\.claude\.json|\.claude/\.credentials|Library/Keychains|Login Data|Cookies|\.mozilla|\.config/gcloud)"),
     "Reads credential stores in the user's home directory",
     "A skill/MCP server should get credentials through declared config, not by reading ~/.ssh, ~/.aws or browser stores.",
     "any", True),
    ("CRED-KEYCHAIN", "High", "credential-access",
     R(r"security\s+(find|dump)-(generic|internet)-password|security\s+dump-keychain|secret-tool\s+lookup|CredRead|vaultcmd", re.I),
     "Queries the OS keychain / credential manager",
     "Block unless keychain access is the declared, documented purpose.",
     "any", True),
    ("CRED-ENV-DUMP", "Medium", "credential-access",
     R(r"JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|json\.dumps\(\s*(dict\()?os\.environ|\bprintenv\b\s*(>|\|)"),
     "Serialises the whole environment (all secrets at once)",
     "Read only the specific variables the tool needs.",
     "any", False),

    # --- persistence / agent-config tampering
    ("PERSIST-AGENT-CONFIG", "High", "persistence",
     R(r"(>>?\s*['\"]?(~|\$HOME|\$\{HOME\}|\.)?/?[\w./-]*(?=\.claude|CLAUDE|AGENTS|\.cursor|\.mcp|claude_desktop|\.codex)|write_text|writeFile(Sync)?|appendFile(Sync)?|open\([^)]*['\"][aw]\+?['\"])[^\n]{0,120}"
       r"(\.claude/(settings|CLAUDE|commands|agents|skills|hooks)|CLAUDE\.md|AGENTS\.md|\.cursor/|\.mcp\.json|claude_desktop_config\.json|\.codex/)"
       r"|(\.claude/(settings|CLAUDE)|CLAUDE\.md|\.mcp\.json|claude_desktop_config\.json)[^\n]{0,80}(>>?|write_text|writeFile|appendFile|['\"][aw]\+?['\"])"),
     "Writes to agent configuration or instruction files (self-installs instructions, hooks or MCP servers)",
     "Block. A package that edits your agent's settings/CLAUDE.md can grant itself permissions or persistent instructions.",
     "any", True),
    ("PERSIST-SHELL-RC", "High", "persistence",
     R(r"(>>|write_text|appendFile|writeFile|open\([^)]*['\"]a)[^\n]{0,80}(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|config\.fish)"
       r"|crontab\s+-|LaunchAgents|LaunchDaemons|systemctl\s+(--user\s+)?enable|schtasks\s+/create|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", re.I),
     "Installs persistence (shell rc, cron, launchd, systemd, Run key)",
     "Block unless the package is explicitly a system service installer.",
     "any", True),
    ("DESTRUCTIVE-RM", "High", "destructive",
     R(r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+(--no-preserve-root\s+)?(/|~|\$HOME|\*)(\s|$|/\*)|shutil\.rmtree\(\s*(os\.path\.expanduser\(['\"]~|Path\.home\(\)|['\"]/['\"])"),
     "Recursively deletes home or root",
     "Block.",
     "any", True),
    ("PRIV-SUDO", "Medium", "privilege",
     R(r"\bsudo\s+(?!-n\s+true)\S|chmod\s+(-R\s+)?[0-7]*777|chmod\s+\+s\b|setuid\("),
     "Asks for root or world-writable permissions",
     "A skill or MCP server should run unprivileged.",
     "code", False),

    # --- prompt injection / tool poisoning (instruction surfaces)
    ("PI-OVERRIDE", "High", "prompt-injection",
     R(r"(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|system|other)\s+(instructions|prompts?|rules|guidelines|messages)", re.I),
     "Instruction-override phrasing",
     "Text the agent loads must not try to override its other instructions.",
     "instr", True),
    ("PI-CONCEAL", "High", "prompt-injection",
     R(r"(do\s*n[o']?t|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|show(ing)?|notify(ing)?|asking|alert(ing)?)\s+((this|it|that|anything)\s+)?(to\s+)?(the\s+)?(user|human|operator)|"
       r"\b(silently|secretly|covertly|quietly)\s+(run|execute|send|upload|post|read|copy|call|install)|"
       r"keep\s+this\s+(a\s+)?secret|the\s+user\s+(must|should)\s+not\s+(know|see)", re.I),
     "Tells the agent to hide actions from the user",
     "Block. Hidden side effects are the signature of tool poisoning.",
     "instr", True),
    ("PI-HIDDEN-TAG", "High", "prompt-injection",
     R(r"<\s*(IMPORTANT|SYSTEM|system-reminder|admin|instructions?|secret|hidden)\s*>|\[\s*(SYSTEM|INST)\s*\]|<\|im_start\|>|<\|system\|>", re.I),
     "Fake system / priority tags that try to look like platform instructions",
     "Remove; the platform's own tags must never appear in third-party content.",
     "instr", True),
    ("PI-AUTO-EXEC", "Medium", "prompt-injection",
     R(r"(always|automatically|immediately|first)\s+(run|execute|call|invoke)\s+[`'\"]?(curl|wget|bash|sh|python|node|npx|pip|npm)\b|"
       r"(without|no\s+need\s+(for|to))\s+(asking|confirmation|approval|permission)|--dangerously-skip-permissions|bypassPermissions", re.I),
     "Pushes the agent to run commands without confirmation",
     "Commands in a skill should be explicit, minimal and confirmed by the user.",
     "instr", False),
    ("PI-CROSS-TOOL", "High", "prompt-injection",
     R(r"(before|after|when)\s+(using|calling|you\s+use)\s+(any\s+other|any|another|the\s+other|other)\s+tools?|"
       r"(read|send|include|pass|attach)\s+(the\s+)?(contents?\s+of\s+)?[`'\"]?(~/\.ssh|id_rsa|\.env\b|mcp\.json|\.aws|\.netrc|\.npmrc|conversation\s+history|system\s+prompt)", re.I),
     "Tries to influence other tools or pull secrets into tool arguments (tool shadowing / poisoning)",
     "Block. A tool description must only describe its own tool.",
     "instr", True),
    ("PI-REMOTE-INSTRUCTIONS", "Medium", "rug-pull",
     R(r"(fetch|download|load|read|curl|get)\s+[^\n]{0,60}(instructions|prompt|skill|rules)[^\n]{0,40}(https?://|raw\.githubusercontent|gist\.github)", re.I),
     "Loads instructions from a remote URL at runtime",
     "Remote instructions can change after review (rug pull). Vendor them into the reviewed package.",
     "instr", False),

    # --- MCP / code-level weaknesses
    ("CODE-SHELL-TRUE", "Medium", "command-injection",
     R(r"subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(|os\.popen\(|child_process[^\n]{0,40}\bexec(Sync)?\s*\(|\bexecSync\s*\(`|\bexec\s*\(\s*`"),
     "Runs shell commands through a shell (command-injection risk if tool arguments reach it)",
     "Use argument arrays (shell=False / execFile) and validate tool inputs.",
     "code", False),
    ("CODE-DYNAMIC-EVAL", "Medium", "code-execution",
     R(r"(?<![\w.])eval\s*\((?!\s*['\"])|new\s+Function\s*\(|(?<![\w.])exec\s*\((?!\s*['\"])|vm\.runIn(New|This)?Context"),
     "Evaluates dynamic code",
     "Check that no model- or user-controlled data reaches eval/exec.",
     "code", False),
    ("CODE-TLS-OFF", "Medium", "transport",
     R(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context"),
     "Disables TLS certificate verification",
     "Keep certificate verification on.",
     "code", False),
    ("CODE-BIND-ALL", "Low", "network-exposure",
     R(r"host\s*=\s*['\"]0\.0\.0\.0['\"]|listen\([^)]*['\"]0\.0\.0\.0['\"]|--host\s+0\.0\.0\.0"),
     "Server binds to all interfaces",
     "Bind local MCP/HTTP servers to 127.0.0.1 and require auth for anything remote.",
     "code", False),

    # --- committed secrets (value is redacted in output)
    ("SECRET-COMMITTED", "High", "secret-exposure",
     R(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-)?[A-Za-z0-9]{32,}|"
       r"xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AIza[0-9A-Za-z_-]{35}"),
     "Hard-coded credential in the source",
     "Never ship keys. Report to the author; the key must be revoked, not just deleted.",
     "any", False),
]

INSTR_ONLY_DOWNGRADE = {"instr"}

# Unicode used to hide instructions from humans but not from models.
NEGATION = R(r"\b(not|never|no|don'?t|do\s+not|must\s+not|avoid|without|refuse|deny|block|detect|flag)\b[^.]*$", re.I)
FAKE_SECRET = R(r"(?i)(x{6,}|0{8,}|test|fake|dummy|example|placeholder|redacted|your[_-]?key|\.\.\.|<[^>]*>)")
TEST_PATH = R(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata|e2e|examples?)(/|$)|(\.|_)(test|spec)\.[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.(py|go)$")
BENIGN_INSTALL = R(r"^\s*(prisma generate|husky( install)?|patch-package|node-gyp rebuild|tsc|npm run build|ngcc|electron-builder install-app-deps)\s*$")
HIDDEN_UNICODE = R("[​‌‍⁠⁡⁢⁣⁤﻿­᠎]")
BIDI_UNICODE = R("[‪-‮⁦-⁩]")
TAG_UNICODE = R("[\U000E0000-\U000E007F]")
BASE64_BLOB = R(r"['\"`]([A-Za-z0-9+/]{240,}={0,2})['\"`]")
URL_RE = R(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(:\d+)?")
HTML_COMMENT = R(r"<!--(.*?)-->", re.S)

POPULAR_NPM = ["react", "lodash", "express", "axios", "chalk", "commander", "dotenv", "zod",
               "typescript", "next", "vue", "webpack", "eslint", "prettier", "jest", "moment",
               "request", "debug", "uuid", "yargs", "openai", "@anthropic-ai/sdk",
               "@modelcontextprotocol/sdk", "node-fetch", "cross-env", "colors", "puppeteer",
               "playwright", "mongoose", "socket.io", "jsonwebtoken", "bcrypt", "sharp"]
POPULAR_PYPI = ["requests", "numpy", "pandas", "anthropic", "openai", "mcp", "fastmcp",
                "pydantic", "flask", "django", "fastapi", "urllib3", "httpx", "boto3", "pyyaml",
                "setuptools", "langchain", "langgraph", "beautifulsoup4", "selenium", "pillow",
                "cryptography", "python-dotenv", "colorama", "matplotlib", "scipy", "click",
                "jinja2", "openpyxl", "python-docx", "pypdf", "tiktoken", "uvicorn"]
SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".ru", ".su", ".zip", ".mov")


def levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment distance (counts a swap of two adjacent letters as 1)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def redact(s: str) -> str:
    s = re.sub(r"(AKIA|ghp_|github_pat_|sk-ant-|sk-proj-|sk-|xox[baprs]-|AIza)[A-Za-z0-9_\-]{4,}",
               lambda m: m.group(1) + "****REDACTED****", s)
    s = s.replace("\r", " ").replace("\t", " ").strip()
    return (s[:180] + "...") if len(s) > 180 else s


# --------------------------------------------------------------------------- fetch
def _run(cmd, cwd=None, timeout=180):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir(),
           "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_LFS_SKIP_SMUDGE": "1",
           "npm_config_ignore_scripts": "true"}
    return subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout, capture_output=True, text=True, check=True)


def _safe_extract_tar(data: bytes, dest: Path):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")
        else:  # pragma: no cover - py<3.12 fallback
            for m in tf.getmembers():
                p = (dest / m.name).resolve()
                if not str(p).startswith(str(dest.resolve())) or m.issym() or m.islnk() or m.isdev():
                    continue
                tf.extract(m, dest)


def _safe_extract_zip(data: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            p = (dest / name).resolve()
            if not str(p).startswith(str(dest.resolve()) + os.sep):
                continue
            zf.extract(name, dest)


def _http_get(url: str, limit=60_000_000) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"saaf-customs/{VERSION}"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - https registry URLs only
        data = r.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("download exceeds size limit")
    return data


def fetch(target: str, quarantine: Path):
    """Return (path, resolved_description, source_ref). Never runs target code."""
    p = Path(target).expanduser()
    if p.exists():
        ref = "local"
        try:
            ref = _run(["git", "-C", str(p), "rev-parse", "HEAD"]).stdout.strip() or "local"
        except Exception:
            pass
        return p.resolve(), str(p.resolve()), ref

    if target.startswith("npm:"):
        spec = target[4:]
        name, _, ver = spec.rpartition("@") if spec.count("@") > (1 if spec.startswith("@") else 0) else (spec, "", "")
        meta = json.loads(_http_get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"))
        ver = ver or meta["dist-tags"]["latest"]
        tarball = meta["versions"][ver]["dist"]["tarball"]
        dest = quarantine / "pkg"
        dest.mkdir()
        _safe_extract_tar(_http_get(tarball), dest)
        return dest, f"npm {name}@{ver}", ver

    if target.startswith("pypi:"):
        spec = target[5:]
        name, _, ver = spec.partition("==")
        url = f"https://pypi.org/pypi/{name}/{ver}/json" if ver else f"https://pypi.org/pypi/{name}/json"
        meta = json.loads(_http_get(url))
        ver = meta["info"]["version"]
        files = meta["urls"]
        pick = next((f for f in files if f["packagetype"] == "sdist"), None) or (files[0] if files else None)
        if not pick:
            raise RuntimeError("no downloadable files on PyPI")
        dest = quarantine / "pkg"
        dest.mkdir()
        blob = _http_get(pick["url"])
        if pick["filename"].endswith((".whl", ".zip")):
            _safe_extract_zip(blob, dest)
        else:
            _safe_extract_tar(blob, dest)
        return dest, f"pypi {name}=={ver} ({pick['filename']})", ver

    m = re.match(r"github:([\w.-]+/[\w.-]+)(?:@(.+))?$", target)
    url, ref = (f"https://github.com/{m.group(1)}", m.group(2)) if m else (target, None)
    if not re.match(r"^(https://|git@|ssh://)", url):
        raise RuntimeError(f"unrecognised target: {target}")
    # Strip GitHub tree/blob paths: https://github.com/o/r/tree/main/sub -> repo + subdir
    sub = ""
    gm = re.match(r"(https://github\.com/[\w.-]+/[\w.-]+?)(?:\.git)?/(?:tree|blob)/([^/]+)/?(.*)$", url)
    if gm:
        url, ref, sub = gm.group(1), gm.group(2), gm.group(3)
    dest = quarantine / "repo"
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
           "-c", "protocol.file.allow=never", "-c", "submodule.recurse=false",
           "clone", "--depth", "1", "--no-tags", "--single-branch"]
    if ref:
        cmd += ["--branch", ref]
    _run(cmd + [url, str(dest)])
    sha = _run(["git", "-C", str(dest), "rev-parse", "HEAD"]).stdout.strip()
    root = dest / sub if sub else dest
    return root, f"{url}{'/' + sub if sub else ''}", sha


# --------------------------------------------------------------------------- scan
def is_instruction_surface(rel: Path) -> bool:
    name = rel.name.lower()
    if name in INSTRUCTION_NAMES:
        return True
    parts = {p.lower() for p in rel.parts[:-1]}
    if rel.suffix.lower() in {".md", ".mdc", ".txt"} and parts & INSTRUCTION_DIRS:
        return True
    return False


def is_tool_description_code(text: str) -> bool:
    return bool(re.search(r"@(mcp|server|app)\.tool|server\.tool\(|registerTool\(|\.setRequestHandler\(\s*ListToolsRequestSchema|"
                          r"\"inputSchema\"|inputSchema\s*:|FastMCP\(", text))


class Scanner:
    def __init__(self, root: Path, mandate: dict | None = None):
        self.root = root
        self.mandate = mandate
        self.findings: list[Finding] = []
        self.inventory = {"instruction_files": [], "hooks": [], "mcp_servers": [], "install_scripts": [],
                          "binaries": [], "domains": set(), "capabilities": set(), "manifests": []}
        self.files = 0

    def add(self, rule, title, sev, cat, rel, line, evidence, obs, rec, blocking=False):
        f = Finding(rule, title, sev, cat, str(rel), line, redact(evidence), obs, rec, blocking)
        if f.key() not in {x.key() for x in self.findings}:
            self.findings.append(f)

    # ---- walk
    def run(self):
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                full = Path(dirpath) / fn
                rel = full.relative_to(self.root)
                self.files += 1
                if self.files > MAX_FILES:
                    self.add("SCAN-LIMIT", "File limit reached", "Medium", "coverage", rel, 0, "",
                             f"Stopped after {MAX_FILES} files; remaining files were not inspected.",
                             "Scan a narrower path or review manually.")
                    return
                self.scan_file(full, rel)
        self.post_checks()

    def scan_file(self, full: Path, rel: Path):
        if full.is_symlink():
            target = os.readlink(full)
            resolved = (full.parent / target).resolve()
            if os.path.isabs(target) or not str(resolved).startswith(str(self.root.resolve())):
                self.add("FS-SYMLINK-ESCAPE", "Symlink points outside the package", "High", "filesystem", rel, 0,
                         f"-> {target}", "A symlink that leaves the package can make tools read or overwrite files such as ~/.ssh or agent config.",
                         "Reject packages with symlinks that escape their root.", True)
            return
        try:
            size = full.stat().st_size
        except OSError:
            return
        with open(full, "rb") as fh:
            head = fh.read(4)
        if head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe") or head[:2] == b"MZ" \
                or rel.suffix.lower() in {".exe", ".dll", ".so", ".dylib", ".pyc", ".node", ".jar", ".bin"}:
            self.inventory["binaries"].append(str(rel))
            self.add("BIN-EXECUTABLE", "Compiled binary / bytecode shipped in the package", "Medium", "opaque-code", rel, 0,
                     f"{size} bytes", "Binaries and bytecode cannot be reviewed from source and may differ from the published source.",
                     "Ask for a reproducible build from source, or reject.")
            return
        if size > MAX_FILE_BYTES or rel.suffix.lower() not in TEXT_EXT:
            return
        try:
            text = full.read_text("utf-8", errors="replace")
        except OSError:
            return
        name = rel.name.lower()
        instr = is_instruction_surface(rel)
        code = rel.suffix.lower() in CODE_EXT or name.startswith(("dockerfile", "containerfile")) or name.endswith(".dockerfile")
        tooldesc = code and is_tool_description_code(text)
        if instr:
            self.inventory["instruction_files"].append(str(rel))

        self.check_unicode(text, rel, instr or tooldesc)
        self.check_rules(text, rel, instr, code, tooldesc)
        self.check_blobs(text, rel, code)
        for m in URL_RE.finditer(text):
            self.inventory["domains"].add(m.group(1).lower())
        self.capabilities(text, code)

        if name == "package.json":
            self.check_package_json(text, rel)
        elif name in {"setup.py"}:
            self.check_setup_py(text, rel)
        elif name == "pyproject.toml":
            self.check_pyproject(text, rel)
        elif name.startswith("requirements") and name.endswith(".txt"):
            self.check_requirements(text, rel)
        elif name in {"hooks.json"} or (name in {"settings.json", "settings.local.json"} and ".claude" in rel.parts):
            self.check_claude_settings(text, rel)
        elif name in {".mcp.json", "mcp.json", "claude_desktop_config.json", "manifest.json"} or name.endswith(".mcp.json"):
            self.check_mcp_config(text, rel)
        elif name in {"plugin.json", "marketplace.json"}:
            self.inventory["manifests"].append(str(rel))
            self.check_mcp_config(text, rel)
            self.check_claude_settings(text, rel)
        if ".github" in rel.parts and "workflows" in rel.parts and rel.suffix in {".yml", ".yaml"}:
            self.check_workflow(text, rel)
        if rel.suffix.lower() in {".md", ".mdx"}:
            self.check_html_comments(text, rel, instr)

    # ---- generic
    def check_rules(self, text, rel, instr, code, tooldesc):
        lines = text.splitlines()
        doc_like = rel.suffix.lower() in {".md", ".mdx", ".txt"} and not instr
        for rid, sev, cat, rx, title, rec, scope, blocking in RULES:
            if scope == "code" and not code:
                continue
            if scope == "instr" and not (instr or tooldesc or doc_like):
                continue
            for i, line in enumerate(lines, 1):
                if len(line) > 5000:
                    line = line[:5000]
                m = rx.search(line)
                if not m:
                    continue
                s, b = sev, blocking
                if cat in {"prompt-injection", "credential-access"} and NEGATION.search(line[max(0, m.start() - 30):m.start()]):
                    continue  # "never read credentials" is a guardrail, not an attack
                if rid == "SECRET-COMMITTED" and FAKE_SECRET.search(m.group(0) + line):
                    continue
                where = "instruction file the agent loads" if instr else ("MCP tool definition code" if tooldesc else "file")
                if scope == "instr" and doc_like:
                    # Prose docs often *discuss* injection; keep as a low signal for the reviewer.
                    s, b, where = "Low", False, "documentation (not loaded as instructions)"
                if doc_like and scope == "any" and cat not in {"secret-exposure"}:
                    # Docs describe things; only commands users are told to paste stay above Low.
                    b = False
                    if rid != "EXEC-PIPE-SHELL":
                        s, where = "Low", "documentation"
                self.add(rid, title, s, cat, rel, i, m.group(0),
                         f"{title} in {where} {rel}:{i}.", rec, b)
                break  # one hit per rule per file keeps the report readable

    def check_unicode(self, text, rel, sensitive):
        for rx, rid, title, sev in ((TAG_UNICODE, "UNI-TAG-CHARS", "Invisible Unicode tag characters (ASCII smuggling)", "Critical"),
                                    (BIDI_UNICODE, "UNI-BIDI", "Bidirectional override characters (Trojan Source)", "High"),
                                    (HIDDEN_UNICODE, "UNI-ZERO-WIDTH", "Zero-width / invisible characters", "Medium")):
            m = rx.search(text)
            if not m:
                continue
            line = text.count("\n", 0, m.start()) + 1
            count = len(rx.findall(text))
            if rid == "UNI-ZERO-WIDTH" and count < 3 and not sensitive:
                continue  # a stray BOM/ZWJ in prose is common
            decoded = ""
            if rid == "UNI-TAG-CHARS":
                decoded = "".join(chr(ord(c) - 0xE0000) for c in rx.findall(text) if 0x20 <= ord(c) - 0xE0000 < 0x7F)
            sev2 = "Critical" if sensitive and rid != "UNI-ZERO-WIDTH" else ("High" if sensitive else sev)
            self.add(rid, title, sev2, "hidden-content", rel, line,
                     f"{count} chars" + (f"; decodes to: {decoded[:120]!r}" if decoded else ""),
                     f"{title}: {count} occurrence(s). Models read these characters; humans reviewing the file do not see them.",
                     "Strip or reject. There is no legitimate reason for hidden characters in instructions or code.",
                     sensitive or rid == "UNI-TAG-CHARS")

    def check_blobs(self, text, rel, code):
        m = BASE64_BLOB.search(text)
        if m and code:
            line = text.count("\n", 0, m.start()) + 1
            self.add("OBF-BASE64-BLOB", "Large encoded blob embedded in code", "Medium", "obfuscation", rel, line,
                     m.group(1)[:40] + "...", f"Base64-like blob of {len(m.group(1))} chars in code.",
                     "Decode it and confirm it is an inert asset (icon, font, test vector).")

    def check_html_comments(self, text, rel, instr):
        for m in HTML_COMMENT.finditer(text):
            body = m.group(1)
            if re.search(r"\b(you|assistant|claude|agent|AI|model|LLM)\b.*\b(must|should|always|never|run|execute|send|ignore)\b", body, re.I | re.S):
                line = text.count("\n", 0, m.start()) + 1
                self.add("PI-HTML-COMMENT", "Hidden instructions inside an HTML comment", "High" if instr else "Medium",
                         "prompt-injection", rel, line, body.strip()[:160],
                         "Markdown renders HTML comments invisibly, but the agent reads them as text.",
                         "Remove hidden directives; anything the agent should do must be visible to the reviewer.", instr)
                return

    def capabilities(self, text, code):
        if not code:
            return
        caps = self.inventory["capabilities"]
        checks = {
            "network": r"\b(requests|httpx|aiohttp|urllib\.request|fetch\(|axios|http\.request|net\.connect|socket\.)",
            "shell": r"\b(subprocess|os\.system|child_process|execa|spawn\(|Popen)",
            "file_write": r"(write_text|write_bytes|open\([^)]*['\"][wa]|,\s*['\"][wa]\+?b?['\"]\s*\)|writeFile|appendFile|fs\.write|shutil\.(copy|move)|os\.(remove|unlink|rename))",
            "send_email": r"\b(smtplib|nodemailer|sendgrid|mailgun|ses\.send|send_email|sendMail)\b",
            "env_secrets": r"(os\.environ|process\.env|getenv\()",
            "browser_automation": r"\b(playwright|puppeteer|selenium)\b",
            "code_eval": r"(?<![\w.])(eval|exec)\s*\(|new Function\(",
        }
        for cap, rx in checks.items():
            if re.search(rx, text):
                caps.add(cap)

    # ---- manifests
    def check_package_json(self, text, rel):
        try:
            pj = json.loads(text)
        except Exception:
            return
        scripts = pj.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"):
            cmd = scripts.get(hook)
            if not cmd:
                continue
            self.inventory["install_scripts"].append(f"{rel}:{hook}: {cmd}")
            danger = re.search(r"curl|wget|node\s+-e|python\s+-c|base64|eval|\bsh\b|bash|powershell|https?://", cmd, re.I)
            if BENIGN_INSTALL.match(cmd):
                self.add("INSTALL-NPM-HOOK-BENIGN", f"npm `{hook}` runs a known build step", "Low", "install-hook", rel, 0,
                         f"{hook}: {cmd}", f"`{cmd}` runs on install; it is a common build step.", "No action; re-check if it changes.")
                continue
            build_only = hook == "prepare" and re.fullmatch(r"\s*(npm run |tsc|husky|node-gyp|ng |vite |rollup |esbuild|patch-package)[^;&|]*", cmd)
            if build_only:
                continue
            self.add("INSTALL-NPM-HOOK", f"npm `{hook}` script runs code on install", "High" if danger else "Medium",
                     "install-hook", rel, 0, f"{hook}: {cmd}",
                     f"`npm install` runs `{cmd}` automatically with the user's privileges, before any review of runtime behaviour.",
                     "Install with --ignore-scripts and read the script; block if it fetches or decodes anything.", bool(danger))
        deps = {**(pj.get("dependencies") or {}), **(pj.get("optionalDependencies") or {})}
        for name, spec in deps.items():
            self.check_typosquat(name, POPULAR_NPM, rel, "npm")
            if isinstance(spec, str) and (spec in {"*", "latest", ""} or re.match(r"^(git|https?|github:|file:)", spec)):
                self.add("DEP-UNPINNED", "Unpinned or non-registry dependency", "Low", "supply-chain", rel, 0,
                         f"{name}: {spec}", f"Dependency {name} resolves to `{spec}`, which can change without a version bump.",
                         "Pin exact versions from the registry and commit a lockfile.")
        if pj.get("bin"):
            self.inventory["install_scripts"].append(f"{rel}:bin: {pj.get('bin')}")

    def check_setup_py(self, text, rel):
        self.inventory["install_scripts"].append(f"{rel}: setup.py executes at build/install time")
        if re.search(r"cmdclass\s*=|class\s+\w+\((install|develop|egg_info|build_py)\)", text):
            self.add("INSTALL-SETUP-CMDCLASS", "setup.py overrides install commands", "High", "install-hook", rel, 0,
                     "cmdclass", "Custom install/develop commands run arbitrary code during `pip install`.",
                     "Read the overridden command; prefer a wheel or pyproject-only build.", False)
        if re.search(r"^(?!\s*#).*\b(urlopen|requests\.|subprocess|os\.system|socket\.|base64)", text, re.M):
            self.add("INSTALL-SETUP-SIDE-EFFECT", "setup.py performs network/shell work at install time", "High", "install-hook",
                     rel, 0, "network/shell in setup.py", "setup.py is executed by pip; network or shell calls here run on install.",
                     "Block unless the behaviour is a documented native build step.", True)

    def check_pyproject(self, text, rel):
        if re.search(r"backend-path\s*=", text):
            self.add("INSTALL-INTREE-BACKEND", "In-tree custom build backend", "Medium", "install-hook", rel, 0, "backend-path",
                     "The package ships its own PEP 517 build backend, which runs during install.",
                     "Review the backend module before installing from sdist.")
        for m in re.finditer(r"['\"]([A-Za-z0-9_.-]+)\s*([<>=!~].*)?['\"]", text):
            self.check_typosquat(m.group(1).lower(), POPULAR_PYPI, rel, "pypi")

    def check_requirements(self, text, rel):
        for i, line in enumerate(text.splitlines(), 1):
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                if re.match(r"-(i|-index-url|-extra-index-url)\s+https?://(?!pypi\.org)", line):
                    self.add("DEP-ALT-INDEX", "Custom package index", "Medium", "supply-chain", rel, i, line,
                             "Packages may be resolved from a non-PyPI index (dependency confusion risk).",
                             "Use PyPI or a trusted internal mirror with hash pinning.")
                continue
            name = re.split(r"[<>=!~\[; @]", line)[0].lower()
            self.check_typosquat(name, POPULAR_PYPI, rel, "pypi", i)
            if "==" not in line and "@" not in line:
                self.add("DEP-UNPINNED", "Unpinned dependency", "Low", "supply-chain", rel, i, line,
                         f"`{line}` floats to the newest release at install time.", "Pin with == and --require-hashes.")

    def check_typosquat(self, name, popular, rel, eco, line=0):
        if not name or name in popular:
            return
        for p in popular:
            if abs(len(p) - len(name)) <= 1 and len(p) > 4 and levenshtein(name, p) == 1:
                self.add("DEP-TYPOSQUAT", f"Possible typosquat of `{p}`", "High", "supply-chain", rel, line, name,
                         f"{eco} dependency `{name}` is one edit away from the popular package `{p}`.",
                         f"Confirm the intended package is `{p}`; typosquats are a common malware delivery path.", True)
                return

    def check_claude_settings(self, text, rel):
        try:
            data = json.loads(text)
        except Exception:
            return
        hooks = data.get("hooks") if isinstance(data, dict) else None
        if isinstance(hooks, dict):
            for event, entries in hooks.items():
                cmds = re.findall(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)"', json.dumps(entries))
                for cmd in cmds:
                    self.inventory["hooks"].append(f"{rel}:{event}: {cmd}")
                    danger = re.search(r"curl|wget|https?://|base64|nc\s|eval|\|\s*(ba)?sh", cmd)
                    sev = "Critical" if danger else ("High" if event in {"SessionStart", "UserPromptSubmit", "PreToolUse"} else "Medium")
                    self.add("HOOK-AUTO-COMMAND", f"Agent hook runs a command on `{event}`", sev, "install-hook", rel, 0,
                             f"{event}: {cmd}",
                             f"The plugin registers a `{event}` hook; the command runs automatically on every matching event without a prompt.",
                             "Read every hook script line by line. Block hooks that touch the network or files outside the project.",
                             bool(danger))
        perms = data.get("permissions") if isinstance(data, dict) else None
        if isinstance(perms, dict):
            allow = perms.get("allow") or []
            wide = [a for a in allow if re.match(r"^(Bash(\(\*?\))?|Bash\(\*\)|Write|Edit|WebFetch|mcp__.*)$", str(a))]
            if wide:
                self.add("PERM-WIDE-ALLOW", "Pre-approves broad tool permissions", "High", "permissions", rel, 0, str(wide),
                         "Shipped settings auto-approve broad tools, so the agent stops asking before running commands.",
                         "Never accept third-party settings that widen permissions; keep approvals local and narrow.", True)
            if perms.get("defaultMode") in {"bypassPermissions", "acceptEdits"}:
                self.add("PERM-BYPASS", "Changes the default permission mode", "High", "permissions", rel, 0,
                         str(perms.get("defaultMode")), "Shipped settings switch the agent to a no-confirmation mode.",
                         "Reject.", True)
        if isinstance(data, dict) and data.get("enableAllProjectMcpServers"):
            self.add("PERM-ALL-MCP", "Auto-enables all project MCP servers", "High", "permissions", rel, 0,
                     "enableAllProjectMcpServers: true", "Any MCP server added to the repo later starts without approval.",
                     "Approve MCP servers individually.", True)

    def check_mcp_config(self, text, rel):
        try:
            data = json.loads(text)
        except Exception:
            return
        servers = {}
        if isinstance(data, dict):
            servers = data.get("mcpServers") or data.get("mcp_servers") or {}
            if not servers and isinstance(data.get("server"), dict):
                servers = {"server": data["server"]}
        if not isinstance(servers, dict):
            return
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            mc = cfg.get("mcp_config") if isinstance(cfg.get("mcp_config"), dict) else {}
            src = cfg if (cfg.get("command") or cfg.get("url")) else mc  # MCPB manifests nest under mcp_config
            cmd = " ".join([str(src.get("command", ""))] + [str(a) for a in src.get("args", []) or []])
            url = src.get("url")
            cfg = {**mc, **cfg}
            self.inventory["mcp_servers"].append(f"{name}: {cmd.strip() or url}")
            if re.search(r"\b(npx|uvx|bunx|pipx\s+run|dlx)\b", cmd):
                pinned = re.search(r"@\d+\.\d+\.\d+|==\d+", cmd)
                if not pinned or "@latest" in cmd:
                    self.add("MCP-UNPINNED-LAUNCH", "MCP server launched from an unpinned registry package", "Medium", "rug-pull",
                             rel, 0, cmd, f"`{name}` is fetched fresh on every start; a later malicious release runs automatically.",
                             "Pin an exact version (pkg@1.2.3) or vendor the server.")
            if url and re.match(r"https?://", str(url)) and not re.match(r"https?://(localhost|127\.0\.0\.1|\[::1\])", str(url)):
                self.add("MCP-REMOTE", "Remote MCP server", "Medium", "data-egress", rel, 0, str(url),
                         f"`{name}` sends tool calls and their data to a third party at {url}; its tools can change server-side at any time.",
                         "Confirm the operator, data processing terms and auth; treat tool descriptions as untrusted.")
                if str(url).startswith("http://"):
                    self.add("MCP-PLAINTEXT", "Remote MCP over plain HTTP", "High", "transport", rel, 0, str(url),
                             "Tool calls and tokens travel unencrypted.", "Require HTTPS.", False)
            env = cfg.get("env") or {}
            for k, v in env.items() if isinstance(env, dict) else []:
                if re.search(r"(TOKEN|SECRET|KEY|PASSWORD)", k) and isinstance(v, str) and not re.match(r"^\$\{?[A-Z_]+\}?$|^<.*>$|^$|^your", v, re.I):
                    self.add("MCP-INLINE-SECRET", "Secret value inline in MCP config", "High", "secret-exposure", rel, 0, f"{k}=****",
                             "A credential is hard-coded in the server config.", "Reference an environment variable instead.")

    def check_workflow(self, text, rel):
        if re.search(r"pull_request_target", text) and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
            self.add("CI-PRT-CHECKOUT", "pull_request_target checks out untrusted PR code", "High", "ci", rel, 0,
                     "pull_request_target + head checkout", "Fork PRs run with the base repo's secrets and write token.",
                     "Use pull_request, or never check out/execute the PR head in pull_request_target.", False)
        m = re.search(r"run:.*\$\{\{\s*github\.event\.(issue|comment|pull_request|review|head_commit)\.[\w.]*(title|body|message|name|label)", text)
        if m:
            self.add("CI-EXPR-INJECTION", "Untrusted event text interpolated into a run step", "Medium", "ci", rel, 0, m.group(0),
                     "Attacker-controlled titles/bodies become shell code.", "Pass via env: and quote the variable.")
        unpinned = re.findall(r"uses:\s*([\w.-]+/[\w.-]+)@(?![0-9a-f]{40})([\w.-]+)", text)
        third = [u for u in unpinned if not u[0].startswith(("actions/", "github/"))]
        if third:
            self.add("CI-UNPINNED-ACTION", "Third-party actions not pinned to a commit SHA", "Low", "ci", rel, 0,
                     ", ".join(f"{a}@{b}" for a, b in third[:5]), "Tags can be moved to malicious commits.", "Pin actions by full SHA.")

    # ---- cross-file
    def post_checks(self):
        down = {"Critical": "Medium", "High": "Low", "Medium": "Low", "Low": "Low", "Informational": "Informational"}
        for f in self.findings:
            if TEST_PATH.search(f.file) and f.category not in {"hidden-content", "install-hook", "permissions"}:
                # Test/fixture code is not shipped to the agent; keep as a reviewer note.
                f.severity, f.blocking = down[f.severity], False
                f.observation += " (in test/fixture code)"
        caps = self.inventory["capabilities"]
        if {"env_secrets", "network"} <= caps and any(f.category in {"credential-access", "obfuscation"} and f.blocking
                                                      for f in self.findings):
            self.add("COMBO-STEALER-SHAPE", "Credential access + obfuscation/network in the same package", "Critical", "exfiltration",
                     Path("."), 0, ", ".join(sorted(caps)),
                     "The package can read secrets and talk to the network, and also shows credential-store access or obfuscation.",
                     "Block and report.", True)
        doms = {d for d in self.inventory["domains"] if d.endswith(SUSPICIOUS_TLDS) or re.match(r"^\d+\.\d+\.\d+\.\d+$", d)}
        if doms:
            self.add("NET-SUSPICIOUS-DOMAIN", "Suspicious domains / raw IPs referenced", "Medium", "data-egress", Path("."), 0,
                     ", ".join(sorted(doms)[:8]), "Low-reputation TLDs or raw IPs are common in droppers and C2 configs.",
                     "Confirm each endpoint's owner.")
        if self.mandate:
            self.check_mandate()

    def check_mandate(self):
        forbidden = {a.lower() for a in self.mandate.get("forbidden_actions", [])}
        caps = self.inventory["capabilities"]
        cap_to_action = {"send_email": {"send_email", "email", "send_mail"},
                         "file_write": {"modify_source_data", "write_files", "modify_evidence"},
                         "network": {"external_network", "call_external_api", "send_data_externally", "exfiltrate"},
                         "shell": {"run_shell", "execute_code", "shell"},
                         "browser_automation": {"browse_web", "scrape_whole_population", "scrape"},
                         "code_eval": {"execute_code"}}
        for cap, actions in cap_to_action.items():
            hit = actions & forbidden
            if cap in caps and hit:
                self.add("MANDATE-CONFLICT", f"Capability `{cap}` conflicts with the agent mandate", "High", "mandate", Path("."), 0,
                         f"forbidden: {', '.join(sorted(hit))}",
                         f"The component can `{cap}`, which the consuming agent's approved mandate forbids ({', '.join(sorted(hit))}). "
                         "Installing it widens what the agent can do without a mandate change PR.",
                         "Do not install, or change the mandate through a pull request first.", True)
        if any(f.category == "persistence" for f in self.findings) and "change_own_config" in forbidden:
            self.add("MANDATE-SELF-CONFIG", "Component edits agent config; mandate forbids change_own_config", "High", "mandate",
                     Path("."), 0, "change_own_config", "The component writes agent configuration, which the mandate forbids.",
                     "Reject.", True)


# --------------------------------------------------------------------------- mandate
def load_mandate(path: str) -> dict:
    """Minimal parser for SAAF agent.yaml mandate blocks (no PyYAML dependency)."""
    text = Path(path).read_text("utf-8")
    out = {"forbidden_actions": [], "allowed_tools": []}
    m = re.search(r"allowed_tools:\s*\[([^\]]*)\]", text)
    if m:
        out["allowed_tools"] = [x.strip() for x in m.group(1).split(",") if x.strip()]
    out["forbidden_actions"] = re.findall(r"-\s*action:\s*([\w-]+)", text)
    return out


# --------------------------------------------------------------------------- output
def verdict_for(findings):
    if any(f.severity == "Critical" or (f.blocking and f.severity in {"High", "Critical"}) for f in findings):
        return "BLOCK"
    if any(f.severity in {"High", "Medium"} for f in findings):
        return "REVIEW"
    return "ALLOW"


def to_markdown(rep: Report) -> str:
    icon = {"ALLOW": "ALLOW", "REVIEW": "REVIEW (human check needed)", "BLOCK": "BLOCK (do not install)"}[rep.verdict]
    out = [f"# SAAF Customs report", "",
           f"- **Target:** {rep.target}", f"- **Resolved:** {rep.resolved}", f"- **Source ref:** `{rep.source_ref}`",
           f"- **Files scanned:** {rep.files_scanned}", f"- **Verdict:** **{icon}**", ""]
    counts = {s: sum(1 for f in rep.findings if f.severity == s) for s in SEVERITIES}
    out.append("| " + " | ".join(SEVERITIES) + " |")
    out.append("|" + "---|" * len(SEVERITIES))
    out.append("| " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |")
    out += ["", "## What it will be able to do", ""]
    inv = rep.inventory
    out.append(f"- Capabilities seen in code: {', '.join(inv['capabilities']) or 'none detected'}")
    for k, label in (("install_scripts", "Install-time code"), ("hooks", "Agent hooks"), ("mcp_servers", "MCP servers"),
                     ("instruction_files", "Instruction files the agent will load"), ("binaries", "Binaries")):
        if inv[k]:
            out.append(f"- {label}:")
            out += [f"  - `{x}`" for x in inv[k][:25]]
    if inv["domains"]:
        out.append(f"- Network endpoints referenced: {', '.join(inv['domains'][:30])}")
    out += ["", "## Findings", ""]
    if not rep.findings:
        out.append("No static findings. Static analysis cannot prove safety; see Limitations in the README.")
    for f in rep.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out += [f"### [{f.severity}] {f.title}{'  (blocking)' if f.blocking else ''}",
                f"- Rule `{f.rule}` · {f.category} · `{loc}`",
                f"- Evidence: `{f.evidence}`" if f.evidence else "",
                f"- {f.observation}", f"- **Fix / decision:** {f.recommendation}", ""]
    return "\n".join(x for x in out if x is not None)


def to_csv(rep: Report, team: str, repo_name: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    w.writerow(["title", "repo", "risk_rating", "observation", "recommendation", "verified", "team"])
    seen = set()
    for f in rep.findings:
        if f.severity == "Informational":
            continue
        k = (f.rule, f.file)
        if k in seen:
            continue
        seen.add(k)
        loc = f"{f.file}:{f.line}" if f.line else f.file
        obs = f.observation if loc in f.observation else f"{f.observation} Location: {loc}."
        w.writerow([f.title[:120], repo_name, f.severity, f"{obs} Source ref {rep.source_ref[:12]}.",
                    f.recommendation, "no", team])
    return buf.getvalue()


def scan(target: str, mandate: str | None = None, keep: bool = False) -> Report:
    q = Path(tempfile.mkdtemp(prefix="saaf-customs-"))
    try:
        root, resolved, ref = fetch(target, q)
        sc = Scanner(root, load_mandate(mandate) if mandate else None)
        sc.run()
        sc.findings.sort(key=lambda f: (SEV_RANK[f.severity], not f.blocking, f.file, f.line))
        inv = {k: (sorted(v) if isinstance(v, set) else v) for k, v in sc.inventory.items()}
        rep = Report(target, resolved, ref, sc.files, sc.findings, inv)
        rep.verdict = verdict_for(sc.findings)
        if keep and str(root).startswith(str(q)):
            rep.inventory["quarantine_path"] = str(root)  # only ever a temp copy, never the user's own directory
        return rep
    finally:
        if not keep:
            shutil.rmtree(q, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="saaf-customs", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="inspect a target")
    s.add_argument("target")
    s.add_argument("--out", help="directory for report.md / findings.json / findings.csv")
    s.add_argument("--mandate", help="SAAF agent.yaml of the agent that would consume this component")
    s.add_argument("--team", default="SAAF Customs", help="team column for the SAAF findings CSV")
    s.add_argument("--repo-name", help="repo column for the CSV (defaults to the target's name)")
    s.add_argument("--keep", action="store_true", help="keep the quarantine copy for manual (LLM) review")
    s.add_argument("--json", action="store_true", help="print JSON to stdout instead of Markdown")
    s.add_argument("--fail-on", choices=["block", "review", "never"], default="block",
                   help="exit non-zero at this verdict (CI). default: block")
    a = ap.parse_args(argv)
    try:
        rep = scan(a.target, a.mandate, a.keep)
    except Exception as e:  # fetch errors etc.
        print(f"saaf-customs: cannot inspect {a.target}: {e}", file=sys.stderr)
        return 3
    repo_name = a.repo_name or re.sub(r"(\.git)?/?$", "", rep.resolved).rstrip("/").split("/")[-1].split(" ")[-1]
    md = to_markdown(rep)
    js = json.dumps({"tool": "saaf-customs", "version": VERSION, **asdict(rep)}, indent=2, default=list)
    if a.out:
        o = Path(a.out)
        o.mkdir(parents=True, exist_ok=True)
        (o / "report.md").write_text(md, "utf-8")
        (o / "findings.json").write_text(js, "utf-8")
        (o / "findings.csv").write_text(to_csv(rep, a.team, repo_name), "utf-8")
    print(js if a.json else md)
    code = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}[rep.verdict]
    if a.fail_on == "never" or (a.fail_on == "block" and code < 2):
        return 0
    return code


if __name__ == "__main__":
    sys.exit(main())
