# SAAF Customs

**Nothing enters a SAAF agent's toolchain without inspection.**

A Claude skill and CI check that inspects a third-party **skill, plugin, MCP server, npm/PyPI package or repo
before you install it**. It returns **ALLOW / REVIEW / BLOCK** with file:line evidence and exports findings in the SAAF CSV format.
It is modelled on [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill): a deterministic scan first, then an LLM review, then validation of every hit.

## Install
```bash
cp -R skills/saaf-customs ~/.claude/skills/        # or .claude/skills/ in a repo
```

## Use
In Claude Code:
```
/saaf-customs https://github.com/someone/cool-mcp-server
is npm:some-mcp@1.2.0 safe to install?
```
Scanner only (Python 3.9+, no dependencies):
```bash
python3 -I skills/saaf-customs/scripts/customs.py scan <target> --out reports/x [--mandate agent.yaml] [--allow-host api.example.com]
# <target>: ./path | https://github.com/o/r[/tree/ref/sub] | github:o/r@ref | npm:pkg@ver | pypi:pkg==ver
# exit 0 ALLOW · 2 BLOCK (--fail-on review to also fail on REVIEW) · 3 fetch error
```
Writes `report.md`, `findings.json` and `findings.csv` (`title,repo,risk_rating,observation,recommendation,verified,team`).

**CI:** copy `.github/workflows/saaf-customs.yml` and `skills/saaf-customs/` into any SAAF repo. PRs that touch `.claude/`,
`.mcp.json`, `SKILL.md`, dependency manifests or `agent.yaml` fail on BLOCK.

## What it checks
- **Prompt injection / tool poisoning:** override phrasing, "don't tell the user", fake `<IMPORTANT>`/`<system>` tags, hidden HTML comments, cross-tool shadowing
- **Hidden Unicode and homoglyphs:** tag-character smuggling (decoded in the report), bidi overrides, zero-width runs, look-alike letters mixed into ASCII words, punycode hosts
- **Code that runs without asking:** npm install scripts, `setup.py` cmdclass, Claude Code hooks; shipped `settings.json` that widens permissions
- **Exfiltration, credential theft, persistence:** env sent to the network, `~/.ssh`/`~/.aws`/keychain reads, webhook/tunnel sinks, writes to `~/.claude`/`CLAUDE.md`/shell rc
- **Obfuscation:** `eval(atob(...))`, `exec(b64decode(...))`, marshal, char-code strings, base64 strings that decode to readable text (preview in the report)
- **Unexpected upstream network:** every host in code and instruction files, checked against `--allow-host` / the mandate's `allowed_hosts`
- **MCP and supply chain:** `npx pkg@latest` rug pulls, remote/HTTP MCP, inline secrets, typosquats, unpinned deps, binaries, escaping symlinks, risky workflows
- **SAAF mandate fit:** detected capabilities checked against the consuming agent's `agent.yaml` `forbidden_actions`

Claude then reads every instruction file, hook, install script and MCP tool in full, and checks whether behaviour matches the description
([CHECKS.md](skills/saaf-customs/CHECKS.md)). It confirms or drops each scanner hit.

**Guardrail triggers.** Hidden Unicode, homoglyphs, encoded strings and unexpected upstream network stop the review until
the user has checked the evidence. Each has a high-level criterion reference in
[skills/saaf-customs/references/](skills/saaf-customs/references/), written from a shared template.

## Safety model
The target is never installed, built, imported or run. Clones disable git hooks, symlinks and submodules.
Registry tarballs are downloaded through the API and unpacked with traversal protection. The scanner runs under `python3 -I`.
All target content is treated as data, and text that tries to instruct the reviewer is itself reported.

## Results on SAAF-Project (10 Nov 2026)
13 repos scanned → 4 validated findings in [findings/saaf-findings.csv](findings/saaf-findings.csv):

| Repo | Finding | Risk |
|---|---|---|
| saaf-portal | Shell command injection via signup `githubUsername` in `scripts/process-signups.ts:66` | High |
| saaf-portal | Members told to install an unpinned skill from `main` straight into `~/.claude/skills` | Medium |
| Executive-Summary-Writer | Unauthenticated `POST /configuration` swaps the Anthropic key, and the service binds to `0.0.0.0` | Medium |
| SAAF-circuit-breaker | Live app served from a developer Mac through a temporary `trycloudflare.com` tunnel | Medium |

## Tests
```bash
python3 -I -m unittest discover -s tests
```
The fixtures are inert malicious samples: a poisoned skill, an exfiltrating plugin hook, a credential-stealing MCP server and a typosquatting npm dropper. There is also a clean skill that must return ALLOW.

## Limitations
- This is static analysis and cannot prove safety. Novel obfuscation, logic bombs and the server-side behaviour of remote MCPs can be missed.
- Transitive dependencies are not resolved, because nothing is installed.
- Regex rules produce false positives. Tests and docs are downgraded automatically, and the skill's validation step removes the rest. Raw hits are `verified=no`.
- A verdict is valid only for the reported `source_ref`. Install exactly that commit or version.
