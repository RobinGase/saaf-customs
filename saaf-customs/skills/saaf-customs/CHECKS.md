# SAAF Customs - review checklist

Use after the deterministic scan. Answer each item for the target; cite file:line.

## A. Identity and provenance
- Who publishes it? Does the repo/package owner match the claimed author? Is the package
  name one edit away from a popular one (typosquat)?
- Is the version you reviewed the one that will be installed (commit SHA / exact version)?
- Do the published artefact (npm tarball / wheel) and the GitHub source match? Packages
  can ship files that are not in the repo.

## B. Instruction surfaces (skills, agents, commands, CLAUDE.md, tool descriptions)
- Any instruction to override, ignore or outrank other instructions?
- Any instruction to hide actions, avoid telling the user, or act "silently"?
- Fake platform tags (`<IMPORTANT>`, `<system>`, `[INST]`), HTML comments with directives,
  invisible Unicode (tag chars U+E0000-E007F, zero-width, bidi overrides)?
- Does a tool description reference other tools, files (`~/.ssh`, `.env`, `mcp.json`) or ask
  for extra parameters that carry data (e.g. a `notes`/`context` field that should contain
  "the full conversation")?
- Does the skill tell the agent to run shell commands, especially `curl | sh`, package installs
  or commands without confirmation?
- Does it load further instructions from a URL at runtime?

## C. Code that runs automatically
- npm `preinstall`/`install`/`postinstall`, `setup.py` cmdclass, in-tree build backends.
- Claude Code plugin hooks (`hooks/hooks.json`, `.claude/settings.json` `hooks`), especially
  `SessionStart`, `UserPromptSubmit`, `PreToolUse`: read the script each one calls.
- Shipped `settings.json` that pre-approves tools (`Bash(*)`, `Write`, `mcp__*`) or sets
  `bypassPermissions` / `enableAllProjectMcpServers`.

## D. Runtime behaviour of MCP servers and scripts
- Description vs behaviour: list what each tool actually does (files read/written, commands,
  network calls).
- Command injection: do tool arguments reach a shell (`shell=True`, `exec`, template strings)?
- Path traversal: can a tool argument read/write outside an allowed root?
- SSRF: can a tool argument choose the URL fetched?
- Secrets: which env vars are read; are they ever logged, returned to the model or sent out?
- Egress: every outbound host; is any of it a paste site, webhook catcher, tunnel or raw IP?
- Persistence/tampering: writes to `~/.claude`, `CLAUDE.md`, shell rc files, cron, launchd.

## E. Supply chain
- Unpinned / git / URL dependencies, custom package indexes.
- Binaries, `.pyc`, minified bundles without source.
- `npx pkg@latest` / unpinned `uvx` launches in MCP configs (rug pull on every start).
- CI workflows: `pull_request_target` + head checkout, expression injection, unpinned actions.

## F. SAAF-specific
- **Evidence integrity:** can it modify source data, workpapers or audit trails?
  (SAAF mandates commonly forbid `modify_source_data`.)
- **Auditee data egress:** does any auditee document or PII leave the machine, and to whom?
- **Mandate fit:** compare with the consuming agent's `agent.yaml`: `forbidden_actions`,
  `allowed_tools`, `trusted_inputs`, `human_approval_required_for`.
- **Auditee documents as data:** if the component feeds documents to a model, does it mark
  them as untrusted data, or can a crafted document instruct the agent?

## G. Guardrail triggers (the user checks before the review continues)
Each has a criterion reference: what triggers it, what the user is asked, and how to decide.
New criteria start from [references/_TEMPLATE.md](references/_TEMPLATE.md).

| Criterion | Rules | Reference |
|---|---|---|
| Hidden Unicode | `UNI-TAG-CHARS`, `UNI-BIDI`, `UNI-ZERO-WIDTH` | [hidden-unicode.md](references/hidden-unicode.md) |
| Homoglyphs | `UNI-HOMOGLYPH`, `UNI-IDN-HOST` | [homoglyphs.md](references/homoglyphs.md) |
| Encoded strings | `OBF-BASE64-TEXT`, `OBF-BASE64-BLOB`, `EXEC-DECODE-EVAL` | [encoded-strings.md](references/encoded-strings.md) |
| Unexpected upstream network | `NET-UNDECLARED-EGRESS`, `NET-EGRESS-INVENTORY`, `NET-SUSPICIOUS-DOMAIN`, `EXFIL-KNOWN-SINK`, `MCP-REMOTE` | [unexpected-egress.md](references/unexpected-egress.md) |

- Did the user answer every trigger, and is each answer recorded in the report?
- Homoglyphs: any word written wholly in another script that reads as an ASCII name? The
  scanner only catches mixed-script words.
- Encoded strings: anything encoded another way (hex, base32, compressed, split across
  concatenations)?
- Egress: any host built at run time or read from config that the static list cannot show?

## Severity guide
| Rating | Example |
|---|---|
| Critical | Credential theft, env exfiltration, invisible-unicode instructions, decode+eval payload |
| High | Install/session hooks with network, agent-config writes, permission widening, tool poisoning, mandate conflict |
| Medium | shell=True on tool input, unpinned `npx` MCP launch, remote MCP, TLS off, binaries |
| Low | Unpinned deps, unpinned CI actions, bind to 0.0.0.0 |
| Informational | Capability inventory notes |
