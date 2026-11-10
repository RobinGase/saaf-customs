# Unexpected upstream network (egress)

- **Rule ids:** `NET-UNDECLARED-EGRESS`, `NET-EGRESS-INVENTORY`, `NET-SUSPICIOUS-DOMAIN`,
  `EXFIL-KNOWN-SINK`, `MCP-REMOTE`
- **Guardrail:** yes
- **Sources last checked:** not yet

## Criterion
Every host the component can contact is known, is needed for what the component says it does,
and is acceptable for the data the consuming agent handles.

## Why it matters
A component that runs inside an agent sees what the agent sees. Any outbound connection is a
path for that data to leave, and a path for instructions or code to arrive after the review.
For SAAF, audit evidence leaving the machine to an unapproved party is a finding in itself.

## What triggers it
| Rule | Fires when | Default severity | Blocking |
|---|---|---|---|
| `NET-UNDECLARED-EGRESS` | an allowlist is declared and a host in code or an instruction file is not on it | High | yes |
| `NET-EGRESS-INVENTORY` | no allowlist is declared and code or instruction files reference at least one host | Low | no |
| `NET-SUSPICIOUS-DOMAIN` | any referenced host is a raw IP address or sits under a low-reputation top-level domain | Medium | no |
| `EXFIL-KNOWN-SINK` | a reference to a throwaway webhook, paste, tunnel or chat-webhook service | High | yes (not in prose docs) |
| `MCP-REMOTE` | an MCP config points at a non-local server URL | Medium | no |

The allowlist comes from `--allow-host HOST` (repeatable) and from `allowed_hosts: [..]` in the
consuming agent's `agent.yaml`. An entry covers the host and its subdomains. An empty
`allowed_hosts` list means no egress is expected. Hosts are collected from code files and
instruction files; prose documentation and manifests are inventoried under "Network endpoints
referenced" but do not count as egress. Loopback addresses and a short list of licence and
schema-namespace hosts are ignored.

## Guardrail: what the user is asked to check
The skill shows each host with the first file:line that references it. The user answers, per host:
1. Is this host expected for the component's stated purpose?
2. Who operates it, and is that an approved processor for the data this agent handles?
3. What goes out (tool arguments, file contents, environment) and what comes back (data, or
   instructions and code)?

Hosts the user confirms are added with `--allow-host` or to the mandate, and the scan is run
again so the result is recorded against a declared list.

## Legitimate uses and false positives
- The API the component exists to call.
- Links in comments and docstrings that the code never contacts.
- Package registries and source hosts named in install instructions.

## Decision
- **Continue** when every host is expected, attributed and acceptable for the data.
- **REVIEW** when a host is plausible but unconfirmed, or a remote MCP server is involved:
  its behaviour can change after review.
- **BLOCK** when a host is outside the declared allowlist and unexplained, is a throwaway sink
  or tunnel, or receives credentials, environment or audit evidence.

## Not covered
- Hosts built at run time, read from configuration or the environment, or resolved through
  another service (for example a value fetched from a public blockchain or a paste).
- Egress by transitive dependencies, which are not resolved.
- Non-HTTP channels: DNS lookups built from data have their own rule (`EXFIL-DNS`); raw
  sockets and other protocols are only visible as the `network` capability.
- What a remote server does with the data. Static review cannot see it.

## External references
- MITRE ATT&CK T1041, Exfiltration Over C2 Channel.
- MITRE ATT&CK T1567, Exfiltration Over Web Service.
- MITRE ATT&CK T1071, Application Layer Protocol.
- MITRE ATT&CK T1102, Web Service (including dead-drop resolvers).
- MITRE ATT&CK T1195.002, Compromise Software Supply Chain.
- CWE-829, Inclusion of Functionality from Untrusted Control Sphere: code or instructions
  loaded from a remote host at run time.
- OWASP Top 10 for LLM Applications: LLM02 Sensitive Information Disclosure, LLM03 Supply Chain.
