# <Criterion name>

> Template for a SAAF Customs criterion reference. Copy to `references/<slug>.md`, fill every
> section, add the rule ids to `GUARDRAILS` in `scripts/customs.py`, and add a row to the table
> in `CHECKS.md` section G. Keep it high level: describe what is checked and how a person
> confirms it. No working payloads, no step-by-step attack instructions, no live indicators.

- **Rule ids:** `<RULE-ID>`, ...
- **Guardrail:** yes / no (yes = the review stops and the user checks before it continues)
- **Sources last checked:** <YYYY-MM-DD, or "not yet">

## Criterion
One or two sentences: what must be true of a component for it to pass.

## Why it matters
What a reviewer or agent gets wrong when this is present. One short paragraph.

## What triggers it
| Rule | Fires when | Default severity | Blocking |
|---|---|---|---|
| `<RULE-ID>` | deterministic condition, in words | Low / Medium / High / Critical | yes / no |

State where severity changes (instruction files, tool descriptions, code, prose docs).

## Guardrail: what the user is asked to check
What the skill shows the user (file:line, escaped evidence, decoded preview) and the
questions the user answers before the review continues.

## Legitimate uses and false positives
When this appears in honest components, and what distinguishes those cases.

## Decision
- **Continue** when ...
- **REVIEW** when ...
- **BLOCK** when ...

## Not covered
What the deterministic check cannot see and the semantic review has to pick up.

## External references
Standards, weakness classes and technique ids only. One line each, with the reason it applies.
