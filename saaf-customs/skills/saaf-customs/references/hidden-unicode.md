# Hidden Unicode

- **Rule ids:** `UNI-TAG-CHARS`, `UNI-BIDI`, `UNI-ZERO-WIDTH`
- **Guardrail:** yes
- **Sources last checked:** not yet

## Criterion
Every character in a file the agent loads or runs is visible to a human reviewer, and the
order in which text is displayed is the order in which it is stored.

## Why it matters
Some code points render as nothing, or reorder the text around them. A reviewer approves
what the editor shows; the model, interpreter or compiler acts on what is stored. The gap
between the two is where instructions and logic are hidden.

## What triggers it
| Rule | Fires when | Default severity | Blocking |
|---|---|---|---|
| `UNI-TAG-CHARS` | any code point in the Tags block (U+E0000 to U+E007F) | Critical | yes |
| `UNI-BIDI` | any bidirectional embedding, override or isolate control (U+202A to U+202E, U+2066 to U+2069) | High | no |
| `UNI-ZERO-WIDTH` | zero-width or invisible format characters (for example U+200B, U+200C, U+200D, U+2060, U+FEFF, U+00AD) | Medium | no |

In instruction files and MCP tool-definition code, `UNI-BIDI` becomes Critical and
`UNI-ZERO-WIDTH` becomes High, and both become blocking. Outside those files, fewer than
three zero-width characters in a file are ignored.

## Guardrail: what the user is asked to check
The skill shows the file, the line of the first occurrence, the count, and for tag characters
the ASCII text they decode to. The user answers:
1. Is there any reason for this file to contain characters that do not render?
2. For tag characters: does the decoded text read as an instruction or a value? It is shown as
   data; nobody acts on it.
3. For bidi controls: does the line read the same with the controls made visible?

## Legitimate uses and false positives
- A single byte-order mark at the start of a file.
- Zero-width joiners inside emoji sequences and in scripts that need them (for example Persian,
  Indic scripts).
- Bidi controls in genuinely right-to-left prose. They have no place in code, identifiers or
  instruction files written in a left-to-right language.
- Soft hyphens in copied prose.

Tag characters have no legitimate use in instruction files or source code.

## Decision
- **Continue** when the characters are explained by the list above and sit in prose.
- **REVIEW** when they are unexplained but sit outside anything the agent loads or runs.
- **BLOCK** when they appear in an instruction file, tool description, hook or code path, or
  when tag characters appear anywhere.

## Not covered
Variation selectors, other default-ignorable code points outside the lists above, and text
hidden by rendering rather than encoding (HTML comments are a separate rule, `PI-HTML-COMMENT`;
styling tricks in HTML are not checked).

## External references
- Unicode UAX #9, Unicode Bidirectional Algorithm: defines the controls `UNI-BIDI` looks for.
  https://www.unicode.org/reports/tr9/
- Unicode UTS #39, Unicode Security Mechanisms: invisible and default-ignorable characters as a
  security concern. https://www.unicode.org/reports/tr39/
- Unicode UTR #36, Unicode Security Considerations. https://www.unicode.org/reports/tr36/
- Trojan Source (CVE-2021-42574): bidi controls that make source display differently from how
  it compiles. https://trojansource.codes/
- CWE-506, Embedded Malicious Code.
- MITRE ATT&CK T1027, Obfuscated Files or Information.
- OWASP Top 10 for LLM Applications, LLM01 Prompt Injection: hidden text is one delivery form of
  indirect injection.
