# Homoglyphs (look-alike characters)

- **Rule ids:** `UNI-HOMOGLYPH`, `UNI-IDN-HOST`
- **Guardrail:** yes
- **Sources last checked:** not yet

## Criterion
Names a reviewer relies on (identifiers, package names, host names, file paths, keywords in
instructions) are written in the characters they appear to be written in.

## Why it matters
Letters from different scripts can render identically. A name that looks like a trusted
package, host or function can be a different string. The reviewer reads one name; the
resolver, interpreter or model compares another. Look-alike letters also let text slip past
keyword rules, including the rules in this scanner.

## What triggers it
| Rule | Fires when | Default severity | Blocking |
|---|---|---|---|
| `UNI-HOMOGLYPH` | one word mixes ASCII letters with letters that imitate ASCII letters: a curated set of Cyrillic and Greek letters, plus any letter that Unicode compatibility normalisation (NFKC) folds to a single ASCII letter, such as fullwidth and mathematical forms | Medium | no |
| `UNI-IDN-HOST` | a URL whose host contains non-ASCII characters or a punycode (`xn--`) label | Medium | no |

`UNI-HOMOGLYPH` is High and blocking in code, instruction files and MCP tool-definition code.
A word counts only when every non-ASCII letter in it is a look-alike, so accented words in
ordinary prose do not fire.

## Guardrail: what the user is asked to check
The skill shows the file and line, the word with non-ASCII letters written as `\uXXXX`
escapes, the ASCII word it reads as, and the number of such words in the file. For a host it
shows the escaped form and, for punycode, what it displays as. The user answers:
1. Is the word meant to be the ASCII word it reads as? If so, why is it not written in ASCII?
2. Is it a name something resolves or compares (package, host, path, identifier, tool name)?
3. For a host: who owns the real code-point name, and is that who the component claims to talk to?

## Legitimate uses and false positives
- Product or personal names that deliberately mix scripts in prose.
- Internationalised domain names for organisations that really use them.
- Mathematical letters in formulas inside documentation.

None of these belong in an identifier, a dependency name or an instruction keyword.

## Decision
- **Continue** when the word is prose, is not a name anything resolves, and the user recognises it.
- **REVIEW** for an internationalised host the user can attribute to a known owner.
- **BLOCK** when the look-alike is in an identifier, dependency, host, path or instruction
  keyword, or the user cannot explain it.

## Not covered
- Whole-script look-alikes: a word written entirely in another script that happens to read as
  an ASCII word. Deterministic detection would flag ordinary words in that script, so this is a
  semantic-review item.
- ASCII-only confusion (for example digit one, lowercase L and capital I; `rn` and `m`).
  Package names one edit from a popular name are covered by `DEP-TYPOSQUAT`.
- The look-alike table is a subset. Scripts beyond Cyrillic and Greek are only caught through
  NFKC folding.

## External references
- Unicode UTS #39, Unicode Security Mechanisms: confusables data, skeleton comparison and
  mixed-script detection. The scanner's table is a subset of that data.
  https://www.unicode.org/reports/tr39/
- Unicode UTR #36, Unicode Security Considerations: visual spoofing. https://www.unicode.org/reports/tr36/
- RFC 5890 (IDNA) and RFC 3492 (Punycode): how internationalised host names are encoded.
- Trojan Source (CVE-2021-42694): homoglyph identifiers in source code. https://trojansource.codes/
- CWE-1007, Insufficient Visual Distinction of Homoglyphs Presented to User.
- MITRE ATT&CK T1036, Masquerading.
