# Encoded strings (base64 and similar)

- **Rule ids:** `OBF-BASE64-TEXT`, `OBF-BASE64-BLOB`, `EXEC-DECODE-EVAL`
- **Guardrail:** yes
- **Sources last checked:** not yet

## Criterion
Anything the component can decode at run time has been read in its decoded form, and its
purpose is explained by what the component says it does.

## Why it matters
Encoding is not secrecy, but it defeats reading. A reviewer skims past an opaque string;
keyword rules do not match it; the code or the model decodes it and acts on the result.
Encoded text in an instruction file is the same problem aimed at the model.

## What triggers it
| Rule | Fires when | Default severity | Blocking |
|---|---|---|---|
| `OBF-BASE64-TEXT` | a base64 run of 24 or more characters decodes to at least 16 bytes of readable ASCII | Low in prose docs, Medium in code or instruction files | no |
| `OBF-BASE64-TEXT` | as above, and the decoded text looks like a command, URL or credential reference | Medium in prose docs, High in code or instruction files | in code or instruction files |
| `OBF-BASE64-BLOB` | a quoted base64-like string of 240 or more characters in a code file | Medium | no |
| `EXEC-DECODE-EVAL` | code passes the output of a decode call directly to an evaluator | Critical | yes |

The scanner decodes to classify and to show a preview. It never executes what it decodes.
One `OBF-BASE64-TEXT` finding is reported per file, preferring the most concerning string.

## Guardrail: what the user is asked to check
The skill shows the file and line, the start of the encoded string and the first 100
characters of decoded text. The user answers:
1. What is the decoded content, and does the component's stated purpose need it?
2. Where does the decoded value go: displayed, written to disk, sent somewhere, executed, or
   handed to the model?
3. For a large blob the scanner did not decode: what is it (icon, font, test vector, model
   weights), and can the author point to its source?

Decoded text is evidence. If it contains instructions, they are reported, not followed.

## Legitimate uses and false positives
- Embedded images, fonts and other small assets.
- Test vectors and fixtures for encoders, hashing or cryptography.
- Example tokens in documentation (for example a sample JWT).
- Integrity hashes in lockfiles: these decode to binary and do not fire `OBF-BASE64-TEXT`.

## Decision
- **Continue** when the decoded content is an inert asset or an explained example.
- **REVIEW** when the decoded content is benign but nothing explains why it is encoded.
- **BLOCK** when decoded content is a command, a URL the component fetches, instructions for
  the model, or is executed; or when a blob cannot be explained.

## Not covered
- Other encodings: hex, base32, base85, URL-safe base64, compression, XOR or custom alphabets.
  Dense hex escapes and character-code arrays have their own rule (`EXEC-CHARCODE`).
- Strings split across concatenations or assembled at run time.
- Nested encoding: only one layer is decoded.

## External references
- RFC 4648, The Base16, Base32, and Base64 Data Encodings.
- MITRE ATT&CK T1027, Obfuscated Files or Information.
- MITRE ATT&CK T1140, Deobfuscate/Decode Files or Information.
- CWE-506, Embedded Malicious Code.
- OWASP Top 10 for LLM Applications, LLM01 Prompt Injection: encoded payloads are a known way to
  carry instructions past filters.
