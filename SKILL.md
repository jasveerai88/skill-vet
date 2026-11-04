# skill-vet — agent skill

Vet an agent skill pack before installing it, with one
command. Use it whenever a task involves a skill from
outside this machine — a marketplace download, a repo
someone linked, a pack a client sent — before the pack
is installed anywhere an agent will load it.

## The one command

```
skill-vet vet <skill-pack-folder> [--json] [--strict]
```

(Installed via `pipx install skill-vet` or `pip install
skill-vet`. From a source checkout, the same command is
`python3 src/skill_vet.py vet <skill-pack-folder> …`.)

- The argument is the pack's root folder (the one
  holding SKILL.md). One pack per run.
- Exit codes: **0** verdict CLEAN or REVIEW, **1**
  verdict BLOCKED (or REVIEW with `--strict`), **2**
  input error (missing folder, not a folder, bad
  arguments). In `--json` mode every error — including
  argument errors — is one JSON object with an `error`
  key. Never a traceback.
- **Read-only, and it executes nothing.** Vet reads the
  pack as static text: it never imports, runs, shells
  out to, or evaluates anything in the pack. Its own
  source imports no network or subprocess module. Safe
  to point at a pack you actively distrust.

## The danger model (the whole product)

A pack is DANGEROUS only if it does one of three
things — the owner's standing rule (2026-10-30),
applied exactly:

1. **STEALS** — reads credential stores, browser
   profiles, SSH keys, or environment secrets AND
   sends or copies the results out.
2. **SPIES** — captures screen, keyboard, microphone,
   camera, or browser history AND persists or sends
   the capture, without the docs disclosing the
   capture.
3. **SENDS IN SECRET** — network calls whose payload
   or destination is concealed: an encoded payload to
   an undisclosed endpoint, local file contents sent
   to an undisclosed endpoint, a send combined with
   writes outside the pack, or any send at all from a
   pack whose docs claim it works offline.

**A pattern hit alone is never a danger verdict.**
Each test needs its combination of evidence *in the
same file*, and the finding cites both halves with
file and line. Anything short of a combination is a
warning with the evidence stated. The combinations:

| Evidence in one file | Verdict |
|---|---|
| secret read + send, or secret read + copy/move to an outside path | `DANGER_STEALING` (BLOCKED) |
| capture + (send or persistence), capture kind undisclosed in SKILL.md / README.md | `DANGER_SPYING` (BLOCKED) |
| send + encoded payload, endpoint undisclosed or non-literal | `DANGER_HIDDEN_SENDING` (BLOCKED) |
| send + read of files outside the pack, endpoint undisclosed | `DANGER_HIDDEN_SENDING` (BLOCKED) |
| send + write outside the pack, endpoint undisclosed | `DANGER_HIDDEN_SENDING` (BLOCKED) |
| send + docs claim offline / local-only | `DANGER_HIDDEN_SENDING` (BLOCKED) |
| secret read, no egress in the file | `SECRET_ACCESS` (WARN) |
| send to an endpoint the docs never mention, no concealment combo | `UNDISCLOSED_NETWORK` (WARN) |
| send with no literal URL to check | `DYNAMIC_ENDPOINT` (WARN) |
| encoded payload to a DISCLOSED endpoint | `ENCODED_PAYLOAD` (WARN) |
| capture + persistence/send, capture disclosed in the docs | `DISCLOSED_CAPTURE` (WARN) |
| capture, no persistence or send | `CAPTURE_CAPABILITY` (WARN) |

Judgement calls, stated openly:

- Stealing needs no concealment: sending a credential
  to a *documented* endpoint is still stealing — the
  docs admitting it does not make it safe. Disclosure
  only separates spying and hidden-sending from their
  honest counterparts.
- A send already judged as the egress half of a
  STEALING finding in the same file is not counted a
  second time as hidden sending.
- Capture "disclosure" is checked per kind against
  plain words in SKILL.md / README.md (screenshot,
  keystroke, microphone, webcam, browser history, …).
  A pack that captures and says so is a capability to
  accept knowingly, not a spy.
- Egress ingredients are collected per file across all
  its lines, including comments (conservative:
  capability evidence is not dismissed because it sits
  near a comment). Hygiene checks (shell=True, eval,
  download-exec) skip full-line comments — a comment
  mentioning a pattern is documentation, not code.

## The rule table

| Rule | Severity | Basis |
|---|---|---|
| `MISSING_SKILL_MD` | ERROR | No SKILL.md at the pack root (a differently-cased name earns `SKILL_MD_CASE`, WARN, and is used). |
| `FRONTMATTER_MISSING` | ERROR | SKILL.md has no `---` block. |
| `FRONTMATTER_PARSE` | ERROR | A frontmatter line outside the supported subset (see below); the line is cited. |
| `REQUIRED_FIELD` | ERROR | `name` or `description` missing or empty. |
| `NAME_DIR_MISMATCH` | WARN | Normalised frontmatter name ≠ folder name. |
| `NAME_FORMAT` | WARN | Name is not a lowercase kebab-case slug. |
| `BROAD_TOOL_GRANT` | WARN | An `allowed-tools` entry that is `*`, a `Tool(*)` wildcard, or a bare `Bash`. Scoped forms like `Bash(npm run *)` are not flagged. |
| `BROKEN_REFERENCE` | ERROR | A local file referenced from SKILL.md (markdown link or backticked path) or from a script (path literal) does not exist. Resolution tries the referencing file's folder, then the pack root. |
| `REFERENCE_OUTSIDE_PACK` | WARN | A reference resolving outside the pack folder. |
| `LARGE_FILE` | WARN | A file over 1 MiB (1,048,576 bytes). |
| `BUNDLED_BINARY` | WARN | A binary file (known binary extension, or a NUL byte in the first 8 KiB). Binaries cannot be statically vetted. |
| `SYMLINK_OUT` | INFO | A symlink whose target leaves the pack; the target is not scanned. |
| `DANGER_STEALING` | ERROR, danger | The combination table above. |
| `DANGER_SPYING` | ERROR, danger | The combination table above. Capture kinds: screen, keyboard, audio, camera, history (a history store read plus a database read in one file). |
| `DANGER_HIDDEN_SENDING` | ERROR, danger | The combination table above. |
| `SECRET_ACCESS` | WARN | A credential-store / env-secret read with no egress in the same file. Secret sources: `.ssh` / key files, `.aws`, `.gnupg`, `.netrc`, stored-credential files, browser stores and profile folders, `.env` files, env access naming a secret (TOKEN / SECRET / PASSWORD / API_KEY / …), whole-environment reads. |
| `UNDISCLOSED_NETWORK` | WARN | A network call whose endpoint host appears in neither SKILL.md nor README.md. A host counts as disclosed when it — or a parent domain of it — appears as a URL in the docs. |
| `DYNAMIC_ENDPOINT` | WARN | A network call with no literal URL anywhere in the file. |
| `ENCODED_PAYLOAD` | WARN | An encoder's output reaches a send to a disclosed endpoint. "Reaches" is judged by: the encoder call inside the send's call segment, or a variable assigned from an encoder used in the segment. |
| `DISCLOSED_CAPTURE` | WARN | Capture + persistence/send, disclosed per kind. |
| `CAPTURE_CAPABILITY` | WARN | A capture API with no persistence or send in the file. |
| `HYGIENE_SHELL_TRUE` | WARN | `shell=True` / `shell: true` on a code line. |
| `HYGIENE_DYNAMIC_EXEC` | WARN | `eval(` / `exec(` / `os.system(` / `os.popen(` / `__import__(` on a code line. |
| `HYGIENE_DOWNLOAD_EXEC` | WARN | A download piped to a shell (`curl … | sh`, `sh <(curl …)`), or a download and a dynamic exec in the same file. |
| `HYGIENE_OBFUSCATION` | WARN | A base64 blob (120+ chars, mixed case with a digit or `+/`), a hex blob (120+ chars), or a run of 8+ `\xNN` escapes, in a text file. One finding per kind per file. |
| `CONCEALED_UNICODE` | WARN | Invisible characters (zero-width, word joiner, soft hyphen, bidi controls, Unicode tag characters) in a text file; count, first line, and character names cited. A leading BOM is a signature, not concealment, and is ignored. |
| `CONCEALED_BLANK_RUN` | WARN | 50+ consecutive blank lines in a markdown file with content after them. |
| `HIDDEN_COMMENT` | WARN | An HTML comment of 120+ characters in a markdown file. |
| `WRITES_OUTSIDE_PACK` | WARN | A script writes to an absolute, home, or system path (`/tmp`, `/etc`, `~/`, `$HOME`, …). |
| `INSTALL_HOOK` | WARN | A file that runs at install time: `setup.py`, `install.*` / `setup.sh`, a `.pth` file, or a `package.json` with a preinstall/install/postinstall hook. |

Verdicts: **BLOCKED** = at least one danger finding
→ exit 1. **REVIEW** = no danger, but at least one
ERROR or WARN → exit 0 (1 with `--strict`).
**CLEAN** = no ERROR or WARN (INFO may remain) →
exit 0. REVIEW exits 0 on purpose: REVIEW means "a
human should read this", and scripts that gate installs
should fail on danger, not on warnings — `--strict`
exists for those who disagree.

## The frontmatter subset

The parser reads the frontmatter shape skill packs
actually ship: `key: value` scalars (quotes stripped),
`key: [a, b]` inline lists, `key:` followed by `- item`
block lists, and indented continuation lines folded
into the previous scalar. It is deliberately not a
full YAML parser. A line outside the subset is a
`FRONTMATTER_PARSE` error with the line cited — vet
reports what it cannot read rather than guessing.

## Scope of the scan

- Every file in the pack is inventoried with its size.
  `.git` and `__pycache__` directories are skipped.
- Text scanning covers scripts (by extension or
  shebang), markdown, and other text files, up to
  2 MiB per file. Binary files and symlink targets
  outside the pack are inventoried, never scanned.
- References are collected from SKILL.md and from
  script files. References inside other markdown
  files (a references/*.md linking onward) are not
  followed in v1.0.0.
- Disclosure is judged against the pack root's
  SKILL.md and README.md only — the two documents a
  person installing the pack is expected to have read.

## JSON schema (`--json`)

One object:

- `tool`, `version`, `command`
- `pack`: `dir` (as passed), `dirname`, `name`
  (frontmatter name or null), `skill_file`
- `files[]`: `path`, `bytes`, `kind`
  (`script`|`markdown`|`text`|`binary`|`other`),
  `binary`, `scanned`, `symlink_out`
- `findings[]`: `rule`, `severity`
  (`ERROR`|`WARN`|`INFO`), `danger` (bool), `file`
  (or null), `line` (or null), `message`, `fix`
- `summary`: `findings`, `errors`, `warnings`,
  `info`, `danger` — counts that recount exactly
  against `findings`
- `verdict` (`CLEAN`|`REVIEW`|`BLOCKED`),
  `verdict_rule`, `limits`

Findings are sorted deterministically: danger first,
then severity, file, line, rule — the same pack always
produces the same report.

## Deliberate non-goals (honesty)

- **It never executes anything.** No script is run,
  imported, compiled, or shell-parsed; no payload is
  decoded (an encoded blob is reported, not opened).
- **Static patterns are evidence, not proof.** A pack
  that assembles its behaviour at runtime from
  innocuous pieces, splits a combination across two
  files (vet judges combinations per file), or writes
  its social engineering in plain, honest sentences
  can pass. A CLEAN verdict means no pattern fired —
  the README says so, and so does every report.
- **Binaries are out of reach.** A bundled binary is
  flagged precisely because vet can say nothing about
  it.
- **No telemetry, no network, no writes.** Stdlib
  only; the source contains no network or subprocess
  code at all (a test parses its imports and proves
  it).
- **Pattern tables are a snapshot.** New capture
  libraries, new credential stores, and new client
  APIs appear constantly; the tables in the source
  are dated by the release, not treated as complete.
