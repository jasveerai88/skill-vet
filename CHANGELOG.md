# Changelog

## v1.0.0 — 2026-11-04

The checks are unchanged from v0.1.0 — this release is
about being installable and readable as a product:

- **Packaged install.** `pyproject.toml` (setuptools,
  single-module layout) — `pip install skill-vet` /
  `pipx install skill-vet` now put a `skill-vet`
  console command on PATH. `python3 src/skill_vet.py`
  from a checkout keeps working, unchanged.
- **README rebuilt as a landing page:** one-line hook,
  badge row, an animated demo (a clean pack passes; a
  hostile pack is BLOCKED with all three danger
  findings), a 20-second quickstart, a what-it-catches
  table with the fixture examples, and a comparison
  table against per-file linters and installing blind.
  The full reference — rule summary and verbatim
  fixture reports — moved below the fold.
- **Demo + social assets** in `docs/`: `demo.gif`
  (rendered from real v1.0.0 output) and
  `social-preview.png` (1280×640).
- **Community files:** SECURITY.md and issue templates
  added; CONTRIBUTING and FUNDING unchanged.
- Version string is now 1.0.0 everywhere (tool header,
  `--json` output, package metadata). All 44 tests pass
  unmodified.

## v0.1.0 — 2026-11-04

First release. Statically vets one agent skill pack —
without executing anything in it — and reports:

- the full file inventory (path, kind, size), with
  `LARGE_FILE` (over 1 MiB) and `BUNDLED_BINARY`
  warnings and `SYMLINK_OUT` notes for symlinks whose
  targets leave the pack (targets are not scanned);
- structure checks on SKILL.md: frontmatter presence
  and parse (a stated YAML subset), the required
  `name` / `description` fields, name-vs-folder match,
  kebab-case name shape, `SKILL_MD_CASE`, and
  `BROAD_TOOL_GRANT` for wildcard `allowed-tools`
  entries (`*`, `Tool(*)`, bare `Bash`);
- `BROKEN_REFERENCE` for local files referenced from
  SKILL.md (links and backticked paths) or from
  scripts (path literals) that do not exist, and
  `REFERENCE_OUTSIDE_PACK` for references that resolve
  outside the pack;
- the three danger tests, each proven only by its
  combination of evidence in the same file:
  `DANGER_STEALING` (credential-store / env-secret
  read + send or copy-out), `DANGER_SPYING` (screen /
  keyboard / audio / camera / history capture +
  persistence or send, undisclosed in the docs), and
  `DANGER_HIDDEN_SENDING` (encoded payload, outside
  file contents, or outside writes sent to an
  undisclosed endpoint — or any send under an
  offline / local-only claim in the docs);
- the short-of-danger warnings the combinations rest
  on: `SECRET_ACCESS`, `UNDISCLOSED_NETWORK`,
  `DYNAMIC_ENDPOINT`, `ENCODED_PAYLOAD`,
  `DISCLOSED_CAPTURE`, `CAPTURE_CAPABILITY`;
- hygiene and concealment warnings:
  `HYGIENE_SHELL_TRUE`, `HYGIENE_DYNAMIC_EXEC`,
  `HYGIENE_DOWNLOAD_EXEC`, `HYGIENE_OBFUSCATION`
  (base64 / hex blobs, `\x` escape runs),
  `CONCEALED_UNICODE` (invisible characters, cited by
  name), `CONCEALED_BLANK_RUN`, `HIDDEN_COMMENT`,
  `WRITES_OUTSIDE_PACK`, `INSTALL_HOOK`.

Verdicts: BLOCKED (any danger finding, exit 1),
REVIEW (errors or warnings, exit 0 — 1 with
`--strict`), CLEAN (exit 0). Read-only by
construction and by test (fixture trees verified
byte-identical after runs; a booby-trapped fixture
script's marker file never appears; the source's
imports are pinned to a stdlib set with no network
or subprocess module). `--json` everywhere,
`{"error": ...}` input errors including argument
errors, exits 1 / 0 / 2. Python 3.10+ standard
library only; no network code.
