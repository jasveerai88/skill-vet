#!/usr/bin/env python3
"""skill-vet — a static, read-only pre-install audit of an
agent skill pack: does its SKILL.md parse, do the files it
references exist, and do its bundled scripts steal, spy, or
send in secret — found before you install it, not after.

Pure Python standard library. READ-ONLY and local only: it
reads the skill folder you point it at, edits nothing,
writes nothing, and NEVER executes anything in the pack —
every file is analysed as static text. The test suite
proves the claim: a fixture script that would write a
marker file if it ran never runs, and every fixture tree
comes out byte-identical after an audit.

A skill pack runs with your agent's permissions the
moment it is installed. Per-file linters check the
SKILL.md's formatting; nobody vets the whole directory —
the frontmatter, the referenced files, and above all the
scripts. The marketplace numbers say why this matters
(Snyk's ToxicSkills audit, Feb 2026: 1,467 of 3,984
marketplace skills carried malicious payloads; VirusTotal
analysed 35,878 skills and found 6,637 malicious, most of
them hiding the payload in plain sentences or concealment
mechanics rather than obvious malware).

THE DANGER MODEL (the owner's standing rule, 2026-10-30,
applied exactly): a pack is DANGEROUS only if it

  1. STEALS — reads credential stores, browser profiles,
     SSH keys or environment secrets AND sends or copies
     the results out;
  2. SPIES — captures screen, keyboard, microphone,
     camera or browser history AND persists or sends the
     capture, without disclosing the capture in its docs;
  3. SENDS IN SECRET — makes network calls whose payload
     or destination is concealed: an encoded payload, the
     contents of local files sent to an undisclosed
     endpoint, or any send at all from a pack whose docs
     claim it works offline.

A pattern hit alone is NEVER a danger verdict. Each test
needs its combination of evidence in the same file, and
the finding cites both halves (file + line for each).
Anything short of a combination is a warning with the
evidence stated: an undisclosed endpoint on its own is
UNDISCLOSED_NETWORK, a credential read with no egress is
SECRET_ACCESS, a capture API with no persistence or send
is CAPTURE_CAPABILITY. Scanner scores are context, never
a block by themselves; BLOCKED is reserved for a proven
three-test combination.

THE RULES (v1.0.0):

  Structure (the pack as a document):
  MISSING_SKILL_MD (ERROR) — no SKILL.md at the pack
    root. SKILL_MD_CASE (WARN) — present, but under a
    differently-cased name some loaders will miss.
  FRONTMATTER_MISSING (ERROR) — SKILL.md has no ---
    frontmatter block. FRONTMATTER_PARSE (ERROR) — a
    frontmatter line the subset parser cannot read (the
    line is cited). REQUIRED_FIELD (ERROR) — `name` or
    `description` missing or empty.
  NAME_DIR_MISMATCH (WARN) — normalised frontmatter name
    differs from the folder name. NAME_FORMAT (WARN) —
    the name is not a lowercase kebab-case slug.
  BROAD_TOOL_GRANT (WARN) — an allowed-tools entry that
    grants a whole tool (`*`, `Bash(*)`, a bare `Bash`, …).
  BROKEN_REFERENCE (ERROR) — a local file referenced
    from SKILL.md (link or backticked path) or from a
    script (path literal) does not exist.
    REFERENCE_OUTSIDE_PACK (WARN) — a reference that
    resolves outside the pack folder.
  LARGE_FILE (WARN) — a file over 1 MiB in a pack that
    ships as text. BUNDLED_BINARY (WARN) — a binary file:
    it cannot be statically vetted at all.
  SYMLINK_OUT (INFO) — a symlink whose target leaves the
    pack; its target is not scanned.

  The three danger tests (ERROR severity, danger class;
  any one of them makes the verdict BLOCKED):
  DANGER_STEALING — secret-source read + (network send
    or copy/move out of the pack) in the same file.
  DANGER_SPYING — capture (screen / keyboard / audio /
    camera / history) + (send or persistence) in the
    same file, with the capture kind undisclosed in
    SKILL.md / README.md.
  DANGER_HIDDEN_SENDING — network send + concealment in
    the same file: an encoded payload sent to an
    undisclosed (or non-literal) endpoint, local file
    contents read from outside the pack and sent to an
    undisclosed endpoint, a send combined with writes
    outside the pack to an undisclosed endpoint, or any
    send at all while the docs claim the pack works
    offline / local-only. (An encoded payload to a
    DISCLOSED endpoint is ENCODED_PAYLOAD, a warning:
    the destination is honest, the payload opaque.)

  Short-of-danger security warnings (WARN):
  SECRET_ACCESS — reads credential stores / env secrets,
    no egress found in that file. UNDISCLOSED_NETWORK —
    a network call whose endpoint appears nowhere in
    SKILL.md / README.md, with no concealment combo.
  DYNAMIC_ENDPOINT — a network call with no literal URL
    to check against the docs. ENCODED_PAYLOAD — an
    encoded payload sent to a DISCLOSED endpoint (the
    destination is honest; what is sent is opaque).
  DISCLOSED_CAPTURE — capture + persistence/send, but
    the capture kind IS disclosed in the docs.
  CAPTURE_CAPABILITY — a capture API present with no
    persistence or send found.

  Hygiene (WARN):
  HYGIENE_SHELL_TRUE — subprocess with shell=True.
  HYGIENE_DYNAMIC_EXEC — eval / exec / os.system /
    os.popen / __import__ on computed values.
  HYGIENE_DOWNLOAD_EXEC — downloaded content executed:
    `curl … | sh`, or a download and an exec in one file.
  HYGIENE_OBFUSCATION — a long base64 blob, a long hex
    blob, or a run of \\x escapes in a text file.
  CONCEALED_UNICODE — invisible characters (zero-width,
    bidi controls, Unicode tag characters, soft hyphens)
    in a text file, cited by name.
  CONCEALED_BLANK_RUN — 50+ consecutive blank lines in a
    markdown file with content after them.
  HIDDEN_COMMENT — an HTML comment of 120+ characters in
    a markdown file.
  WRITES_OUTSIDE_PACK — a script writes to a path
    outside the pack (absolute, home, /tmp, …).
  INSTALL_HOOK — a file that runs at install time
    (setup.py, a .pth file, an install script, a
    package.json install hook): review it first.

VERDICT (printed on every report):
  BLOCKED — at least one DANGER_* finding (a proven
    three-test combination). Exit 1.
  REVIEW — no danger finding, but at least one ERROR or
    WARN. Exit 0 (exit 1 with --strict).
  CLEAN — no ERROR or WARN findings (INFO may remain).
    Exit 0.

WHAT IT DOES NOT CLAIM (stated plainly): static pattern
analysis reads evidence, it does not prove safety. A
CLEAN verdict means no pattern fired — a well-written
plain-sight social-engineering skill, a payload assembled
at runtime from innocuous pieces, or a binary's behaviour
can all pass. Vet is the first pass, not the verdict on
a pack's soul. Input errors (missing folder, not a
folder, bad arguments) exit 2 as a clean {"error": ...}
object in --json mode — never a traceback.
"""

import argparse
import json
import os
import re
import sys

TOOL = "skill-vet"
VERSION = "1.0.0"

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

LARGE_FILE_BYTES = 1_048_576          # 1 MiB
SCAN_CAP_BYTES = 2_097_152            # text scanning cap per file
BASE64_BLOB_MIN = 120                 # chars in one token
HEX_BLOB_MIN = 120
ESCAPE_RUN_MIN = 8                    # consecutive \xNN escapes
BLANK_RUN_MIN = 50                    # consecutive blank lines
HIDDEN_COMMENT_MIN = 120              # chars inside <!-- ... -->

SKIP_DIRS = {".git", "__pycache__"}

SCRIPT_EXTS = {
    ".py", ".sh", ".bash", ".zsh", ".ksh", ".js", ".mjs",
    ".cjs", ".ts", ".rb", ".pl", ".php", ".ps1", ".bat",
    ".cmd",
}
MARKDOWN_EXTS = {".md", ".markdown"}
BINARY_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".whl", ".jar",
    ".class", ".o", ".a", ".node", ".wasm", ".com", ".msi",
    ".dmg", ".pkg", ".deb", ".rpm", ".elf", ".pyc",
}
REF_EXTS = {
    ".md", ".py", ".sh", ".json", ".txt", ".csv", ".yaml",
    ".yml", ".toml", ".js", ".ts",
}
REF_PREFIX_DIRS = (
    "scripts/", "references/", "assets/", "templates/",
    "data/", "files/", "docs/",
)

VERDICT_RULE = (
    "BLOCKED = at least one danger finding (a proven "
    "stealing / spying / hidden-sending combination); "
    "REVIEW = no danger finding, but at least one ERROR "
    "or WARN; CLEAN = no ERROR or WARN findings (INFO "
    "may remain). Exit 1 only for BLOCKED (or for REVIEW "
    "with --strict); exit 2 is an input error."
)

LIMITS_LINE = (
    "Static pattern analysis only: it reads evidence, it "
    "cannot prove a pack safe. A CLEAN verdict means no "
    "pattern fired — plain-sight social engineering, a "
    "payload assembled at runtime, and bundled binaries "
    "can all pass a static vet."
)


class ToolError(Exception):
    """An input error: clean message, exit 2."""


# ------------------------------------------------------------------
# Findings
# ------------------------------------------------------------------

_SEVERITY_RANK = {"ERROR": 0, "WARN": 1, "INFO": 2}


def finding(rule, severity, file, line, message, fix,
            danger=False):
    return {
        "rule": rule,
        "severity": severity,
        "danger": danger,
        "file": file,
        "line": line,
        "message": message,
        "fix": fix,
    }


def sort_findings(findings):
    def key(f):
        return (
            0 if f["danger"] else 1,
            _SEVERITY_RANK[f["severity"]],
            f["file"] or "",
            f["line"] or 0,
            f["rule"],
        )
    return sorted(findings, key=key)


# ------------------------------------------------------------------
# Frontmatter (a deliberately small YAML subset)
# ------------------------------------------------------------------
# Supported: `key: value` scalars (quotes stripped),
# `key: [a, b]` inline lists, `key:` followed by `- item`
# block lists, and indented continuation lines folded into
# the previous scalar. Anything else is a parse error with
# the line cited — a frontmatter the subset cannot read
# is reported, never guessed at.

_KEY_LINE = re.compile(r"^([A-Za-z0-9_-]+):\s*(.*)$")
_LIST_ITEM = re.compile(r"^\s+-\s+(.*)$")


def _strip_quotes(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and \
            value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_frontmatter(text):
    """Return (fields, body, error, error_line).

    fields maps key -> str | list[str]. error is None on
    success; on a missing block error is "missing".
    Line numbers are 1-based, counting the opening ---.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, text, "missing", None
    close = None
    for i in range(1, min(len(lines), 400)):
        if lines[i].strip() in ("---", "..."):
            close = i
            break
    if close is None:
        return None, text, "no closing --- for the " \
            "frontmatter block", 1
    fields = {}
    current = None
    for i in range(1, close):
        raw = lines[i]
        lineno = i + 1
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        item = _LIST_ITEM.match(raw)
        if item and current is not None:
            value = _strip_quotes(item.group(1))
            if not isinstance(fields.get(current), list):
                fields[current] = []
            fields[current].append(value)
            continue
        if raw[0] in (" ", "\t") and current is not None and \
                isinstance(fields.get(current), str):
            fields[current] = (
                fields[current] + " " + raw.strip()).strip()
            continue
        m = _KEY_LINE.match(raw)
        if not m:
            return None, text, "frontmatter line %d is not " \
                "a key: value line, a list item, or a " \
                "continuation: %r" % (lineno, raw.strip()), \
                lineno
        key, value = m.group(1), m.group(2).strip()
        current = key
        if value == "":
            fields[key] = ""
        elif value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            fields[key] = [
                _strip_quotes(part)
                for part in inner.split(",") if part.strip()
            ] if inner else []
        else:
            fields[key] = _strip_quotes(value)
    body = "\n".join(lines[close + 1:])
    return fields, body, None, None


def field_text(fields, key):
    """A frontmatter field as one string (lists join)."""
    value = fields.get(key)
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(value)
    return value


def field_entries(fields, key):
    """A frontmatter field as a list of entries."""
    value = fields.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [part.strip() for part in value.split(",")
            if part.strip()]


# ------------------------------------------------------------------
# Inventory
# ------------------------------------------------------------------

def _is_binary(path, ext, head):
    if ext in BINARY_EXTS:
        return True
    return b"\x00" in head


def inventory(pack_dir):
    """Walk the pack. Returns a list of records:
    {path, bytes, kind, binary, scanned, symlink_out}.
    .git and __pycache__ directories are skipped.
    """
    records = []
    for root, dirs, names in os.walk(pack_dir):
        dirs[:] = sorted(
            d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, pack_dir)
            rec = {
                "path": rel.replace(os.sep, "/"),
                "bytes": 0,
                "kind": "other",
                "binary": False,
                "scanned": False,
                "symlink_out": False,
            }
            try:
                rec["bytes"] = os.path.getsize(full)
            except OSError:
                pass
            if os.path.islink(full):
                real = os.path.realpath(full)
                if not real.startswith(
                        os.path.realpath(pack_dir) + os.sep):
                    rec["symlink_out"] = True
            ext = os.path.splitext(name)[1].lower()
            head = b""
            if not rec["symlink_out"]:
                try:
                    with open(full, "rb") as fh:
                        head = fh.read(8192)
                except OSError:
                    head = b""
            rec["binary"] = _is_binary(full, ext, head)
            if ext in SCRIPT_EXTS or head.startswith(b"#!"):
                rec["kind"] = "script"
            elif ext in MARKDOWN_EXTS:
                rec["kind"] = "markdown"
            elif rec["binary"]:
                rec["kind"] = "binary"
            elif ext:
                rec["kind"] = "text"
            records.append(rec)
    records.sort(key=lambda r: r["path"])
    return records


def read_text(pack_dir, rel):
    """Read one pack file as text (utf-8, lossy). Returns
    None when unreadable. Capped at SCAN_CAP_BYTES."""
    full = os.path.join(pack_dir, rel.replace("/", os.sep))
    try:
        with open(full, "rb") as fh:
            data = fh.read(SCAN_CAP_BYTES)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


# ------------------------------------------------------------------
# Pattern tables (static text — data, never executed)
# ------------------------------------------------------------------
# Each entry: (label, compiled regex). Lines are matched
# one at a time; a "hit" records (line_number, label).

SECRET_PATTERNS = [
    ("an SSH key or .ssh store path",
     re.compile(r"\.ssh[/\\]|id_(rsa|dsa|ecdsa|ed25519)\b")),
    ("an AWS credentials/config path",
     re.compile(r"\.aws[/\\]|\.aws\b")),
    ("a GnuPG store path", re.compile(r"\.gnupg\b")),
    ("a .netrc credentials file", re.compile(r"\.netrc\b|_netrc\b")),
    ("a stored-credentials file",
     re.compile(r"\.git-credentials\b|\.docker[/\\]config\.json"
                r"|\.kube[/\\]config\b")),
    ("a browser credential store",
     re.compile(r"Login Data|Local State|logins\.json|key4\.db"
                r"|places\.sqlite|Cookies\.sqlite")),
    ("a browser profile directory",
     re.compile(r"User Data[/\\]|[/\\]Mozilla[/\\]|[/\\]Firefox[/\\]"
                r"|profiles\.ini")),
    ("a .env secrets file",
     re.compile(r"[\"'][^\"']*\.env[\"']|(?:cat|open|read)\b"
                r"[^\n]*\.env\b")),
]

_ENV_ACCESS = re.compile(
    r"os\.environ|os\.getenv|environ\.get|process\.env|ENV\["
    r"|getenv\s*\(")
_ENV_SECRET_NAME = re.compile(
    r"SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY"
    r"|CREDENTIAL|AWS_|GITHUB_|GH_TOKEN|OPENAI_|ANTHROPIC_"
    r"|STRIPE_")
_ENV_WHOLE = re.compile(
    r"dict\(\s*os\.environ|list\(\s*os\.environ"
    r"|json\.dumps\([^)]*os\.environ|\{\*\*os\.environ"
    r"|os\.environ\.items\(\)|os\.environ\.copy\(\)")

SEND_PATTERNS = [
    ("an HTTP client call",
     re.compile(r"requests\.(get|post|put|patch|delete|request"
                r"|head)\s*\(|httpx\.(get|post|put|patch|delete"
                r"|request|stream)\s*\(")),
    ("a urllib request",
     re.compile(r"urlopen\s*\(|urllib\.request")),
    ("a raw HTTP connection",
     re.compile(r"http\.client\.|HTTPSConnection|HTTPConnection")),
    ("a socket connection",
     re.compile(r"socket\.socket\s*\(|create_connection\s*\(")),
    ("a browser-style fetch",
     re.compile(r"\bfetch\s*\(|axios\.(get|post|put|delete"
                r"|request)|XMLHttpRequest")),
    ("a shell network tool",
     re.compile(r"\bcurl\b|\bwget\b|\bnc\s+-|netcat\b"
                r"|Invoke-WebRequest|Invoke-RestMethod")),
    ("a mail/FTP/telnet client",
     re.compile(r"smtplib\.|ftplib\.|telnetlib\.|websocket")),
]

_URL_RE = re.compile(r"(?:https?|ftp|wss?)://([A-Za-z0-9.\-]+)")

CAPTURE_PATTERNS = {
    "screen": [
        ("a screenshot call",
         re.compile(r"pyautogui\.screenshot|ImageGrab\.grab"
                    r"|\bmss\.mss|pyscreenshot|\bscreencapture\b"
                    r"|\bscrot\b")),
    ],
    "keyboard": [
        ("a keyboard hook/listener",
         re.compile(r"pynput|GetAsyncKeyState|pyxhook"
                    r"|keyboard\.(on_press|record|hook)"
                    r"|\bkeylogger?\b")),
    ],
    "audio": [
        ("a microphone/audio capture",
         re.compile(r"pyaudio|sounddevice|\barecord\b"
                    r"|Microphone\s*\(")),
    ],
    "camera": [
        ("a camera capture",
         re.compile(r"cv2\.VideoCapture|VideoCapture\s*\(")),
    ],
}

CAPTURE_DISCLOSURE_WORDS = {
    "screen": ("screenshot", "screen capture", "screen recording",
               "captures the screen", "screen grab"),
    "keyboard": ("keystroke", "keyboard", "key logging",
                 "keylogging"),
    "audio": ("microphone", "audio recording", "records audio",
              "voice recording"),
    "camera": ("webcam", "camera", "video capture"),
    "history": ("browser history", "browsing history", "history"),
}

_SQLITE_RE = re.compile(r"sqlite3|sqlite\b|\bSELECT\b")

PERSIST_PATTERNS = [
    ("a file save/write",
     re.compile(r"\.save\s*\(|open\s*\([^)]*[\"'][wa][\"']"
                r"|\.write\s*\(")),
    ("an endless loop",
     re.compile(r"while\s+True\s*:|while\s*\(\s*true\s*\)"
                r"|for\s*\(\s*;\s*;")),
    ("an autostart/persistence mechanism",
     re.compile(r"crontab|LaunchAgent|schtasks|autostart"
                r"|systemd")),
]

ENCODE_PATTERNS = [
    ("a base64/hex/compression encoder",
     re.compile(r"b64encode|b64decode|hexlify|unhexlify"
                r"|codecs\.encode|zlib\.compress|gzip\.compress"
                r"|bz2\.compress|lzma\.compress")),
]

COPY_OUT_PATTERNS = [
    ("a copy/move out",
     re.compile(r"shutil\.(copy|copy2|copyfile|move)\b"
                r"|os\.rename\s*\(|\bcp\s+|\bmv\s+|\bscp\b"
                r"|\brsync\b")),
]

OUTSIDE_TOKENS = (
    "~/", "$HOME", "%USERPROFILE%", "/Users/", "/home/",
    "/etc/", "/root/", "/tmp/", "/var/", "C:\\Users",
    "C:/Users",
)

_READ_HINT = re.compile(
    r"\bopen\s*\(|\bread\b|\bcat\s|Path\s*\(|expanduser"
    r"|Path\.home")
_WRITE_HINT = re.compile(
    r"open\s*\([^)]*[\"'][wa][\"']|\.write\s*\(|\.save\s*\("
    r"|>\s*[\"']?(?:/|~|\$)")


def _is_comment_line(line, rel):
    """A full-line comment, for the hygiene checks: a
    comment MENTIONING shell=True or eval is documentation,
    not code. (Danger ingredients deliberately still scan
    comment lines — capability evidence is judged
    conservatively.)"""
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return True
    ext = os.path.splitext(rel)[1].lower()
    if ext in (".js", ".mjs", ".cjs", ".ts", ".php"):
        return stripped.startswith("//")
    return False


def _hits(lines, patterns):
    """All (line, label) hits for a pattern list."""
    out = []
    for lineno, line in enumerate(lines, 1):
        for label, rx in patterns:
            if rx.search(line):
                out.append((lineno, label))
                break
    return out


def _first(hits):
    return hits[0] if hits else None


class FileScan:
    """The ingredient evidence found in one script file."""

    def __init__(self, rel, lines):
        self.rel = rel
        self.lines = lines
        self.secret = _hits(lines, SECRET_PATTERNS)
        self.env_secret = []       # (line, label)
        self.whole_env = []        # (line, label)
        for lineno, line in enumerate(lines, 1):
            if _ENV_ACCESS.search(line) and \
                    _ENV_SECRET_NAME.search(line):
                self.env_secret.append(
                    (lineno, "an environment-secret read"))
            if _ENV_WHOLE.search(line):
                self.whole_env.append(
                    (lineno, "a whole-environment read"))
        self.send = _hits(lines, SEND_PATTERNS)
        self.hosts = []            # (host, line)
        for lineno, line in enumerate(lines, 1):
            for m in _URL_RE.finditer(line):
                self.hosts.append((m.group(1), lineno))
        self.captures = {}         # kind -> [(line, label)]
        for kind, pats in CAPTURE_PATTERNS.items():
            hits = _hits(lines, pats)
            if hits:
                self.captures[kind] = hits
        # browser-history scraping: a history store read
        # plus a database read in the same file
        hist_lines = [
            (n, "a browser history store")
            for n, line in enumerate(lines, 1)
            if re.search(r"places\.sqlite|\bHistory\b", line)
        ]
        if hist_lines and any(
                _SQLITE_RE.search(l) for l in lines):
            self.captures["history"] = hist_lines
        self.persist = _hits(lines, PERSIST_PATTERNS)
        self.encode = _hits(lines, ENCODE_PATTERNS)
        self.copy_out = []
        for lineno, line in enumerate(lines, 1):
            if any(rx.search(line)
                   for _, rx in COPY_OUT_PATTERNS) and \
                    _outside_token(line):
                self.copy_out.append(
                    (lineno, "a copy/move to an outside path"))
        self.read_outside = []     # (line, label)
        self.write_outside = []    # (line, label)
        for lineno, line in enumerate(lines, 1):
            if _outside_token(line):
                if _READ_HINT.search(line):
                    self.read_outside.append(
                        (lineno, "a read of a path outside "
                                 "the pack"))
                if _WRITE_HINT.search(line):
                    self.write_outside.append(
                        (lineno, "a write to a path outside "
                                 "the pack"))

    # -- send-segment analysis --------------------------------
    def send_segments(self):
        """Approximate call segments for each send hit:
        the hit line plus following lines until the parens
        balance. Used to see what actually flows out."""
        segments = []
        for lineno, _label in self.send:
            chunk = []
            depth = 0
            started = False
            for j in range(lineno - 1, min(len(self.lines),
                                           lineno + 14)):
                text = self.lines[j]
                chunk.append(text)
                depth += text.count("(") - text.count(")")
                if "(" in text:
                    started = True
                if started and depth <= 0:
                    break
            segments.append((lineno, "\n".join(chunk)))
        return segments

    def encoded_payload_sent(self):
        """(encode_line, send_line) when an encoded value
        reaches a send: the encoder call inside the send
        segment, a variable assigned from an encoder used
        in the segment, or os.environ inside the segment
        (whole-env exfil is judged under STEALING, not
        here)."""
        if not self.send or not self.encode:
            return None
        enc_vars = set()
        assign = re.compile(
            r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*.*"
            r"(b64encode|hexlify|codecs\.encode|zlib\.compress"
            r"|gzip\.compress|bz2\.compress|lzma\.compress)")
        for line in self.lines:
            m = assign.match(line)
            if m:
                enc_vars.add(m.group(1))
        enc_line = self.encode[0][0]
        for send_line, segment in self.send_segments():
            if any(rx.search(segment)
                   for _, rx in ENCODE_PATTERNS):
                return (enc_line, send_line)
            for var in enc_vars:
                if re.search(r"\b%s\b" % re.escape(var),
                             segment):
                    return (enc_line, send_line)
        return None


def _outside_token(line):
    return any(tok in line for tok in OUTSIDE_TOKENS)


# ------------------------------------------------------------------
# Disclosure (what the pack's own docs admit to)
# ------------------------------------------------------------------

def doc_hosts(doc_text):
    return {m.group(1).lower()
            for m in _URL_RE.finditer(doc_text)}


def host_disclosed(host, hosts):
    host = host.lower()
    return any(host == h or host.endswith("." + h)
               for h in hosts)


_OFFLINE_CLAIM = re.compile(
    r"(?i)\boffline\b|no network|never (sends|phones|connects"
    r"|shares)|local[- ]only|works locally|does not (send"
    r"|connect|phone|share)|nothing (is )?(sent|leaves|shared)")


def capture_disclosed(kind, doc_text_lower):
    return any(word in doc_text_lower
               for word in CAPTURE_DISCLOSURE_WORDS[kind])


# ------------------------------------------------------------------
# The danger tests + short-of-danger warnings (per script)
# ------------------------------------------------------------------

def scan_script(scan, docs_text, docs_lower, hosts_in_docs,
                offline_claim):
    out = []
    rel = scan.rel

    def cite(hit):
        return hit[0] if hit else None

    secret_hits = scan.secret + scan.env_secret + scan.whole_env
    send_hit = _first(scan.send)
    encoded = scan.encoded_payload_sent()
    undisclosed_hosts = [
        (host, line) for host, line in scan.hosts
        if not host_disclosed(host, hosts_in_docs)
    ]

    # ---- Test 1: STEALING --------------------------------
    egress = send_hit or _first(scan.copy_out)
    stealing_fired = False
    if secret_hits and egress:
        stealing_fired = True
        s_line, s_label = secret_hits[0]
        e_line, e_label = egress
        out.append(finding(
            "DANGER_STEALING", "ERROR", rel, s_line,
            "STEALING combination: this file reads secrets "
            "(%s, line %d) and has an egress path (%s, line "
            "%d). Credential material plus a way out is the "
            "stealing test — the pack can take what it reads "
            "off the machine." % (s_label, s_line, e_label,
                                  e_line),
            "do not install; if you maintain this pack, "
            "remove the credential read or the egress — a "
            "legitimate pack needs at most one of them",
            danger=True))
    elif secret_hits:
        s_line, s_label = secret_hits[0]
        out.append(finding(
            "SECRET_ACCESS", "WARN", rel, s_line,
            "this file reads secrets (%s, line %d) but no "
            "send or copy-out was found in the same file — "
            "short of the stealing combination, and still "
            "worth asking why a skill needs it"
            % (s_label, s_line),
            "confirm the pack genuinely needs this access "
            "before installing"))

    # ---- Test 2: SPYING ----------------------------------
    for kind, hits in sorted(scan.captures.items()):
        c_line, c_label = hits[0]
        persist_hit = _first(scan.persist)
        if send_hit or persist_hit:
            if capture_disclosed(kind, docs_lower):
                out.append(finding(
                    "DISCLOSED_CAPTURE", "WARN", rel, c_line,
                    "this file captures %s (%s, line %d) and "
                    "persists or sends it — and the pack's "
                    "docs DO disclose %s capture, so this is "
                    "not the spying test; it is a capability "
                    "to accept knowingly"
                    % (kind, c_label, c_line, kind),
                    "install only if you want this capture "
                    "happening"))
            else:
                via = send_hit or persist_hit
                out.append(finding(
                    "DANGER_SPYING", "ERROR", rel, c_line,
                    "SPYING combination: this file captures "
                    "%s (%s, line %d), persists or sends it "
                    "(%s, line %d), and the pack's docs "
                    "nowhere disclose %s capture — capture "
                    "plus a way to keep or move it, in "
                    "secret, is the spying test."
                    % (kind, c_label, c_line, via[1], via[0],
                       kind),
                    "do not install; undisclosed capture is "
                    "never a feature",
                    danger=True))
        else:
            out.append(finding(
                "CAPTURE_CAPABILITY", "WARN", rel, c_line,
                "this file can capture %s (%s, line %d) but "
                "no persistence or send was found in the "
                "same file — capability alone is short of "
                "the spying combination"
                % (kind, c_label, c_line),
                "ask why the pack ships a capture API it "
                "does not appear to use"))

    # ---- Test 3: HIDDEN SENDING ---------------------------
    # A send already judged as the egress half of STEALING
    # in this file is not counted a second time here.
    hidden_reason = None
    if send_hit and not stealing_fired:
        if offline_claim:
            hidden_reason = (
                "the pack's docs claim it works offline / "
                "local-only, yet this file makes a network "
                "call (%s, line %d) — a send the docs deny "
                "exists" % (send_hit[1], send_hit[0]))
        elif encoded and (undisclosed_hosts or not scan.hosts):
            hidden_reason = (
                "an encoded payload reaches the network "
                "call (encoder at line %d, send at line %d) "
                "to an endpoint the docs never disclose — "
                "neither what is sent nor where it goes "
                "can be read off the pack"
                % encoded)
        elif scan.read_outside and undisclosed_hosts:
            hidden_reason = (
                "this file reads local files from outside "
                "the pack (line %d) and sends to an endpoint "
                "the docs never mention (%s, line %d) — "
                "local contents leaving to an unnamed place"
                % (scan.read_outside[0][0],
                   undisclosed_hosts[0][0],
                   undisclosed_hosts[0][1]))
        elif scan.write_outside and undisclosed_hosts:
            hidden_reason = (
                "this file writes outside the pack (line "
                "%d) and sends to an endpoint the docs never "
                "mention (%s, line %d)"
                % (scan.write_outside[0][0],
                   undisclosed_hosts[0][0],
                   undisclosed_hosts[0][1]))
    if hidden_reason:
        out.append(finding(
            "DANGER_HIDDEN_SENDING", "ERROR", rel,
            send_hit[0],
            "HIDDEN-SENDING combination: " + hidden_reason
            + ". Concealment of what is sent, or to where, "
            "is the hidden-sending test.",
            "do not install until the send is disclosed "
            "in the docs and the payload is readable in "
            "the code",
            danger=True))
    elif send_hit:
        # short-of-danger network warnings (suppressed when
        # a danger finding in this file already covers the
        # send)
        covered = any(f["danger"] for f in out)
        if encoded and not covered:
            out.append(finding(
                "ENCODED_PAYLOAD", "WARN", rel, encoded[1],
                "an encoded payload reaches a network call "
                "(encoder at line %d, send at line %d) to a "
                "disclosed endpoint — the destination is "
                "honest, what is sent is opaque"
                % encoded,
                "ask the pack's author what the encoded "
                "payload contains"))
        elif undisclosed_hosts and not covered:
            host, h_line = undisclosed_hosts[0]
            out.append(finding(
                "UNDISCLOSED_NETWORK", "WARN", rel, h_line,
                "this file calls %s (line %d), an endpoint "
                "that appears nowhere in the pack's SKILL.md "
                "/ README.md — undisclosed network use, "
                "short of the hidden-sending combination "
                "(no encoded payload, no local-file read, "
                "no offline claim)" % (host, h_line),
                "the pack should name every endpoint it "
                "calls in its docs"))
        elif not scan.hosts and not covered:
            out.append(finding(
                "DYNAMIC_ENDPOINT", "WARN", rel, send_hit[0],
                "this file makes a network call (%s, line "
                "%d) with no literal URL in the code — the "
                "endpoint cannot be checked against the docs"
                % (send_hit[1], send_hit[0]),
                "read where the URL is built before "
                "installing"))

    # ---- Hygiene that lives in scripts --------------------
    # (full-line comments are skipped here: a comment that
    # mentions shell=True is documentation, not code)
    code_lines = [(n, line) for n, line in
                  enumerate(scan.lines, 1)
                  if not _is_comment_line(line, rel)]
    for lineno, line in code_lines:
        if "shell=True" in line or "shell: true" in line:
            out.append(finding(
                "HYGIENE_SHELL_TRUE", "WARN", rel, lineno,
                "subprocess runs with shell=True — command "
                "strings become shell input, so any value "
                "that reaches the command is an injection "
                "path",
                "use an argument list with shell=False"))
            break
    dyn = None
    for lineno, line in code_lines:
        if re.search(r"\beval\s*\(|\bexec\s*\(|os\.system\s*\("
                     r"|os\.popen\s*\(|__import__\s*\(", line):
            dyn = lineno
            break
    if dyn is not None:
        out.append(finding(
            "HYGIENE_DYNAMIC_EXEC", "WARN", rel, dyn,
            "dynamic execution (eval / exec / os.system / "
            "os.popen / __import__) at line %d — code whose "
            "behaviour cannot be fully read statically"
            % dyn,
            "review exactly what strings can reach it"))
    pipe = None
    for lineno, line in code_lines:
        if re.search(r"(curl|wget)[^|\n]*\|\s*(sh|bash|zsh)\b",
                     line) or re.search(
                         r"(sh|bash)\s+<\(\s*(curl|wget)", line):
            pipe = lineno
            break
    if pipe is not None or (scan.send and dyn is not None):
        where = pipe if pipe is not None else dyn
        out.append(finding(
            "HYGIENE_DOWNLOAD_EXEC", "WARN", rel, where,
            "downloaded content is executed (a download "
            "piped to a shell, or a download and a dynamic "
            "exec in the same file) — the pack's real "
            "behaviour would live on a server, not in this "
            "code",
            "never install a pack that fetches its own "
            "logic at run time"))
    if scan.write_outside and not any(
            f["rule"] == "DANGER_HIDDEN_SENDING" for f in out):
        w_line, w_label = scan.write_outside[0]
        out.append(finding(
            "WRITES_OUTSIDE_PACK", "WARN", rel, w_line,
            "%s (line %d) — a skill should keep its writes "
            "inside its own folder or the user's explicit "
            "workspace" % (w_label, w_line),
            "confirm the destination is one you accept"))
    return out


# ------------------------------------------------------------------
# Hygiene over text files (concealment + obfuscation)
# ------------------------------------------------------------------

_INVISIBLE = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u00ad": "SOFT HYPHEN",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
}
for _cp in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)):
    _INVISIBLE[chr(_cp)] = "BIDI CONTROL U+%04X" % _cp


def _invisible_hits(text):
    """(count, first_line, [names]) for invisible chars.
    A leading BOM is a file signature, not concealment,
    and is ignored. Unicode tag characters (U+E0000–
    U+E007F) are counted by range."""
    total = 0
    first_line = None
    names = []
    body = text[1:] if text.startswith("\ufeff") else text
    for lineno, line in enumerate(body.splitlines(), 1):
        for ch in line:
            name = _INVISIBLE.get(ch)
            if name is None and 0xE0000 <= ord(ch) <= 0xE007F:
                name = "UNICODE TAG CHARACTER U+%05X" % ord(ch)
            if name is not None:
                total += 1
                if first_line is None:
                    first_line = lineno
                if name not in names and len(names) < 3:
                    names.append(name)
    return total, first_line, names


_B64_TOKEN = re.compile(r"[A-Za-z0-9+/=]{%d,}" % BASE64_BLOB_MIN)
_HEX_TOKEN = re.compile(r"[0-9a-fA-F]{%d,}" % HEX_BLOB_MIN)
_ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){%d,}"
                         % ESCAPE_RUN_MIN)


def scan_text_hygiene(rel, text, kind):
    out = []
    lines = text.splitlines()
    # obfuscation blobs (one finding per kind per file)
    found_kinds = set()
    for lineno, line in enumerate(lines, 1):
        for m in _ESCAPE_RUN.finditer(line):
            if "escape-run" not in found_kinds:
                found_kinds.add("escape-run")
                out.append(finding(
                    "HYGIENE_OBFUSCATION", "WARN", rel, lineno,
                    "a run of %d+ \\xNN escapes at line %d — "
                    "code or text stored as escapes cannot be "
                    "read at a glance, which is the point of "
                    "storing it that way" % (ESCAPE_RUN_MIN,
                                             lineno),
                    "decode it in the open or remove it"))
        for m in _B64_TOKEN.finditer(line):
            token = m.group(0)
            if all(c in "0123456789abcdefABCDEF"
                   for c in token):
                kind_name = "hex-blob"
            else:
                kind_name = "base64-blob"
            if kind_name in found_kinds:
                continue
            if kind_name == "base64-blob" and not (
                    any(c.isupper() for c in token)
                    and any(c.islower() for c in token)
                    and any(c.isdigit() or c in "+/"
                            for c in token)):
                continue
            found_kinds.add(kind_name)
            out.append(finding(
                "HYGIENE_OBFUSCATION", "WARN", rel, lineno,
                "a %s of %d+ characters at line %d — content "
                "encoded as one opaque blob cannot be "
                "reviewed as written"
                % (kind_name.replace("-", " "),
                   HEX_BLOB_MIN if kind_name == "hex-blob"
                   else BASE64_BLOB_MIN, lineno),
                "keep pack content readable; encoded blobs "
                "belong in the open or not at all"))
    # invisible characters
    count, first_line, names = _invisible_hits(text)
    if count:
        out.append(finding(
            "CONCEALED_UNICODE", "WARN", rel, first_line,
            "%d invisible character(s) in this file (first "
            "at line %d): %s — invisible text can carry "
            "instructions a reader never sees"
            % (count, first_line, ", ".join(names)),
            "strip invisible characters from pack files"))
    if kind == "markdown":
        # long blank-line runs with content after them
        run = 0
        run_start = None
        for lineno, line in enumerate(lines, 1):
            if not line.strip():
                if run == 0:
                    run_start = lineno
                run += 1
            else:
                if run >= BLANK_RUN_MIN:
                    out.append(finding(
                        "CONCEALED_BLANK_RUN", "WARN", rel,
                        run_start,
                        "%d consecutive blank lines starting "
                        "at line %d, with content after them — "
                        "a known place to hide instructions "
                        "past the point a reviewer stops "
                        "scrolling" % (run, run_start),
                        "collapse the gap; keep the whole "
                        "file in review range"))
                run = 0
        # long HTML comments
        for m in re.finditer(r"<!--(.*?)-->", text,
                             re.DOTALL):
            if len(m.group(1)) >= HIDDEN_COMMENT_MIN:
                line_no = text[:m.start()].count("\n") + 1
                out.append(finding(
                    "HIDDEN_COMMENT", "WARN", rel, line_no,
                    "an HTML comment of %d characters at "
                    "line %d — comments do not render, so "
                    "long ones are a place to put text a "
                    "reader of the rendered page never sees"
                    % (len(m.group(1)), line_no),
                    "move anything that matters into the "
                    "visible text"))
    return out


# ------------------------------------------------------------------
# Install hooks
# ------------------------------------------------------------------

_INSTALL_NAMES = {"setup.py", "install.py", "install.sh",
                  "install.bash", "setup.sh"}
_PKG_HOOK = re.compile(r'"(preinstall|install|postinstall)"'
                       r'\s*:')


def scan_install_hooks(pack_dir, records):
    out = []
    for rec in records:
        base = rec["path"].rsplit("/", 1)[-1]
        ext = os.path.splitext(base)[1].lower()
        reason = None
        if base in _INSTALL_NAMES:
            reason = "an install/setup script"
        elif ext == ".pth":
            reason = "a .pth file (its lines are executed " \
                     "by the interpreter at startup)"
        elif base == "package.json" and not rec["binary"]:
            text = read_text(pack_dir, rec["path"]) or ""
            if _PKG_HOOK.search(text):
                reason = "a package.json with an install " \
                         "hook (preinstall/install/" \
                         "postinstall)"
        if reason:
            out.append(finding(
                "INSTALL_HOOK", "WARN", rec["path"], None,
                "this file runs at install time — %s. "
                "Install-time code executes before any "
                "review of the pack's normal flow"
                % reason,
                "read this file first, before installing"))
    return out


# ------------------------------------------------------------------
# References (SKILL.md links + script path literals)
# ------------------------------------------------------------------

_MD_LINK = re.compile(
    r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_BACKTICK = re.compile(r"`([^`\n]+)`")
_SCRIPT_LITERAL = re.compile(r"[\"']([^\"'\n]{2,200})[\"']")


def _clean_target(raw):
    target = raw.strip()
    if not target or "://" in target:
        return None
    if target.startswith(("#", "mailto:", "/", "~", "$",
                          "<")):
        return None
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None
    return target


def _looks_like_path(target, from_backtick):
    if " " in target:
        return False
    ext = os.path.splitext(target)[1].lower()
    if "/" in target:
        return True
    if from_backtick:
        return ext in REF_EXTS
    return ext in REF_EXTS


def _resolve(pack_dir, base_dir, target):
    """Returns "ok" | "missing" | "outside". Tries the
    base dir, then the pack root."""
    root = os.path.realpath(pack_dir)
    for base in (base_dir, pack_dir):
        cand = os.path.realpath(os.path.join(base, target))
        if cand == root or cand.startswith(root + os.sep):
            if os.path.exists(cand):
                return "ok"
        else:
            return "outside"
    return "missing"


def scan_references(pack_dir, source_rel, text, is_script):
    out = []
    seen = set()
    targets = []  # (target, line)
    if is_script:
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in _SCRIPT_LITERAL.finditer(line):
                raw = m.group(1)
                if raw.startswith(("./", "../")) or \
                        raw.startswith(REF_PREFIX_DIRS) or \
                        ("/" in raw and not raw.startswith(
                            ("/", "~", "$")) and
                         os.path.splitext(raw)[1].lower()
                         in REF_EXTS):
                    targets.append((raw, lineno))
    else:
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in _MD_LINK.finditer(line):
                targets.append((m.group(1), lineno))
            for m in _BACKTICK.finditer(line):
                if _looks_like_path(m.group(1), True):
                    targets.append((m.group(1), lineno))
    base_dir = os.path.join(
        pack_dir, os.path.dirname(source_rel.replace(
            "/", os.sep)))
    for raw, lineno in targets:
        target = _clean_target(raw)
        if target is None or (target, lineno) in seen:
            continue
        if not _looks_like_path(target, False):
            continue
        seen.add((target, lineno))
        status = _resolve(pack_dir, base_dir, target)
        if status == "missing":
            out.append(finding(
                "BROKEN_REFERENCE", "ERROR", source_rel,
                lineno,
                "referenced local file %r does not exist "
                "in the pack — the pack points at something "
                "that is not there" % target,
                "add the file, or fix the reference"))
        elif status == "outside":
            out.append(finding(
                "REFERENCE_OUTSIDE_PACK", "WARN",
                source_rel, lineno,
                "reference %r resolves outside the pack "
                "folder — the pack depends on, or points "
                "into, the wider filesystem" % target,
                "keep pack references inside the pack, or "
                "document the external dependency"))
    return out


# ------------------------------------------------------------------
# Structure checks
# ------------------------------------------------------------------

_NAME_SLUG = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_TOOL_STAR = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\(\*\)$")


def _norm_name(name):
    return name.strip().lower()


def scan_structure(pack_dir, records, skill_rel, fields,
                   parse_error, parse_line):
    out = []
    dirname = os.path.basename(os.path.realpath(pack_dir))
    if skill_rel is None:
        out.append(finding(
            "MISSING_SKILL_MD", "ERROR", None, None,
            "no SKILL.md at the pack root — whatever this "
            "folder is, a skill loader cannot load it as a "
            "skill",
            "a skill pack ships a SKILL.md at its root"))
        return out, None
    if os.path.basename(skill_rel) != "SKILL.md":
        out.append(finding(
            "SKILL_MD_CASE", "WARN", skill_rel, None,
            "the skill file is named %r, not SKILL.md — "
            "some loaders look for the exact name and will "
            "miss this pack" % os.path.basename(skill_rel),
            "rename it to SKILL.md"))
    if parse_error == "missing":
        out.append(finding(
            "FRONTMATTER_MISSING", "ERROR", skill_rel, 1,
            "SKILL.md has no --- frontmatter block — the "
            "name and description a loader registers the "
            "skill under are absent",
            "add a frontmatter block with name and "
            "description"))
        return out, None
    if parse_error:
        out.append(finding(
            "FRONTMATTER_PARSE", "ERROR", skill_rel,
            parse_line,
            "the frontmatter does not parse: %s — a loader "
            "reading this block will fail or guess"
            % parse_error,
            "fix the frontmatter line"))
        return out, fields
    name = field_text(fields, "name")
    description = field_text(fields, "description")
    if name is None or not name.strip():
        out.append(finding(
            "REQUIRED_FIELD", "ERROR", skill_rel, None,
            "frontmatter field 'name' is missing or empty "
            "— a skill is registered under its name",
            "add a name to the frontmatter"))
    if description is None or not description.strip():
        out.append(finding(
            "REQUIRED_FIELD", "ERROR", skill_rel, None,
            "frontmatter field 'description' is missing or "
            "empty — the description is how a loader "
            "decides when the skill applies",
            "add a description to the frontmatter"))
    if name and name.strip():
        if _norm_name(name) != _norm_name(dirname):
            out.append(finding(
                "NAME_DIR_MISMATCH", "WARN", skill_rel,
                None,
                "frontmatter name %r does not match the "
                "pack folder name %r — loaders and humans "
                "will call this pack two different things"
                % (name.strip(), dirname),
                "make the name and the folder agree"))
        if not _NAME_SLUG.match(name.strip()):
            out.append(finding(
                "NAME_FORMAT", "WARN", skill_rel, None,
                "skill name %r is not a lowercase "
                "kebab-case slug — some loaders reject or "
                "mangle names outside that shape"
                % name.strip(),
                "rename to lowercase words joined by "
                "hyphens"))
    for entry in field_entries(fields, "allowed-tools"):
        if entry == "*" or _TOOL_STAR.match(entry) or \
                entry == "Bash":
            out.append(finding(
                "BROAD_TOOL_GRANT", "WARN", skill_rel,
                None,
                "allowed-tools grants %r — the whole tool, "
                "unscoped. A grant that wide should be a "
                "deliberate, documented choice"
                % entry,
                "scope the grant (e.g. Bash(npm run *)), "
                "or document why the whole tool is needed"))
    return out, fields


# ------------------------------------------------------------------
# The audit driver
# ------------------------------------------------------------------

def vet_pack(pack_dir):
    records = inventory(pack_dir)
    by_path = {r["path"]: r for r in records}

    skill_rel = None
    for rec in records:
        base = rec["path"].rsplit("/", 1)[-1]
        if "/" not in rec["path"] and \
                base.lower() == "skill.md":
            if base == "SKILL.md":
                skill_rel = rec["path"]
                break
            skill_rel = skill_rel or rec["path"]

    skill_text = None
    fields = None
    parse_error = None
    parse_line = None
    if skill_rel is not None:
        skill_text = read_text(pack_dir, skill_rel)
        if skill_text is None:
            skill_text = ""
        fields, _body, parse_error, parse_line = \
            parse_frontmatter(skill_text)

    readme_text = ""
    for rec in records:
        base = rec["path"].rsplit("/", 1)[-1]
        if "/" not in rec["path"] and \
                base.lower() == "readme.md" and \
                not rec["binary"] and not rec["symlink_out"]:
            readme_text = read_text(pack_dir,
                                    rec["path"]) or ""
            rec["scanned"] = True
            break

    docs_text = (skill_text or "") + "\n" + readme_text
    docs_lower = docs_text.lower()
    hosts_in_docs = doc_hosts(docs_text)
    offline_claim = bool(_OFFLINE_CLAIM.search(docs_text))

    findings = []
    structure, _ = scan_structure(
        pack_dir, records, skill_rel, fields, parse_error,
        parse_line)
    findings.extend(structure)

    for rec in records:
        if rec["bytes"] > LARGE_FILE_BYTES:
            findings.append(finding(
                "LARGE_FILE", "WARN", rec["path"], None,
                "this file is %d bytes — over the 1 MiB "
                "line for a pack that ships as reviewable "
                "text; bulk content hides bulk behaviour"
                % rec["bytes"],
                "split it, shrink it, or be ready to "
                "explain the bulk"))
        if rec["binary"]:
            findings.append(finding(
                "BUNDLED_BINARY", "WARN", rec["path"], None,
                "a binary file (%d bytes) — it cannot be "
                "statically vetted at all; its behaviour "
                "is whatever it does when run"
                % rec["bytes"],
                "install only if you trust the source "
                "enough to run unauditable code"))
        if rec["symlink_out"]:
            findings.append(finding(
                "SYMLINK_OUT", "INFO", rec["path"], None,
                "a symlink whose target leaves the pack — "
                "its target was not scanned; what it "
                "points at is outside this audit",
                "check the target before installing"))

    findings.extend(scan_install_hooks(pack_dir, records))

    for rec in records:
        if rec["binary"] or rec["symlink_out"]:
            continue
        if rec["kind"] not in ("script", "markdown", "text"):
            continue
        text = read_text(pack_dir, rec["path"])
        if text is None:
            continue
        rec["scanned"] = True
        findings.extend(
            scan_text_hygiene(rec["path"], text,
                              rec["kind"]))
        if rec["kind"] == "script":
            lines = text.splitlines()
            scan = FileScan(rec["path"], lines)
            findings.extend(scan_script(
                scan, docs_text, docs_lower, hosts_in_docs,
                offline_claim))
            findings.extend(scan_references(
                pack_dir, rec["path"], text, True))
        if skill_rel is not None and \
                rec["path"] == skill_rel:
            findings.extend(scan_references(
                pack_dir, rec["path"], text, False))

    findings = sort_findings(findings)
    summary = {
        "findings": len(findings),
        "errors": sum(1 for f in findings
                      if f["severity"] == "ERROR"),
        "warnings": sum(1 for f in findings
                        if f["severity"] == "WARN"),
        "info": sum(1 for f in findings
                    if f["severity"] == "INFO"),
        "danger": sum(1 for f in findings if f["danger"]),
    }
    if summary["danger"]:
        verdict = "BLOCKED"
    elif summary["errors"] or summary["warnings"]:
        verdict = "REVIEW"
    else:
        verdict = "CLEAN"
    pack_name = field_text(fields, "name") if fields else None
    return {
        "tool": TOOL,
        "version": VERSION,
        "command": "vet",
        "pack": {
            "dir": pack_dir,
            "dirname": os.path.basename(
                os.path.realpath(pack_dir)),
            "name": pack_name,
            "skill_file": skill_rel,
        },
        "files": records,
        "findings": findings,
        "summary": summary,
        "verdict": verdict,
        "verdict_rule": VERDICT_RULE,
        "limits": LIMITS_LINE,
    }


# ------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------

def _human_size(n):
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KiB" % (n / 1024)
    return "%.1f MiB" % (n / (1024 * 1024))


def _render_finding(f):
    head = "[%s] %s" % (f["rule"], f["file"] or "(pack)")
    if f["line"]:
        head += " · line %d" % f["line"]
    return "%s\n  %s\n  fix: %s" % (head, f["message"],
                                    f["fix"])


def render_text(result):
    pack = result["pack"]
    files = result["files"]
    total = sum(r["bytes"] for r in files)
    lines = []
    lines.append(
        "%s v%s — vet · pack %s · %d files · %s total"
        % (TOOL, VERSION, pack["dirname"], len(files),
           _human_size(total)))
    if pack["name"]:
        lines.append("Frontmatter name: %s" % pack["name"])
    lines.append(
        "Read-only: it edits nothing, writes nothing, and "
        "never executes anything in the pack — every file "
        "is analysed as static text.")
    lines.append("Verdict rule: " + VERDICT_RULE)
    lines.append("Limits: " + LIMITS_LINE)
    lines.append("")
    lines.append("INVENTORY (%d files):" % len(files))
    for rec in files:
        lines.append("  %s — %s · %s"
                     % (rec["path"], rec["kind"],
                        _human_size(rec["bytes"])))
    findings = result["findings"]
    groups = [
        ("DANGER — proven stealing / spying / "
         "hidden-sending combinations",
         [f for f in findings if f["danger"]]),
        ("ERRORS — structure and references that do not "
         "work as shipped",
         [f for f in findings if f["severity"] == "ERROR"
          and not f["danger"]]),
        ("WARNINGS — short of danger, worth a human look",
         [f for f in findings if f["severity"] == "WARN"]),
        ("INFO — worth knowing",
         [f for f in findings if f["severity"] == "INFO"]),
    ]
    for title, group in groups:
        if not group:
            continue
        lines.append("")
        lines.append("%s (%d):" % (title, len(group)))
        for f in group:
            lines.append(_render_finding(f))
    s = result["summary"]
    lines.append("")
    if not findings:
        lines.append(
            "No findings — no structure errors, no danger "
            "combination, no hygiene warning fired. "
            "(Absence of findings is not proof of safety.)")
    lines.append(
        "Summary: %d findings · %d errors · %d warnings "
        "· %d info · %d danger"
        % (s["findings"], s["errors"], s["warnings"],
           s["info"], s["danger"]))
    verdict = result["verdict"]
    if verdict == "BLOCKED":
        lines.append(
            "Verdict: BLOCKED — %d proven danger "
            "combination(s) (stealing / spying / hidden "
            "sending). Do not install." % s["danger"])
    elif verdict == "REVIEW":
        lines.append(
            "Verdict: REVIEW — no danger combination "
            "found, but %d error(s) and %d warning(s) "
            "need a human look before installing."
            % (s["errors"], s["warnings"]))
    else:
        lines.append(
            "Verdict: CLEAN — no errors, no warnings, no "
            "danger combinations found by the static "
            "rules.")
    return "\n".join(lines)


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

class _JsonAwareParser(argparse.ArgumentParser):
    """ArgumentParser that reports usage errors as JSON in
    --json mode ({"error": ...} on stdout, same exit code
    2), matching the house error contract."""

    json_mode = False

    def error(self, message):
        if self.json_mode:
            print(json.dumps({"error": message}))
            raise SystemExit(2)
        super().error(message)


def cmd_vet(args):
    path = args.path
    if not os.path.exists(path):
        raise ToolError(
            "no such folder: %s" % path)
    if not os.path.isdir(path):
        raise ToolError(
            "not a folder: %s — point vet at the skill "
            "pack's root folder" % path)
    result = vet_pack(path)
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print(render_text(result))
    if result["verdict"] == "BLOCKED":
        return 1
    if result["verdict"] == "REVIEW" and args.strict:
        return 1
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    _JsonAwareParser.json_mode = "--json" in argv
    ap = _JsonAwareParser(
        prog=TOOL,
        description="Statically vet an agent skill pack "
                    "before installing it: frontmatter and "
                    "structure, broken references, bundled "
                    "binaries, and the three danger tests — "
                    "stealing, spying, hidden sending — "
                    "each proven only by combined evidence "
                    "in the same file. Read-only, executes "
                    "nothing (stdlib only, local only).")
    sub = ap.add_subparsers(dest="command", required=True,
                            parser_class=_JsonAwareParser)

    p_vet = sub.add_parser(
        "vet", help="vet one skill pack folder: exit 1 "
                    "when the verdict is BLOCKED, 0 for "
                    "CLEAN or REVIEW (1 for REVIEW with "
                    "--strict), 2 for input errors")
    p_vet.add_argument(
        "path",
        help="the skill pack's root folder (the one "
             "holding SKILL.md)")
    p_vet.add_argument("--json", action="store_true",
                       help="print one JSON object instead "
                            "of text")
    p_vet.add_argument(
        "--strict", action="store_true",
        help="also exit 1 when the verdict is REVIEW")
    p_vet.set_defaults(func=cmd_vet)

    a = ap.parse_args(argv)

    def fail(msg):
        if getattr(a, "json", False):
            print(json.dumps({"error": msg}))
        else:
            print("ERROR: %s" % msg)
        return 2

    try:
        return a.func(a)
    except ToolError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
