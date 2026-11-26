#!/usr/bin/env python3
"""Deterministic checks behind the osdo-llm-scan action.

Subcommands (run with `python3 -I`):
  provider     detect the LLM provider SDK used by the source tree (key=value output)
  sarif        convert a Semgrep SARIF file into the findings file
  scan         run the enabled checks and append findings to the findings file
  consolidate  count findings by severity and category and evaluate the threshold

Findings file: tab-separated lines
  category<TAB>severity<TAB>rule<TAB>location<TAB>message

Exit codes: 0 completed (findings are reported, not treated as an error),
            2 scanner or input error. The action step fails on exit 2, so a
            broken check never reads as a clean result.
"""
import argparse
import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# OWASP LLM Top 10 (2023 numbering), plus two non-LLM categories.
CATEGORIES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "CODE": "Code security (SAST)",
    "SHELL": "Shell scripts (shellcheck)",
}
OWASP_CATEGORIES = [c for c in CATEGORIES if c.startswith("LLM")]

CHECK_ENV = {
    "prompt_injection": "OSDO_CHECK_PROMPT_INJECTION",
    "pii": "OSDO_CHECK_PII_EXPOSURE",
    "serialization": "OSDO_CHECK_MODEL_SERIALIZATION",
    "output": "OSDO_CHECK_OUTPUT_HANDLING",
    "prose": "OSDO_CHECK_PROSE_INJECTION",
    "unicode": "OSDO_CHECK_HIDDEN_UNICODE",
    "mcp": "OSDO_CHECK_MCP_MANIFESTS",
    "toolscope": "OSDO_CHECK_TOOL_SCOPE",
    "shell": "OSDO_CHECK_SHELL_SCRIPTS",
}

PROSE_EXTS = {".md", ".mdx", ".markdown", ".txt", ".rst", ".html", ".htm", ".tmpl",
              ".template", ".j2", ".jinja", ".jinja2", ".hbs", ".prompt", ".yaml", ".yml", ".json"}
FRONTMATTER_EXTS = {".md", ".mdx", ".markdown"}
MCP_BASENAMES = {".mcp.json", "mcp.json", "opencode.json"}
SHELL_EXTS = {".sh", ".bash"}
SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
CODE_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php",
             ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".sol", ".sql", ".ps1", ".bat",
             ".cmd", ".tf", ".hcl", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml", ".gradle"}
TEXT_EXTS = PROSE_EXTS | CODE_EXTS | SHELL_EXTS
BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".zip", ".gz", ".tgz",
               ".tar", ".bz2", ".xz", ".7z", ".jar", ".class", ".so", ".dylib", ".dll", ".exe", ".bin",
               ".wasm", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".wav", ".ogg",
               ".pyc", ".pyo"}
# Asset files that are scanned wherever they appear, including inside node_modules.
AGENT_FILE_NAMES = {"SKILL.md", "AGENTS.md", "CLAUDE.md", ".mcp.json", "mcp.json", "opencode.json"}
# NUL and C0 control bytes other than tab, LF, CR and form feed.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")


class CheckError(Exception):
    """A scanner or input problem. Always fatal for the step."""


def fail(message):
    raise CheckError(message)


# ---------------------------------------------------------------- findings

class Findings:
    def __init__(self, path):
        self.path = path
        self.rows = []

    def add(self, category, severity, rule, location, message):
        assert category in CATEGORIES, category
        assert severity in SEVERITY_RANK, severity
        row = (category, severity, rule, location, message)
        self.rows.append(row)
        clean = [str(x).replace("\t", " ").replace("\n", " ").replace("\r", " ") for x in row]
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("\t".join(clean) + "\n")


def env_flag(name, default="true"):
    value = os.environ.get(name, default).strip().lower()
    if value not in ("true", "false"):
        fail(f"{name} must be 'true' or 'false', got '{value}'")
    return value == "true"


def read_text(path):
    """Return (text, has_control_chars). Text is always decoded, so binary-looking
    text files are still scanned; the caller decides what a control byte means."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")
    text = data.decode("utf-8", errors="replace")
    return text, CONTROL_CHARS.search(text) is not None


def is_agent_file(name):
    return name in AGENT_FILE_NAMES or os.path.splitext(name)[1].lower() == ".prompt"


def iter_files(source, results):
    """Yield (path, agent_only) for regular files and (path, None) for symlinks.

    Only two exclusions exist, both exact paths: <source>/.git and the results
    directory. <source>/node_modules is walked but only agent-asset files inside it
    are yielded (agent_only=True). Symlinks are reported, never followed.
    """
    git_path = os.path.join(source, ".git")
    node_path = os.path.join(source, "node_modules")
    for dirpath, dirnames, filenames in os.walk(source):
        kept = []
        for name in sorted(dirnames):
            full = os.path.join(dirpath, name)
            if full == results or full == git_path:
                continue
            if os.path.islink(full):
                yield full, None
                continue
            kept.append(name)
        dirnames[:] = kept
        under_node = dirpath == node_path or dirpath.startswith(node_path + os.sep)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if full == git_path:
                continue
            if os.path.islink(full):
                yield full, None
            elif under_node:
                if is_agent_file(name):
                    yield full, True
            else:
                yield full, False


# ---------------------------------------------------------------- provider

PROVIDER_PATTERNS = [
    ("openai", re.compile(r"openai|ChatCompletion|gpt-")),
    ("anthropic", re.compile(r"anthropic|claude")),
    ("google", re.compile(r"google\.generativeai|gemini")),
    ("huggingface", re.compile(r"huggingface|transformers")),
]


def cmd_provider(args):
    source = require_dir(args.source)
    detected = "unknown"
    for name, pattern in PROVIDER_PATTERNS:
        if detected != "unknown":
            break
        for path, _ in iter_files(source, None):
            text, _ = read_text(path)
            if pattern.search(text):
                detected = name
                break
    print(f"provider={detected}")
    return 0


# ---------------------------------------------------------------- semgrep

SARIF_CATEGORY = {
    "prompt-injection-risk": "LLM01",
    "unvalidated-llm-output": "LLM02",
    "insecure-model-load": "LLM05",
    "api-key-exposure": "LLM06",
    "excessive-permissions": "LLM08",
}
SARIF_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}


def cmd_sarif(args):
    try:
        with open(args.sarif, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        fail(f"cannot read SARIF {args.sarif}: {exc}")
    findings = Findings(args.findings)
    count = 0
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            category = "CODE"
            for key, cat in SARIF_CATEGORY.items():
                if rule_id == key or rule_id.endswith("." + key):
                    category = cat
            level = SARIF_LEVEL.get(result.get("level", "warning"), "MEDIUM")
            location = "unknown"
            try:
                phys = result["locations"][0]["physicalLocation"]
                location = f"{phys['artifactLocation']['uri']}:{phys.get('region', {}).get('startLine', 0)}"
            except (KeyError, IndexError, TypeError):
                pass
            message = result.get("message", {}).get("text", rule_id)
            findings.add(category, level, f"semgrep:{rule_id}", location, message)
            count += 1
    print(f"semgrep_findings={count}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- code rules

CODE_PROMPT_RULES = [
    ("prompt-fstring-user-input", re.compile(r'f".*\{(user|input|request)'), None,
     "User input interpolated into an f-string prompt"),
    ("unsanitized-user-input-in-messages", re.compile(r"messages.*content.*user_input"),
     re.compile(r"sanitize|escape|clean"), "Unsanitized user input placed in LLM message content"),
    ("user-controlled-system-prompt", re.compile(r"system.*=.*user|role.*=.*request"), None,
     "User-controlled system prompt or role"),
]
OUTPUT_RULES = [
    ("llm-output-to-eval-exec", re.compile(r"eval.*response|exec.*completion|subprocess.*output"),
     "LLM output passed to eval, exec or a subprocess"),
    ("llm-output-rendered-as-html", re.compile(r"innerHTML.*response|dangerouslySetInnerHTML.*completion"),
     "LLM output rendered as raw HTML"),
]
PII_FIELD = re.compile(r"email|phone|ssn|credit_card|password")
PII_CONTEXT = re.compile(r"content|prompt|message", re.IGNORECASE)
PICKLE = re.compile(r"pickle\.load")
TORCH_LOAD = re.compile(r"torch\.load\(")


def check_code(rel, text, flags, findings):
    for lineno, line in enumerate(text.splitlines(), start=1):
        loc = f"{rel}:{lineno}"
        if flags["prompt_injection"]:
            for rule, pattern, exclude, message in CODE_PROMPT_RULES:
                if pattern.search(line) and not (exclude and exclude.search(line)):
                    findings.add("LLM01", "HIGH", rule, loc, message)
        if flags["serialization"]:
            if PICKLE.search(line):
                findings.add("LLM05", "CRITICAL", "insecure-pickle-deserialization", loc,
                             "Insecure pickle deserialization of model or data")
            if TORCH_LOAD.search(line) and "weights_only=True" not in line:
                findings.add("LLM05", "HIGH", "torch-load-without-weights-only", loc,
                             "torch.load without weights_only=True")
        if flags["output"]:
            for rule, pattern, message in OUTPUT_RULES:
                if pattern.search(line):
                    findings.add("LLM02", "CRITICAL", rule, loc, message)
        if flags["pii"] and PII_FIELD.search(line) and PII_CONTEXT.search(line):
            findings.add("LLM06", "HIGH", "pii-field-in-llm-prompt", loc,
                         "PII-like field appears in an LLM prompt or message")


# ---------------------------------------------------------------- prose

PROSE_RULES = [
    ("prose-ignore-instructions", "HIGH",
     re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|all|any)\b"
                r"[^.\n]{0,20}\b(instructions?|prompts?|rules|directives|guidelines)\b", re.IGNORECASE),
     "Instruction-override phrase"),
    ("prose-reveal-system-prompt", "HIGH",
     re.compile(r"\b(reveal|print|show|output|leak|repeat)\b[^.\n]{0,30}\b(system prompt|your instructions|hidden instructions)\b",
                re.IGNORECASE),
     "Request to reveal the system prompt or hidden instructions"),
    ("prose-hide-from-user", "HIGH",
     re.compile(r"\b(do not|don't|never)\s+(tell|inform|mention)\s+the user\b|\bwithout (telling|informing|notifying) the user\b",
                re.IGNORECASE),
     "Instruction to conceal behaviour from the user"),
    ("prose-role-override", "HIGH",
     re.compile(r"\byou are now\s+(a|an|in|the|my|DAN|unrestricted|jailbroken|free)\b|"
                r"\bact as (an? )?(unrestricted|jailbroken|DAN)\b", re.IGNORECASE),
     "Role override ('you are now ...')"),
    ("prose-chat-template-token", "HIGH",
     re.compile(r"<\|im_(start|end)\|>|<\|(system|user|assistant)\|>|\[/?INST\]|<</?SYS>>"),
     "Chat-template control token embedded in prose"),
    ("prose-you-are-now", "MEDIUM", re.compile(r"\byou are now\b", re.IGNORECASE),
     "'you are now' phrase; review whether it redefines the model's role"),
    ("prose-new-instructions", "MEDIUM", re.compile(r"\bnew (system )?instructions?\s*:", re.IGNORECASE),
     "Inline 'new instructions:' block"),
]
HIGH_PROSE_PATTERNS = [pattern for _, severity, pattern, _ in PROSE_RULES if severity == "HIGH"]
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
COMMENT_INSTRUCTION = re.compile(
    r"\b(system|assistant|developer)\s*:|\balways (reply|respond|answer|output|say)\b|"
    r"\bdo not (mention|reveal|tell)\b|curl |wget |exfiltrat|\bignore\b.*\binstruction",
    re.IGNORECASE)
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
BASE64_BLOB_MIN = 120  # longer tokens are also reported for review, even when they decode to plain text


def check_prose(rel, text, findings):
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, severity, pattern, message in PROSE_RULES:
            if pattern.search(line):
                findings.add("LLM01", severity, rule, f"{rel}:{lineno}", message)

    for match in HTML_COMMENT.finditer(text):
        body = match.group(1)
        if COMMENT_INSTRUCTION.search(body) or any(p.search(body) for p in HIGH_PROSE_PATTERNS):
            line = text.count("\n", 0, match.start()) + 1
            findings.add("LLM01", "HIGH", "prose-hidden-html-comment", f"{rel}:{line}",
                         "HTML comment contains instructions the reader will not see")

    for match in BASE64_TOKEN.finditer(text):
        if text[max(0, match.start() - 12):match.start()].endswith("base64,"):
            continue  # inline data URI, e.g. an image
        line = text.count("\n", 0, match.start()) + 1
        decoded = decode_base64_text(match.group(0))
        if decoded is not None and any(p.search(decoded) for p in HIGH_PROSE_PATTERNS):
            findings.add("LLM01", "HIGH", "prose-encoded-injection", f"{rel}:{line}",
                         "Base64 blob decodes to instruction-override text")
        elif len(match.group(0)) >= BASE64_BLOB_MIN:
            findings.add("LLM01", "MEDIUM", "prose-base64-blob", f"{rel}:{line}",
                         "Long base64 blob in prose; decode and review")


def decode_base64_text(blob):
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
        return raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None


# ---------------------------------------------------------------- hidden unicode

HIDDEN_RANGES = [
    (0x200B, 0x200F, "HIGH", "hidden-zero-width-or-bidi-mark", "Zero-width or bidi mark"),
    (0x202A, 0x202E, "HIGH", "hidden-bidi-override", "Bidi embedding or override character"),
    (0x2060, 0x2064, "HIGH", "hidden-invisible-operator", "Invisible operator or word joiner"),
    (0x2066, 0x2069, "HIGH", "hidden-bidi-isolate", "Bidi isolate character"),
    (0xE0000, 0xE007F, "CRITICAL", "hidden-unicode-tag-chars", "Unicode tag character (ASCII smuggling)"),
]


def check_unicode(rel, text, findings):
    counts = {}
    first = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        for index, char in enumerate(line):
            cp = ord(char)
            if cp == 0xFEFF and not (lineno == 1 and index == 0):
                key = ("HIGH", "hidden-byte-order-mark", "Byte order mark in the middle of a file")
            else:
                key = None
                for low, high, severity, rule, message in HIDDEN_RANGES:
                    if low <= cp <= high:
                        key = (severity, rule, message)
                        break
            if key:
                counts[key] = counts.get(key, 0) + 1
                first.setdefault(key, (lineno, cp))
    for key, count in counts.items():
        severity, rule, message = key
        lineno, cp = first[key]
        findings.add("LLM01", severity, rule, f"{rel}:{lineno}",
                     f"{message} U+{cp:04X}; {count} occurrence(s) in file")


# ---------------------------------------------------------------- MCP manifests

SECRET_KEY = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.IGNORECASE)
SECRET_VALUE = re.compile(r"sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
                          r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{20,}\.")
def is_reference(value):
    """True when the value pulls a secret from the environment instead of embedding it."""
    return "${" in value or "{env:" in value or re.fullmatch(r"\$[A-Z_][A-Z0-9_]*", value) is not None


def mcp_servers(doc):
    for key in ("mcpServers", "servers", "mcp"):
        block = doc.get(key)
        if isinstance(block, dict):
            return block
    return {}


def check_mcp(rel, path, findings):
    text, _ = read_text(path)
    try:
        doc = json.loads(text)
    except ValueError as exc:
        findings.add("LLM05", "HIGH", "unparseable-mcp-manifest", rel,
                     f"Cannot parse MCP manifest, so its servers cannot be checked: {exc}")
        return
    if not isinstance(doc, dict):
        findings.add("LLM05", "HIGH", "unparseable-mcp-manifest", rel, "MCP manifest is not a JSON object")
        return

    for name, cfg in mcp_servers(doc).items():
        if not isinstance(cfg, dict):
            continue
        loc = f"{rel}#{name}"
        command = cfg.get("command")
        if isinstance(command, str):
            raw_args = cfg.get("args", [])
            argv = [command] + [a for a in (raw_args if isinstance(raw_args, list) else []) if isinstance(a, str)]
        elif isinstance(command, list):
            argv = [a for a in command if isinstance(a, str)]
        else:
            argv = []
        if argv:
            exe = os.path.basename(argv[0]).lower()
            if exe in SHELL_INTERPRETERS:
                findings.add("LLM07", "HIGH", "mcp-shell-server", loc,
                             f"MCP server runs a shell interpreter ({exe}); it can execute arbitrary commands")

        env = cfg.get("env") or cfg.get("environment") or {}
        headers = cfg.get("headers") or {}
        for block_name, block in (("env", env), ("headers", headers)):
            if not isinstance(block, dict):
                continue
            for key, value in block.items():
                if not isinstance(value, str) or not value or is_reference(value):
                    continue
                if SECRET_KEY.search(key) or SECRET_VALUE.search(value):
                    findings.add("LLM06", "HIGH", "mcp-inline-secret", loc,
                                 f"Secret written inline in MCP {block_name}.{key}; reference an environment variable instead")

        url = cfg.get("url")
        if isinstance(url, str) and url:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or "").lower()
            if parsed.scheme == "https":
                continue
            if parsed.scheme == "http" and host in ("localhost", "127.0.0.1", "::1"):
                continue
            findings.add("LLM05", "HIGH", "mcp-non-https-url", loc,
                         f"MCP remote URL uses '{parsed.scheme or 'no'}' scheme; use https")


# ---------------------------------------------------------------- tool scope

TOOL_KEYS = {"tools", "allowed-tools", "allowed_tools"}
PERMISSION_KEYS = {"permission", "permissions"}


def frontmatter_lines(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return []
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return lines[1:index]
    return []


def tool_tokens(lines, start, inline):
    tokens = []
    if inline:
        raw = inline.strip().strip("[]")
        tokens.extend(t.strip().strip("\"'") for t in raw.split(",") if t.strip())
        return tokens
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("- "):
            tokens.append(stripped[2:].strip().strip("\"'"))
        elif stripped == "" or not line.startswith((" ", "\t")):
            break
    return tokens


def check_toolscope(rel, text, findings):
    lines = frontmatter_lines(text)
    in_permission = None  # indentation of an open permission block
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if in_permission is not None and indent <= in_permission:
            in_permission = None
        key, _, value = line.strip().partition(":")
        key = key.strip().strip("\"'")
        value = value.strip()
        loc = f"{rel}:{index + 2}"
        if key in TOOL_KEYS:
            for token in tool_tokens(lines, index + 1, value):
                name, _, arg = token.partition("(")
                arg = arg.rstrip(")").strip()
                if name == "*":
                    findings.add("LLM08", "HIGH", "tool-wildcard", loc, "Agent is granted every tool ('*')")
                elif name.lower() == "bash" and arg in ("", "*"):
                    findings.add("LLM08", "HIGH", "unrestricted-bash", loc,
                                 "Agent is granted unrestricted Bash; scope it, e.g. Bash(npm test:*)")
                elif name in ("Write", "Edit", "MultiEdit", "NotebookEdit") and not arg:
                    findings.add("LLM08", "MEDIUM", "unrestricted-write", loc,
                                 f"Agent is granted unrestricted {name}")
        elif key in PERMISSION_KEYS:
            if value.strip('"\'') == "allow":
                findings.add("LLM08", "HIGH", "permission-allow-all", loc, "Permission block allows everything")
            elif value == "":
                in_permission = indent
        elif in_permission is not None:
            perm = key.strip('"\'')
            verdict = value.strip('"\'')
            if perm == "bash" and verdict == "allow":
                findings.add("LLM08", "HIGH", "bash-permission-allow", loc, "Bash permission set to allow")
            elif perm == "*" and verdict == "allow":
                findings.add("LLM08", "HIGH", "wildcard-permission-allow", loc,
                             "Wildcard permission set to allow")
            elif perm in ("edit", "write") and verdict == "allow":
                findings.add("LLM08", "MEDIUM", "write-permission-allow", loc,
                             f"{perm} permission set to allow")


# ---------------------------------------------------------------- shell

def is_shell_script(path, text):
    if os.path.splitext(path)[1].lower() in SHELL_EXTS:
        return True
    first = text.split("\n", 1)[0]
    return first.startswith("#!") and any(s in first for s in ("sh", "bash", "zsh", "ksh"))


def run_shellcheck(paths, root, findings):
    exe = shutil.which("shellcheck")
    if exe is None:
        fail("shellcheck is required for shell checks. Install it, or set check-shell-scripts to 'false'.")
    level_map = {"error": ("HIGH", "error"), "warning": ("MEDIUM", "warning"),
                 "info": ("LOW", "info"), "style": ("LOW", "style")}
    for start in range(0, len(paths), 100):
        chunk = paths[start:start + 100]
        proc = subprocess.run([exe, "-f", "json", "--"] + chunk, cwd=root,
                              capture_output=True, text=True, check=False)
        if proc.returncode not in (0, 1):
            fail(f"shellcheck failed with exit {proc.returncode}: {proc.stderr.strip()}")
        try:
            comments = json.loads(proc.stdout) if proc.stdout.strip() else []
        except ValueError as exc:
            fail(f"cannot parse shellcheck output: {exc}")
        for item in comments:
            severity, _ = level_map.get(item.get("level", "warning"), ("MEDIUM", "warning"))
            location = f"{item.get('file', '?')}:{item.get('line', 0)}"
            findings.add("SHELL", severity, f"shellcheck:SC{item.get('code', '0')}", location,
                         item.get("message", "shellcheck finding"))


# ---------------------------------------------------------------- scan

def require_dir(path):
    if not path or not os.path.isdir(path):
        fail(f"source path is not a directory: {path!r}")
    return os.path.realpath(path)


def results_location(results_dir, source):
    """Validate the results directory and return its absolute path.

    The path must be literally equal to its realpath, so no component may be a
    symlink. It must not be the source tree or one of its parents, since excluding
    it would hide the scanned tree.
    """
    if not results_dir:
        fail("results-dir is required")
    results = os.path.abspath(results_dir)
    if os.path.realpath(results) != results:
        fail(f"results-dir path contains a symlink (resolves to {os.path.realpath(results)}); refusing to write there")
    if results == source or source.startswith(results + os.sep):
        fail("results-dir must not be the source directory or one of its parents")
    return results


def cmd_prepare(args):
    source = require_dir(args.source)
    results = results_location(args.results_dir, source)
    os.makedirs(results, exist_ok=True)
    findings = os.path.abspath(args.findings)
    if os.path.dirname(findings) != results:
        fail("findings file must be inside results-dir")
    if os.path.islink(findings):
        fail("findings file is a symlink; refusing to write through it")
    open(findings, "w", encoding="utf-8").close()
    return 0


def run_text_checks(rel, path, text, base, ext, flags, findings, agent_only):
    """Run the checks for one text file. Agent-asset files inside node_modules get
    only the prompt-facing checks; everything else also gets code and shell checks."""
    if flags["mcp"] and base in MCP_BASENAMES:
        check_mcp(rel, path, findings)
    if flags["unicode"]:
        check_unicode(rel, text, findings)
    if flags["prose"] and ext in PROSE_EXTS:
        check_prose(rel, text, findings)
    if flags["toolscope"] and ext in FRONTMATTER_EXTS:
        check_toolscope(rel, text, findings)
    if agent_only:
        return None
    if any(flags[k] for k in ("prompt_injection", "pii", "serialization", "output")):
        check_code(rel, text, flags, findings)
    return flags["shell"] and is_shell_script(path, text)


def cmd_scan(args):
    source = require_dir(args.source)
    results = results_location(args.results_dir, source)
    flags = {name: env_flag(env) for name, env in CHECK_ENV.items()}
    open(args.findings, "a", encoding="utf-8").close()
    findings = Findings(args.findings)
    shell_candidates = []

    for path, agent_only in iter_files(source, results):
        rel = os.path.relpath(path, source)
        if agent_only is None:
            target = os.path.realpath(path)
            if target != source and not target.startswith(source + os.sep):
                findings.add("CODE", "MEDIUM", "symlink-escapes-source", rel,
                             f"symlink resolves outside the scanned tree ({target}); its content is not scanned")
            continue
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        if ext in BINARY_EXTS:
            continue
        text, has_controls = read_text(path)
        if has_controls:
            if ext in TEXT_EXTS or is_agent_file(base):
                match = CONTROL_CHARS.search(text)
                line = text.count("\n", 0, match.start()) + 1
                findings.add("LLM01", "HIGH", "control-characters-in-text", f"{rel}:{line}",
                             "NUL or control characters in a text file can hide instructions from review")
            else:
                findings.add("CODE", "LOW", "unscanned-binary-content", rel,
                             "NUL or control bytes and no recognised text extension; not scanned as text")
                continue
        is_shell = run_text_checks(rel, path, text, base, ext, flags, findings, agent_only)
        if is_shell:
            shell_candidates.append(rel)

    if flags["shell"]:
        run_shellcheck(sorted(shell_candidates), source, findings)
    print(f"scanned_root={source}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- consolidate

THRESHOLD_FAILS_AT = {
    "CRITICAL": ("CRITICAL",),
    "HIGH": ("CRITICAL", "HIGH"),
    "MEDIUM": ("CRITICAL", "HIGH", "MEDIUM"),
    "LOW": ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
}


def read_findings(path):
    rows = []
    if not os.path.isfile(path):
        # The validate step creates this file. Its absence means the scan never ran,
        # and that must not read as "no findings".
        fail(f"findings file not found: {path}. The scan did not run.")
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            parts = raw.split("\t")
            if len(parts) != 5 or parts[0] not in CATEGORIES or parts[1] not in SEVERITY_RANK:
                fail(f"malformed findings line: {raw!r}")
            rows.append(parts)
    return rows


def cmd_consolidate(args):
    threshold = args.threshold.strip().upper()
    if threshold not in THRESHOLD_FAILS_AT:
        fail(f"fail-on-severity must be one of {', '.join(THRESHOLD_FAILS_AT)}, got '{args.threshold}'")
    rows = read_findings(args.findings)

    by_severity = {s: 0 for s in SEVERITIES}
    by_category = {c: 0 for c in CATEGORIES}
    for category, severity, *_ in rows:
        by_severity[severity] += 1
        by_category[category] += 1

    blocking = sum(by_severity[s] for s in THRESHOLD_FAILS_AT[threshold])
    passed = blocking == 0
    owasp = " ".join(f"{c}={by_category[c]}" for c in OWASP_CATEGORIES)
    flagged = sum(1 for c in OWASP_CATEGORIES if by_category[c] > 0)

    print("=" * 39, file=sys.stderr)
    print("  LLM Security Scan Summary", file=sys.stderr)
    print("=" * 39, file=sys.stderr)
    print(f"  Total findings : {len(rows)}", file=sys.stderr)
    for s in SEVERITIES:
        print(f"  {s:<15}: {by_severity[s]}", file=sys.stderr)
    print(f"  OWASP LLM categories with findings: {flagged}/{len(OWASP_CATEGORIES)}", file=sys.stderr)
    for c in CATEGORIES:
        print(f"    {c:<6} {CATEGORIES[c]:<32} {by_category[c]}", file=sys.stderr)
    print(f"  Threshold {threshold}: {'PASS' if passed else 'FAIL'} ({blocking} blocking)", file=sys.stderr)
    print("=" * 39, file=sys.stderr)

    print(f"vulnerabilities-found={len(rows)}")
    print(f"critical-count={by_severity['CRITICAL']}")
    print(f"high-count={by_severity['HIGH']}")
    print(f"findings-by-category={json.dumps(by_category, sort_keys=True)}")
    print(f"owasp-summary={owasp}")
    print(f"owasp-categories-with-findings={flagged}")
    print(f"passed={'true' if passed else 'false'}")
    return 0


# ---------------------------------------------------------------- main

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("provider")
    p.add_argument("--source", required=True)
    p.set_defaults(func=cmd_provider)

    p = sub.add_parser("sarif")
    p.add_argument("--sarif", required=True)
    p.add_argument("--findings", required=True)
    p.set_defaults(func=cmd_sarif)

    p = sub.add_parser("prepare")
    p.add_argument("--source", required=True)
    p.add_argument("--results-dir", required=True)
    p.add_argument("--findings", required=True)
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("scan")
    p.add_argument("--source", required=True)
    p.add_argument("--results-dir", required=True)
    p.add_argument("--findings", required=True)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("consolidate")
    p.add_argument("--findings", required=True)
    p.add_argument("--threshold", required=True)
    p.set_defaults(func=cmd_consolidate)
    return parser


def main(argv):
    args = build_parser().parse_args(argv[1:])
    try:
        return args.func(args)
    except CheckError as exc:
        print(f"::error::osdo-llm-scan: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
