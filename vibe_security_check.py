"""Static, non-executing security preflight checks for rapid-development projects."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", "__pycache__"}
TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".md"}
SENSITIVE_NAMES = {".env", ".env.production", "id_rsa", "id_ed25519", "service-account.json", "credentials.json"}
PLACEHOLDERS = {"replace-me", "changeme", "example", "placeholder", "your-key-here", "dummy-value"}
PENALTIES = {"critical": 30, "high": 15, "medium": 7, "low": 2}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    evidence: str
    risk: str
    remediation: str


RULES = [
    ("PY-DYNAMIC-EXEC", "high", re.compile(r"\b(?:eval|exec)\s*\("), "Dynamic code execution can run attacker-controlled input.", "Remove dynamic execution or constrain input with a safe parser."),
    ("PY-UNSAFE-SHELL", "high", re.compile(r"(?:subprocess\.|\brun\s*\().*shell\s*=\s*True"), "Shell execution may allow command injection.", "Use an argument array with shell disabled and validate every argument."),
    ("TLS-VERIFY-DISABLED", "high", re.compile(r"verify\s*=\s*False"), "Disabled certificate verification enables interception attacks.", "Enable certificate verification and configure a trusted CA when needed."),
    ("DEBUG-PRODUCTION", "medium", re.compile(r"(?:DEBUG\s*=\s*True|debug\s*:\s*true|debug\s*=\s*true)", re.I), "Debug mode can expose internal details or interactive consoles.", "Disable debug mode in production and use environment-specific configuration."),
    ("CORS-WILDCARD", "medium", re.compile(r"(?:allow_origins|Access-Control-Allow-Origin|origin)\s*[:=]\s*[\[\"']*\*", re.I), "Wildcard cross-origin access can expose sensitive application data.", "Allow only the trusted origins required by the application."),
    ("WEB-UNSAFE-HTML", "high", re.compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()"), "Direct HTML injection can create cross-site scripting risk.", "Render text safely or sanitize HTML with a maintained, context-aware library."),
    ("COOKIE-INSECURE", "medium", re.compile(r"(?:secure\s*[:=]\s*false|httponly\s*[:=]\s*false)", re.I), "Session cookies without protections are easier to steal or misuse.", "Enable Secure, HttpOnly, and an appropriate SameSite policy."),
]

SECRET_ASSIGNMENT = re.compile(r"(?i)\b(api[_-]?key|secret|password|database_url|token)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']")


def redact(value: str) -> str:
    return value[:2] + "…" + value[-2:] if len(value) >= 6 else "[redacted]"


def walk_files(root: Path, max_files: int = 5_000, max_bytes: int = 1_000_000) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts) or not path.is_file():
            continue
        if path.stat().st_size > max_bytes or (path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in SENSITIVE_NAMES):
            continue
        count += 1
        if count > max_files:
            raise ValueError(f"scan stopped after {max_files} files; narrow the target or raise --max-files")
        yield path


def scan(root: Path, max_files: int = 5_000) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("target must be an existing directory")
    findings: list[Finding] = []
    scanned = 0
    for path in walk_files(root, max_files=max_files):
        scanned += 1
        relative = path.relative_to(root).as_posix()
        if path.name in SENSITIVE_NAMES or path.suffix == ".pem":
            findings.append(Finding("SENSITIVE-FILE", "critical", relative, 1, path.name, "Sensitive files may be committed or deployed publicly.", "Remove the file from source control, rotate exposed credentials, and use a secret manager."))
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for rule_id, severity, pattern, risk, remediation in RULES:
                if pattern.search(line):
                    findings.append(Finding(rule_id, severity, relative, number, line.strip()[:160], risk, remediation))
            for match in SECRET_ASSIGNMENT.finditer(line):
                value = match.group(2).strip()
                if value.lower() not in PLACEHOLDERS and not value.startswith(("${", "{{", "process.env", "os.getenv")):
                    findings.append(Finding("HARDCODED-SECRET", "critical", relative, number, f"{match.group(1)}={redact(value)}", "A credential appears to be stored in source code.", "Rotate it if real, remove it from history, and load it from a managed secret store."))
    if not (root / ".gitignore").exists():
        findings.append(Finding("REPO-NO-GITIGNORE", "low", ".", 1, ".gitignore not found", "Generated files and local secrets are easier to commit accidentally.", "Add a framework-appropriate .gitignore including environment and credential files."))
    unique = list({(x.rule_id, x.file, x.line): x for x in findings}.values())
    counts = {severity: sum(x.severity == severity for x in unique) for severity in PENALTIES}
    score = max(0, 100 - sum(PENALTIES[x.severity] for x in unique))
    risk = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "clear"
    return {"tool": "Vibe Security Check", "target": root.name, "files_scanned": scanned, "score": score, "risk": risk, "counts": counts, "findings": [asdict(x) for x in sorted(unique, key=lambda x: (-PENALTIES[x.severity], x.file, x.line))], "limitations": "Static preflight only; findings require human verification and do not prove exploitability or security."}


def markdown(report: dict) -> str:
    lines = ["# Vibe Security Check Report", "", f"**Target:** `{report['target']}`  ", f"**Score:** {report['score']}/100  ", f"**Risk:** {report['risk']}  ", f"**Files scanned:** {report['files_scanned']}", "", "## Summary", "", "| Critical | High | Medium | Low |", "|---:|---:|---:|---:|", f"| {report['counts']['critical']} | {report['counts']['high']} | {report['counts']['medium']} | {report['counts']['low']} |", "", "## Findings", ""]
    if not report["findings"]:
        lines.append("No findings from the configured checks. This does not prove the application is secure.")
    for item in report["findings"]:
        evidence = item["evidence"].replace("`", "'")
        lines.extend([f"### [{item['severity'].upper()}] {item['rule_id']}", "", f"- Location: `{item['file']}:{item['line']}`", f"- Evidence: `{evidence}`", f"- Risk: {item['risk']}", f"- Recommendation: {item['remediation']}", ""])
    lines.extend(["## Limitations", "", report["limitations"], ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run non-executing security preflight checks on a local project.")
    parser.add_argument("target", type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-files", type=int, default=5_000)
    args = parser.parse_args()
    try:
        report = scan(args.target, max_files=args.max_files)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    rendered = markdown(report) if args.format == "markdown" else json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    raise SystemExit(1 if report["counts"]["critical"] or report["counts"]["high"] else 0)


if __name__ == "__main__":
    main()

