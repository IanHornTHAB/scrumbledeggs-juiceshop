#!/usr/bin/env python3
"""
normalize_gitleaks.py — Normalisiert Gitleaks JSON-Output in das einheitliche
Vulnerability-Report-Schema.

WICHTIG: Das Secret-Feld wird zwingend maskiert (***).
         Der Klartext-Wert wird niemals in den Output geschrieben.

Verwendung:
    python3 normalize_gitleaks.py \
        --input    gitleaks-report.json \
        --output   reports/findings-gitleaks.json \
        --pipeline-id "$CI_PIPELINE_ID" \
        --commit-sha  "$CI_COMMIT_SHA"
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# RuleID -> CWE Mapping
# ---------------------------------------------------------------------------
RULE_CWE_MAP = {
    "generic-api-key":       "CWE-798",
    "jwt":                   "CWE-798",
    "private-key":           "CWE-321",
    "aws-access-token":      "CWE-798",
    "github-pat":            "CWE-798",
    "gitlab-pat":            "CWE-798",
    "google-api-key":        "CWE-798",
    "password-in-url":       "CWE-256",
    "generic-secret":        "CWE-798",
}

# Alle Secret-Findings sind mindestens HIGH
# Private Keys und direkte Credentials sind CRITICAL
RULE_SEVERITY_MAP = {
    "private-key":           "critical",
    "jwt":                   "high",
    "generic-api-key":       "high",
    "aws-access-token":      "critical",
    "github-pat":            "critical",
    "gitlab-pat":            "critical",
    "google-api-key":        "high",
    "password-in-url":       "high",
    "generic-secret":        "high",
}


def get_cwe(rule_id: str) -> str:
    return RULE_CWE_MAP.get(rule_id, "CWE-798")


def get_severity(rule_id: str) -> str:
    return RULE_SEVERITY_MAP.get(rule_id, "high")


def build_advisory_url(cwe: str) -> str:
    number = cwe.split("-")[1]
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


def make_id(tool: str, fingerprint: str) -> str:
    """
    Gitleaks liefert einen eigenen Fingerprint (commit:file:rule:line).
    Dieser ist bereits deterministisch — wir hashen ihn nochmals
    für einen einheitlichen 16-Zeichen-Hash.
    """
    raw = f"{tool}:{fingerprint}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def mask_secret(value: str) -> str:
    """Maskiert den Secret-Wert. Niemals Klartext speichern."""
    return "***"


def process_entry(entry: dict) -> dict:
    rule_id     = entry.get("RuleID", "unknown")
    description = entry.get("Description", "")
    file_path   = entry.get("File", "")
    start_line  = entry.get("StartLine")
    end_line    = entry.get("EndLine")
    fingerprint = entry.get("Fingerprint", "")
    commit      = entry.get("Commit", "")
    author      = entry.get("Author", "")

    # Secret IMMER maskieren — niemals Klartext
    masked_match = mask_secret(entry.get("Match", ""))

    cwe      = get_cwe(rule_id)
    severity = get_severity(rule_id)

    try:
        line_start = int(start_line) if start_line else None
        line_end   = int(end_line)   if end_line   else None
    except (ValueError, TypeError):
        line_start = None
        line_end   = None

    desc = (
        f"{description} "
        f"Found in commit {commit[:8] if commit else 'unknown'} "
        f"by {author}. "
        f"Match: {masked_match}."
    )

    return {
        "id":                 make_id("gitleaks", fingerprint),
        "vulnerability_name": f"Hardcoded Secret: {rule_id}",
        "severity":           severity,
        "description":        desc.strip(),
        "affected_component": file_path,
        "location": {
            "file":       file_path or None,
            "line_start": line_start,
            "line_end":   line_end,
            "url":        None,
        },
        "cwe":          cwe,
        "cve":          None,
        "advisory_url": build_advisory_url(cwe),
    }


def main():
    parser = argparse.ArgumentParser(description="Normalize Gitleaks output to unified schema.")
    parser.add_argument("--input",       required=True, help="Pfad zur gitleaks-report.json")
    parser.add_argument("--output",      required=True, help="Ausgabepfad fuer normalized JSON.")
    parser.add_argument("--pipeline-id", default=None,  help="$CI_PIPELINE_ID")
    parser.add_argument("--commit-sha",  default=None,  help="$CI_COMMIT_SHA")
    args = parser.parse_args()

    all_findings = []

    if not os.path.isfile(args.input):
        print(f"[WARN] Input-Datei nicht gefunden: {args.input}", file=sys.stderr)
    else:
        try:
            with open(args.input) as f:
                data = json.load(f)

            # Gitleaks gibt eine Liste oder null aus
            if data is None:
                data = []

            if not isinstance(data, list):
                print(f"[WARN] Unerwartetes Format: {type(data)}", file=sys.stderr)
                data = []

            print(f"[INFO] {len(data)} Einträge gefunden", file=sys.stderr)

            for entry in data:
                try:
                    finding = process_entry(entry)
                    all_findings.append(finding)
                except Exception as e:
                    print(f"[ERROR] Eintrag übersprungen: {e}", file=sys.stderr)

        except Exception as e:
            print(f"[ERROR] Fehler beim Verarbeiten: {e}", file=sys.stderr)

    report = {
        "meta": {
            "tool_name":       "gitleaks",
            "scan_type":       "secret-detection",
            "pipeline_run_id": args.pipeline_id,
            "commit_sha":      args.commit_sha,
            "timestamp":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "findings": all_findings,
    }

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Report geschrieben: {args.output} ({len(all_findings)} Findings)", file=sys.stderr)

    # Sicherheitscheck: kein Secret im Output
    with open(args.output) as f:
        content = f.read()
    for entry in (json.load(open(args.input)) or []):
        secret = entry.get("Secret", "")
        if secret and secret in content:
            print(f"[CRITICAL] Secret-Leak im Output erkannt! Abbruch.", file=sys.stderr)
            os.remove(args.output)
            sys.exit(1)

    print("[INFO] Secret-Check bestanden — kein Klartext im Output.", file=sys.stderr)


if __name__ == "__main__":
    main()
