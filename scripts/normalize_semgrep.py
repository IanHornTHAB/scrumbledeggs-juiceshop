#!/usr/bin/env python3
"""
normalize_semgrep.py — Normalisiert Semgrep JSON-Output in das einheitliche
Vulnerability-Report-Schema.

HINWEIS: Wenn Semgrep keine Dateien scannt (z.B. wegen falscher Sprach-
         erkennung), gibt es ein leeres results-Array. Das Script schreibt
         dann einen validen Report mit leeren findings.

Verwendung:
    python3 normalize_semgrep.py \
        --input    semgrep-report.json \
        --output   reports/findings-semgrep.json \
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
# Severity-Mapping
# Semgrep verwendet: ERROR, WARNING, INFO (und manchmal CRITICAL)
# ---------------------------------------------------------------------------
SEVERITY_MAP = {
    "critical": "critical",
    "error":    "high",
    "warning":  "medium",
    "info":     "low",
    "low":      "low",
}


def parse_severity(result: dict) -> str:
    """Severity aus extra.severity oder severity Feld."""
    raw = (
        result.get("extra", {}).get("severity", "")
        or result.get("severity", "")
    ).lower()
    return SEVERITY_MAP.get(raw, "low")


def parse_cwe(result: dict) -> str | None:
    """
    CWE aus extra.metadata.cwe extrahieren.
    Semgrep liefert CWE als Liste oder String.
    """
    metadata = result.get("extra", {}).get("metadata", {})

    cwe_val = metadata.get("cwe") or metadata.get("cwe-id")
    if not cwe_val:
        return None

    # Liste -> erstes Element nehmen
    if isinstance(cwe_val, list):
        cwe_val = cwe_val[0] if cwe_val else None

    if not cwe_val:
        return None

    cwe_str = str(cwe_val).strip()

    # Bereits im Format CWE-XXX
    if cwe_str.upper().startswith("CWE-"):
        return cwe_str.upper()

    # Nur Nummer
    if cwe_str.isdigit():
        return f"CWE-{cwe_str}"

    return cwe_str


def build_advisory_url(cwe: str | None) -> str | None:
    if cwe and cwe.upper().startswith("CWE-"):
        number = cwe.split("-")[1]
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    return None


def make_id(tool: str, check_id: str, file_path: str, line: int | None) -> str:
    raw = f"{tool}:{check_id}:{file_path}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def process_result(result: dict) -> dict:
    check_id  = result.get("check_id", "unknown")
    file_path = result.get("path", "")

    start     = result.get("start", {})
    end       = result.get("end", {})
    line_start = start.get("line")
    line_end   = end.get("line")

    extra     = result.get("extra", {})
    message   = extra.get("message", "")
    severity  = parse_severity(result)
    cwe       = parse_cwe(result)
    advisory  = build_advisory_url(cwe)

    # Vulnerability-Name aus check_id ableiten
    # z.B. "javascript.lang.security.audit.sqli.sequelize-sqli" -> "sequelize-sqli"
    name_parts = check_id.split(".")
    vuln_name  = name_parts[-1].replace("-", " ").replace("_", " ").title()
    if not vuln_name:
        vuln_name = check_id

    return {
        "id":                 make_id("semgrep", check_id, file_path, line_start),
        "vulnerability_name": vuln_name,
        "severity":           severity,
        "description":        message or f"Semgrep rule {check_id} matched.",
        "affected_component": file_path,
        "location": {
            "file":       file_path or None,
            "line_start": line_start,
            "line_end":   line_end,
            "url":        None,
        },
        "cwe":          cwe,
        "cve":          None,
        "advisory_url": advisory,
    }


def main():
    parser = argparse.ArgumentParser(description="Normalize Semgrep output to unified schema.")
    parser.add_argument("--input",       required=True, help="Pfad zur semgrep-report.json")
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

            results = data.get("results", [])
            errors  = data.get("errors", [])

            if errors:
                print(f"[WARN] {len(errors)} Semgrep-Fehler im Report:", file=sys.stderr)
                for err in errors:
                    print(f"  - {err.get('short_msg', err)}", file=sys.stderr)

            print(f"[INFO] {len(results)} Semgrep-Results gefunden", file=sys.stderr)

            for result in results:
                try:
                    finding = process_result(result)
                    all_findings.append(finding)
                except Exception as e:
                    print(f"[ERROR] Result übersprungen: {e}", file=sys.stderr)

        except Exception as e:
            print(f"[ERROR] Fehler beim Verarbeiten: {e}", file=sys.stderr)

    report = {
        "meta": {
            "tool_name":       "semgrep",
            "scan_type":       "sast",
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


if __name__ == "__main__":
    main()
