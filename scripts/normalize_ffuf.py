#!/usr/bin/env python3
"""
normalize_ffuf.py — Normalisiert ffuf-Output-Dateien in das einheitliche
Vulnerability-Report-Schema.

Liest alle JSON-Dateien aus dem Fuzzing-Reports-Verzeichnis ein und
bewertet jeden Treffer anhand von Payload-Typ und HTTP-Statuscode.

Verwendung:
    python3 normalize_ffuf.py \
        --input-dir reports/fuzzing \
        --output    reports/findings-ffuf.json \
        --pipeline-id "$CI_PIPELINE_ID" \
        --commit-sha "$CI_COMMIT_SHA"
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Payload-Klassifikation
# Ordnet bekannte Angriffs-Payloads einer Schwachstellenklasse zu.
# ---------------------------------------------------------------------------
PAYLOAD_RULES = [
    {
        "keywords":  ["OR 1=1", "' OR", "\" OR", "1=1--", "UNION SELECT", "' --"],
        "vuln_name": "SQL Injection",
        "cwe":       "CWE-89",
        "base_severity": "high",
    },
    {
        "keywords":  ["<script>", "alert(", "onerror=", "onload=", "javascript:"],
        "vuln_name": "Cross-Site Scripting (XSS)",
        "cwe":       "CWE-79",
        "base_severity": "high",
    },
    {
        "keywords":  ["../", "..\\", "/etc/passwd", "..%2F", "%2e%2e"],
        "vuln_name": "Path Traversal",
        "cwe":       "CWE-22",
        "base_severity": "high",
    },
    {
        "keywords":  ["%00", "\x00", "null byte"],
        "vuln_name": "Null Byte Injection",
        "cwe":       "CWE-158",
        "base_severity": "medium",
    },
]

# HTTP-Statuscodes die auf einen erfolgreichen Angriff oder
# ein unerwartetes Verhalten hinweisen.
SUSPICIOUS_STATUSES = {200, 201, 400, 500, 502, 503}
# Statuscodes die erwartetes Verhalten darstellen (kein Finding).
EXPECTED_STATUSES   = {401, 403, 404}


def classify_payload(payload: str):
    """Gibt das passende Payload-Regel-Dict zurueck oder None."""
    payload_upper = payload.upper()
    for rule in PAYLOAD_RULES:
        for kw in rule["keywords"]:
            if kw.upper() in payload_upper:
                return rule
    return None


def severity_from_status(base_severity: str, status: int) -> str:
    """
    Erhoeht den Schweregrad wenn der HTTP-Status auf einen
    tatsaechlich erfolgreichen Angriff hindeutet.

    - 200 bei Injection-Payload -> eine Stufe hoeher (max. critical)
    - 500 -> bleibt bei base oder wird auf medium angehoben
    - Alles andere -> base_severity beibehalten
    """
    scale = ["info", "low", "medium", "high", "critical"]

    if status == 200:
        idx = scale.index(base_severity)
        return scale[min(idx + 1, len(scale) - 1)]
    if status == 500:
        idx = scale.index(base_severity)
        return scale[max(idx, scale.index("medium"))]
    return base_severity


def make_id(tool: str, rule_id: str, location: str) -> str:
    """Deterministischer SHA-256-Fingerprint (16 Zeichen)."""
    raw = f"{tool}:{rule_id}:{location}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_advisory_url(cwe: str | None) -> str | None:
    if cwe and cwe.upper().startswith("CWE-"):
        number = cwe.split("-")[1]
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    return None


def describe_finding(payload: str, status: int, url: str, method: str) -> str:
    return (
        f"ffuf fuzzed {method} {url} with payload {payload!r}. "
        f"Server responded with HTTP {status}, indicating potential vulnerability."
    )


def process_file(filepath: str) -> list[dict]:
    """Verarbeitet eine einzelne ffuf-JSON-Datei und gibt Findings zurueck."""
    findings = []

    with open(filepath) as f:
        data = json.load(f)

    results  = data.get("results", [])
    cmd      = data.get("commandline", "")
    method   = data.get("config", {}).get("method", "GET")

    for result in results:
        status  = result.get("status", 0)
        url     = result.get("url", "")
        payload = result.get("input", {}).get("FUZZ", "")

        # Erwartete Statuscodes -> kein Finding
        if status in EXPECTED_STATUSES:
            continue

        rule = classify_payload(payload)

        if rule:
            # Bekannter Angriffs-Payload
            final_severity = severity_from_status(rule["base_severity"], status)
            vuln_name      = rule["vuln_name"]
            cwe            = rule["cwe"]
        elif status == 500:
            # Unbekannter Payload hat Server-Fehler ausgeloest
            final_severity = "medium"
            vuln_name      = "Unexpected Server Error (500)"
            cwe            = "CWE-390"
        else:
            # Kein bekannter Payload, kein auffaelliger Status -> ueberspringen
            continue

        location_str = url
        finding_id   = make_id("ffuf", f"{rule['cwe'] if rule else 'CWE-390'}:{payload}", location_str)

        findings.append({
            "id":                  finding_id,
            "vulnerability_name":  vuln_name,
            "severity":            final_severity,
            "description":         describe_finding(payload, status, url, method),
            "affected_component":  url,
            "location": {
                "file":       None,
                "line_start": None,
                "line_end":   None,
                "url":        url,
            },
            "cwe":          cwe,
            "cve":          None,
            "advisory_url": build_advisory_url(cwe),
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Normalize ffuf output to unified schema.")
    parser.add_argument("--input-dir",   required=True, help="Verzeichnis mit ffuf JSON-Dateien.")
    parser.add_argument("--output",      required=True, help="Ausgabepfad fuer normalized JSON.")
    parser.add_argument("--pipeline-id", default=None,  help="$CI_PIPELINE_ID")
    parser.add_argument("--commit-sha",  default=None,  help="$CI_COMMIT_SHA")
    args = parser.parse_args()

    all_findings = []
    errors       = []

    if not os.path.isdir(args.input_dir):
        print(f"[WARN] Input-Verzeichnis nicht gefunden: {args.input_dir}", file=sys.stderr)
    else:
        for filename in sorted(os.listdir(args.input_dir)):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(args.input_dir, filename)
            try:
                found = process_file(filepath)
                print(f"[INFO] {filename}: {len(found)} Finding(s)", file=sys.stderr)
                all_findings.extend(found)
            except Exception as e:
                msg = f"Fehler beim Verarbeiten von {filename}: {e}"
                print(f"[ERROR] {msg}", file=sys.stderr)
                errors.append(msg)

    report = {
        "meta": {
            "tool_name":       "ffuf",
            "scan_type":       "fuzzing",
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

    if errors:
        print(f"[WARN] {len(errors)} Fehler aufgetreten, aber Report wurde trotzdem geschrieben.", file=sys.stderr)


if __name__ == "__main__":
    main()
