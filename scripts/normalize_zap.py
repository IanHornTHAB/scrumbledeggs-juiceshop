#!/usr/bin/env python3
"""
normalize_zap.py — Normalisiert ZAP DAST JSON-Output in das einheitliche
Vulnerability-Report-Schema.

ZAP gibt pro Alert eine Liste von Instanzen (betroffene URLs) aus.
Jede Instanz wird als eigenes Finding behandelt, da URL und Parameter
sich unterscheiden können.

Verwendung:
    python3 normalize_zap.py \
        --input    reports/zap-report.json \
        --output   reports/findings-zap.json \
        --pipeline-id "$CI_PIPELINE_ID" \
        --commit-sha  "$CI_COMMIT_SHA"
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Severity-Mapping
# ZAP verwendet riskcode (0-3) und riskdesc ("Low (Medium)" etc.)
# ---------------------------------------------------------------------------
RISKCODE_MAP = {
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
}

# riskdesc-Prefix zu Severity
RISKDESC_MAP = {
    "high":          "high",
    "medium":        "medium",
    "low":           "low",
    "informational": "info",
    "info":          "info",
}


def parse_severity(alert: dict) -> str:
    """Severity aus riskcode oder riskdesc ableiten."""
    riskcode = alert.get("riskcode")
    if riskcode is not None:
        try:
            return RISKCODE_MAP.get(int(riskcode), "info")
        except (ValueError, TypeError):
            pass

    riskdesc = alert.get("riskdesc", "").lower()
    for key, val in RISKDESC_MAP.items():
        if riskdesc.startswith(key):
            return val

    return "info"


def parse_cwe(alert: dict) -> str | None:
    """CWE-ID aus cweid-Feld oder reference-Text extrahieren."""
    cweid = alert.get("cweid")
    if cweid and str(cweid).strip() not in ("", "0", "-1"):
        return f"CWE-{cweid}"

    reference = alert.get("reference", "")
    matches = re.findall(r"cwe\.mitre\.org/data/definitions/(\d+)", reference)
    if matches:
        return f"CWE-{matches[0]}"

    return None


def build_advisory_url(cwe: str | None) -> str | None:
    if cwe and cwe.upper().startswith("CWE-"):
        number = cwe.split("-")[1]
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    return None


def strip_html(text: str) -> str:
    """Einfaches HTML-Tag-Stripping fuer Beschreibungsfelder."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def make_id(tool: str, plugin_id: str, uri: str) -> str:
    """Deterministischer SHA-256-Fingerprint (16 Zeichen)."""
    raw = f"{tool}:{plugin_id}:{uri}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def process_alert(alert: dict) -> list[dict]:
    """
    Verarbeitet einen ZAP-Alert und gibt eine Liste von Findings zurueck —
    eines pro Instanz (betroffene URL).
    """
    findings    = []
    plugin_id   = str(alert.get("pluginid", alert.get("alertRef", "unknown")))
    name        = alert.get("name", alert.get("alert", "Unknown Alert"))
    severity    = parse_severity(alert)
    description = strip_html(alert.get("desc", ""))
    solution    = strip_html(alert.get("solution", ""))
    cwe         = parse_cwe(alert)
    advisory    = build_advisory_url(cwe)

    full_desc = description
    if solution:
        full_desc += f" Solution: {solution}"

    instances = alert.get("instances", [])

    # Kein instances-Array -> ein generisches Finding fuer den Alert
    if not instances:
        uri = alert.get("url", "")
        findings.append({
            "id":                 make_id("zap", plugin_id, uri),
            "vulnerability_name": name,
            "severity":           severity,
            "description":        full_desc,
            "affected_component": uri or "unknown",
            "location": {
                "file":       None,
                "line_start": None,
                "line_end":   None,
                "url":        uri or None,
            },
            "cwe":          cwe,
            "cve":          None,
            "advisory_url": advisory,
        })
        return findings

    # Pro Instanz ein Finding
    for instance in instances:
        uri    = instance.get("uri", "")
        method = instance.get("method", "GET")
        param  = instance.get("param", "")
        attack = instance.get("attack", "")

        inst_desc = full_desc
        if param:
            inst_desc += f" Parameter: {param}."
        if attack:
            inst_desc += f" Attack: {attack}."

        location_key = f"{method}:{uri}:{param}"

        findings.append({
            "id":                 make_id("zap", plugin_id, location_key),
            "vulnerability_name": name,
            "severity":           severity,
            "description":        inst_desc.strip(),
            "affected_component": uri,
            "location": {
                "file":       None,
                "line_start": None,
                "line_end":   None,
                "url":        uri,
            },
            "cwe":          cwe,
            "cve":          None,
            "advisory_url": advisory,
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Normalize ZAP JSON output to unified schema.")
    parser.add_argument("--input",       required=True, help="Pfad zur zap-report.json")
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

            sites = data.get("site", [])
            for site in sites:
                alerts = site.get("alerts", [])
                print(f"[INFO] Site {site.get('@host','?')}: {len(alerts)} Alerts", file=sys.stderr)
                for alert in alerts:
                    findings = process_alert(alert)
                    all_findings.extend(findings)

        except Exception as e:
            print(f"[ERROR] Fehler beim Verarbeiten: {e}", file=sys.stderr)

    report = {
        "meta": {
            "tool_name":       "zap",
            "scan_type":       "dast",
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
