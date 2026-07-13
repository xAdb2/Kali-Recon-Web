"""Parse Nuclei JSONL output into finding dicts.

Malformed lines are skipped rather than aborting the whole parse, so a single
truncated final line (common when a scan is killed) does not lose earlier
findings.
"""
from __future__ import annotations

import json

_SEVERITY_MAP = {
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


class NucleiParseError(ValueError):
    pass


def parse_nuclei_jsonl(text: str) -> list[dict]:
    if text is None:
        raise NucleiParseError("Nuclei 輸出為空。")
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            # Skip malformed/truncated line, keep prior findings.
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        severity = _SEVERITY_MAP.get(
            str(info.get("severity", "info")).lower(), "info"
        )
        template_id = item.get("template-id") or item.get("templateID") or ""
        matched = item.get("matched-at") or item.get("host") or ""
        classification = info.get("classification") or {}
        category = ""
        tags = info.get("tags")
        if isinstance(tags, list) and tags:
            category = str(tags[0])
        elif isinstance(tags, str):
            category = tags.split(",")[0].strip()
        findings.append(
            {
                "template_id": template_id,
                "severity": severity,
                "title": info.get("name") or template_id or "Nuclei finding",
                "description": info.get("description", "") or "",
                "category": category or "nuclei",
                "matched_at": matched,
                "evidence": item.get("extracted-results") or matched or "",
                "remediation": (classification or {}).get("remediation", "")
                if isinstance(classification, dict)
                else "",
                "reference": info.get("reference") or [],
            }
        )
    return findings
