"""Parse dirsearch JSON (preferred) or CSV output into endpoint dicts."""
from __future__ import annotations

import csv
import io
import json


class DirsearchParseError(ValueError):
    pass


def _coerce_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_dirsearch_json(text: str) -> list[dict]:
    if not text or not text.strip():
        raise DirsearchParseError("dirsearch JSON 為空。")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DirsearchParseError(f"dirsearch JSON 解析失敗：{exc}") from exc

    results = []
    # dirsearch --format=json emits {"results": [...]} (list of dicts) in
    # recent versions, or a {target: [...]} mapping in older ones.
    raw_items: list[dict] = []
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        raw_items = [i for i in data["results"] if isinstance(i, dict)]
    elif isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                raw_items.extend(i for i in value if isinstance(i, dict))
    elif isinstance(data, list):
        raw_items = [i for i in data if isinstance(i, dict)]

    for item in raw_items:
        url = item.get("url") or item.get("path") or ""
        if not url:
            continue
        results.append(
            {
                "url": url,
                "status_code": _coerce_int(item.get("status")),
                "content_length": _coerce_int(
                    item.get("content-length", item.get("content_length"))
                ),
                "redirect_location": item.get("redirect", "") or "",
                "content_type": item.get("content-type", "") or "",
            }
        )
    return results


def parse_dirsearch_csv(text: str) -> list[dict]:
    if not text or not text.strip():
        raise DirsearchParseError("dirsearch CSV 為空。")
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise DirsearchParseError("dirsearch CSV 缺少標頭。")
    lower = {name.lower().strip(): name for name in reader.fieldnames}
    results = []
    for row in reader:
        url = row.get(lower.get("url", ""), "") or row.get(lower.get("path", ""), "")
        if not url:
            continue
        results.append(
            {
                "url": url,
                "status_code": _coerce_int(row.get(lower.get("status", ""))),
                "content_length": _coerce_int(
                    row.get(lower.get("content-length", ""))
                ),
                "redirect_location": row.get(lower.get("redirection", ""), "")
                or row.get(lower.get("redirect", ""), ""),
                "content_type": row.get(lower.get("content-type", ""), ""),
            }
        )
    return results
