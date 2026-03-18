#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import email.utils
import json
import re
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


OUTPUT_FILE = Path("output/adguard-master.txt")
STATS_FILE = Path("output/source_stats.json")
SOURCES_FILE = Path("sources.txt")
EXCLUDE_FILE = Path("exclude_rules.txt")

USER_AGENT = "dns_blocklist-builder/1.1"
REQUEST_TIMEOUT_SECONDS = 60
STALE_DAYS = 30

# Health thresholds
LOW_VALID_RULES_THRESHOLD = 100
LOW_UNIQUE_RULES_THRESHOLD = 25
SHARP_DROP_RATIO = 0.10  # current < 10% of previous

# Timestamp parsing patterns from content
LAST_MODIFIED_RE = re.compile(r"^\s*(?:!|#)?\s*Last modified:\s*(.+?)\s*$", re.IGNORECASE)
TIME_UPDATED_RE = re.compile(r"^\s*(?:!|#)?\s*TimeUpdated:\s*(.+?)\s*$", re.IGNORECASE)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ensure_output_dir() -> None:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)


def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        raise FileNotFoundError(f"Missing required file: {SOURCES_FILE}")

    sources: list[str] = []
    for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sources.append(stripped)
    return sources


def load_excludes() -> set[str]:
    if not EXCLUDE_FILE.exists():
        return set()

    excludes: set[str] = set()
    for line in EXCLUDE_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        excludes.add(stripped)
    return excludes


def load_previous_stats() -> dict[str, Any]:
    if not STATS_FILE.exists():
        return {}

    try:
        return json.loads(STATS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def fetch_url(url: str) -> tuple[str, dict[str, str], int | None]:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        content = resp.read().decode("utf-8", errors="ignore")
        headers = {k.lower(): v for k, v in resp.info().items()}
        status = getattr(resp, "status", None)
        return content, headers, status


def is_valid_rule(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False

    # Skip comments/header lines
    if stripped.startswith("!") or stripped.startswith("#"):
        return False

    return True


def parse_iso_like_timestamp(value: str) -> dt.datetime | None:
    raw = value.strip()

    # Try RFC 2822 / HTTP date formats first
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
    except Exception:
        pass

    # Normalize trailing Z to +00:00 for fromisoformat
    iso_candidate = raw.replace("Z", "+00:00")

    # Python handles:
    #   2026-03-14T09:22:31.123+00:00
    #   2026-03-14T09:22:31+00:00
    try:
        parsed = dt.datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except Exception:
        pass

    # Handle +0000 style offsets
    # Example: 2026-03-14T09:22:31+0000
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            parsed = dt.datetime.strptime(raw, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
        except Exception:
            continue

    return None


def detect_last_update(
    headers: dict[str, str],
    content: str,
) -> tuple[str | None, str | None, str | None]:
    # Returns:
    # (normalized_utc_iso, raw_value, source_kind)

    # 1) HTTP Last-Modified header
    header_value = headers.get("last-modified")
    if header_value:
        parsed = parse_iso_like_timestamp(header_value)
        if parsed:
            return (
                parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                header_value,
                "http_last_modified",
            )

    # 2) Look near top of file for content metadata
    top_lines = content.splitlines()[:100]
    for line in top_lines:
        m = LAST_MODIFIED_RE.match(line)
        if m:
            raw_value = m.group(1).strip()
            parsed = parse_iso_like_timestamp(raw_value)
            if parsed:
                return (
                    parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    raw_value,
                    "content_last_modified",
                )

        m = TIME_UPDATED_RE.match(line)
        if m:
            raw_value = m.group(1).strip()
            parsed = parse_iso_like_timestamp(raw_value)
            if parsed:
                return (
                    parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    raw_value,
                    "content_timeupdated",
                )

    return None, None, None


def compute_days_since_update(last_update_utc: str | None, now_utc: dt.datetime) -> int | None:
    if not last_update_utc:
        return None

    try:
        parsed = dt.datetime.fromisoformat(last_update_utc.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        delta = now_utc - parsed.astimezone(dt.timezone.utc)
        return max(delta.days, 0)
    except Exception:
        return None


def build_metadata(
    maintainer: str,
    sources: list[str],
    success_count: int,
    failed_count: int,
    rule_count: int,
    now_utc: dt.datetime,
) -> str:
    next_run = now_utc + dt.timedelta(days=3)

    lines: list[str] = [
        "! Title: VovchykBratyk Consolidated AdGuard Home Blocklist",
        "! Description: Consolidated DNS blocklist for personal AdGuard Home instances",
        f"! Maintainer: {maintainer}",
        "! Repository: https://github.com/VovchykBratyk/dns_blocklist",
        "! Created: 2026-03-18",
        f"! Last Updated UTC: {now_utc.replace(microsecond=0).isoformat().replace('+00:00', 'Z')}",
        f"! Next Scheduled Update UTC: {next_run.replace(microsecond=0).isoformat().replace('+00:00', 'Z')}",
        f"! Total Sources: {len(sources)}",
        f"! Successful Sources: {success_count}",
        f"! Failed Sources: {failed_count}",
        f"! Rule Count: {rule_count}",
        "! Format: AdGuard / Adblock-style DNS rules",
        "! Diagnostics Sidecar: output/source_stats.json",
        "!",
        "! --- BEGIN RULES ---",
    ]
    return "\n".join(lines)


def make_empty_source_stat(url: str) -> dict[str, Any]:
    return {
        "url": url,
        "status": "unknown",
        "http_status": None,
        "error": None,
        "raw_lines": 0,
        "valid_rules": 0,
        "excluded_rules": 0,
        "duplicate_rules": 0,
        "unique_contributed": 0,
        "last_update_raw": None,
        "last_update_utc": None,
        "last_update_source": None,
        "days_since_update": None,
        "stale": None,
        "health_warnings": [],
    }


def evaluate_health(
    current_stat: dict[str, Any],
    previous_stat: dict[str, Any] | None,
) -> None:
    warnings: list[str] = []

    valid_rules = current_stat.get("valid_rules", 0)
    unique_contributed = current_stat.get("unique_contributed", 0)

    if current_stat.get("status") != "ok":
        warnings.append("FETCH_FAILED")
    else:
        if valid_rules < LOW_VALID_RULES_THRESHOLD:
            warnings.append("LOW_VALID_RULE_COUNT")
        if unique_contributed < LOW_UNIQUE_RULES_THRESHOLD:
            warnings.append("LOW_UNIQUE_CONTRIBUTION")
        if current_stat.get("stale") is True:
            warnings.append("STALE")

        if previous_stat and previous_stat.get("status") == "ok":
            prev_valid = int(previous_stat.get("valid_rules", 0) or 0)
            prev_unique = int(previous_stat.get("unique_contributed", 0) or 0)

            if prev_valid > 0 and valid_rules < max(1, int(prev_valid * SHARP_DROP_RATIO)):
                warnings.append("SHARP_DROP_VALID_RULES")

            if prev_unique > 0 and unique_contributed < max(1, int(prev_unique * SHARP_DROP_RATIO)):
                warnings.append("SHARP_DROP_UNIQUE_CONTRIBUTION")

    current_stat["health_warnings"] = sorted(set(warnings))


def main() -> int:
    ensure_output_dir()

    now_utc = utcnow()
    sources = load_sources()
    excludes = load_excludes()
    previous_stats_blob = load_previous_stats()
    previous_sources: dict[str, Any] = {
        item["url"]: item
        for item in previous_stats_blob.get("sources", [])
        if isinstance(item, dict) and "url" in item
    }

    seen_rules: set[str] = set()
    merged_rules: list[str] = []
    source_stats: list[dict[str, Any]] = []

    success_count = 0
    failed_count = 0

    for url in sources:
        stat = make_empty_source_stat(url)
        print(f"[+] Fetching: {url}")

        try:
            content, headers, http_status = fetch_url(url)
            stat["status"] = "ok"
            stat["http_status"] = http_status
            success_count += 1

            stat["raw_lines"] = len(content.splitlines())

            last_update_utc, last_update_raw, last_update_source = detect_last_update(headers, content)
            stat["last_update_raw"] = last_update_raw
            stat["last_update_utc"] = last_update_utc
            stat["last_update_source"] = last_update_source
            stat["days_since_update"] = compute_days_since_update(last_update_utc, now_utc)
            stat["stale"] = (
                stat["days_since_update"] > STALE_DAYS
                if stat["days_since_update"] is not None
                else None
            )

            for line in content.splitlines():
                stripped = line.strip()

                if not is_valid_rule(stripped):
                    continue

                stat["valid_rules"] += 1

                if stripped in excludes:
                    stat["excluded_rules"] += 1
                    continue

                if stripped in seen_rules:
                    stat["duplicate_rules"] += 1
                    continue

                seen_rules.add(stripped)
                merged_rules.append(stripped)
                stat["unique_contributed"] += 1

        except Exception as exc:
            failed_count += 1
            stat["status"] = "failed"
            stat["error"] = str(exc)
            print(f"[!] Failed: {url} ({exc})")

        previous_stat = previous_sources.get(url)
        evaluate_health(stat, previous_stat)
        source_stats.append(stat)

    metadata = build_metadata(
        maintainer="VovchykBratyk",
        sources=sources,
        success_count=success_count,
        failed_count=failed_count,
        rule_count=len(merged_rules),
        now_utc=now_utc,
    )

    output_text = metadata + "\n" + "\n".join(merged_rules) + "\n"
    OUTPUT_FILE.write_text(output_text, encoding="utf-8")

    stats_payload = {
        "generated_at_utc": now_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "stale_days_threshold": STALE_DAYS,
        "health_thresholds": {
            "low_valid_rules_threshold": LOW_VALID_RULES_THRESHOLD,
            "low_unique_rules_threshold": LOW_UNIQUE_RULES_THRESHOLD,
            "sharp_drop_ratio": SHARP_DROP_RATIO,
        },
        "summary": {
            "total_sources": len(sources),
            "successful_sources": success_count,
            "failed_sources": failed_count,
            "final_rule_count": len(merged_rules),
        },
        "sources": source_stats,
    }
    STATS_FILE.write_text(json.dumps(stats_payload, indent=2, sort_keys=False), encoding="utf-8")

    print(f"[✓] Wrote {len(merged_rules)} rules to {OUTPUT_FILE}")
    print(f"[✓] Wrote source stats to {STATS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())