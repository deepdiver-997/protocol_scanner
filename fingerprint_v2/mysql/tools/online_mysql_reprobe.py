#!/usr/bin/env python3
"""
Authorized online MySQL reprobe and fingerprint matcher.

The script samples unique IPs from an existing MYSQL scan corpus, reconnects to
the observed MySQL ports, reads only the initial server handshake, then matches
the live result against mysql_fingerprints.json. It never sends a login packet.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import re
import secrets
import struct
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def iter_json_objects(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        obj, idx = decoder.raw_decode(text, idx)
        yield obj


def load_targets(source: Path) -> dict[str, set[int]]:
    targets: dict[str, set[int]] = defaultdict(set)
    for report in iter_json_objects(source):
        ip = str(report.get("ip", ""))
        if not ip:
            continue
        for proto in report.get("protocols", []):
            if str(proto.get("protocol", "")).upper() == "MYSQL":
                targets[ip].add(int(proto.get("port", 3306)))
    return targets


def sample_targets(targets: dict[str, set[int]], fraction: float, seed: str | None, max_targets: int | None):
    ips = sorted(targets)
    if seed is None:
        seed = secrets.token_hex(16)
    rng = random.Random(seed)
    rng.shuffle(ips)
    selected_ips = ips[:max(1, round(len(ips) * fraction))]
    selected = [(ip, port) for ip in selected_ips for port in sorted(targets[ip])]
    if max_targets is not None and len(selected) > max_targets:
        rng.shuffle(selected)
        selected = sorted(selected[:max_targets])
    return seed, selected


def parse_handshake(data: bytes) -> dict[str, Any]:
    if len(data) < 5:
        return {"error": "short_handshake"}
    packet_len = data[0] | (data[1] << 8) | (data[2] << 16)
    payload = data[4:4 + packet_len]
    if not payload:
        return {"error": "empty_payload"}
    protocol_version = payload[0]
    nul = payload.find(b"\x00", 1)
    if nul == -1:
        version = payload[1:].decode("utf-8", errors="replace")
    else:
        version = payload[1:nul].decode("utf-8", errors="replace")
    capability_flags = 0
    if nul != -1 and len(payload) >= nul + 1 + 4 + 8 + 1 + 2:
        cap_off = nul + 1 + 4 + 8 + 1
        cap_low = struct.unpack_from("<H", payload, cap_off)[0]
        capability_flags = cap_low
        if len(payload) >= cap_off + 2 + 1 + 2 + 2:
            cap_high = struct.unpack_from("<H", payload, cap_off + 2 + 1 + 2)[0]
            capability_flags |= cap_high << 16
    auth_plugin = ""
    if b"\x00" in payload[max(0, len(payload) - 80):]:
        tail = payload[max(0, len(payload) - 80):].rstrip(b"\x00")
        parts = tail.split(b"\x00")
        if parts:
            candidate = parts[-1].decode("utf-8", errors="replace")
            if re.match(r"^[A-Za-z0-9_]+$", candidate):
                auth_plugin = candidate
    return {
        "protocol_version": protocol_version,
        "version": version,
        "capability_flags": capability_flags,
        "auth_plugin": auth_plugin,
    }


async def probe_one(ip: str, port: int, timeout: float, max_bytes: int) -> dict[str, Any]:
    start = time.perf_counter()
    result = {"ip": ip, "port": port, "probe_status": "unknown", "response_time_ms": None, "error": "", "record": None}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        parsed = parse_handshake(data)
        if parsed.get("version"):
            result["probe_status"] = "handshake"
            result["record"] = {
                "protocol": "MYSQL",
                "port": port,
                "accessible": True,
                "banner": parsed["version"],
                "vendor": f"MySQL {parsed['version']}",
                "mysql": parsed,
            }
        else:
            result["probe_status"] = "unparsed_response"
            result["error"] = parsed.get("error", "")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as exc:
        result["probe_status"] = "connect_failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
    result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
    return result


def get_path(record: dict[str, Any], dotted: str) -> Any:
    cur: Any = record
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return ""
        cur = cur[part]
    return cur


def regex_match(value: Any, pattern: str) -> bool:
    return re.search(pattern, str(value), re.IGNORECASE | re.DOTALL | re.MULTILINE) is not None


def condition_matches(rule: dict[str, Any], record: dict[str, Any]) -> bool:
    match = rule.get("match", {})
    for field, expected in match.get("field_equals", {}).items():
        if get_path(record, field) != expected:
            return False
    for field, pattern in match.get("field_regex", {}).items():
        if not regex_match(get_path(record, field), pattern):
            return False
    for field in match.get("field_present", []):
        if get_path(record, field) in ("", None):
            return False
    any_items = match.get("any_field_regex", [])
    if any_items and not any(regex_match(get_path(record, item["field"]), item["regex"]) for item in any_items):
        return False
    for item in match.get("none_field_regex", []):
        if regex_match(get_path(record, item["field"]), item["regex"]):
            return False
    return True


def match_record(library: dict[str, Any], record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {"protocol_match": False, "implementation": "", "version": "", "matched_rule_ids": []}
    ids = []
    implementation = []
    version = ""
    for rule in library["rules"]:
        if condition_matches(rule, record):
            ids.append(rule["id"])
            if rule["category"] == "implementation":
                implementation.append(rule["labels"].get("implementation", ""))
            if rule["id"] == "mysql.extract.version":
                version = str(get_path(record, "mysql.version"))
    return {
        "protocol_match": any(i.startswith("mysql.protocol.") for i in ids),
        "implementation": ",".join(sorted(set(filter(None, implementation)))),
        "version": version,
        "matched_rule_ids": ids,
    }


async def run(targets, concurrency, timeout, max_bytes):
    sem = asyncio.Semaphore(concurrency)
    async def one(ip, port):
        async with sem:
            return await probe_one(ip, port, timeout, max_bytes)
    tasks = [asyncio.create_task(one(ip, port)) for ip, port in targets]
    return [await task for task in asyncio.as_completed(tasks)]


def summarize(records: list[dict[str, Any]], total_ips: int, selected_targets: int, seed: str, fraction: float):
    total = len(records)
    pct = lambda n: round(n * 100 / total, 2) if total else 0.0
    responded = sum(1 for r in records if r["record"])
    rpct = lambda n: round(n * 100 / responded, 2) if responded else 0.0
    protocol = sum(1 for r in records if r["match"]["protocol_match"])
    impl = sum(1 for r in records if r["match"]["implementation"])
    version = sum(1 for r in records if r["match"]["version"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": {"fraction": fraction, "random_seed": seed, "total_unique_ips": total_ips, "selected_ip_port_targets": selected_targets},
        "metrics": {
            "responded": {"count": responded, "percent": pct(responded)},
            "protocol_match": {"count": protocol, "percent": pct(protocol), "percent_of_responded": rpct(protocol)},
            "implementation_match": {"count": impl, "percent": pct(impl), "percent_of_responded": rpct(impl)},
            "version_extraction": {"count": version, "percent": pct(version), "percent_of_responded": rpct(version)},
        },
        "probe_status": [{"status": k, "count": v, "percent": pct(v)} for k, v in Counter(r["probe_status"] for r in records).most_common()],
        "implementation_distribution": [{"implementation": k, "count": v, "percent": pct(v)} for k, v in Counter(r["match"]["implementation"] or "unknown" for r in records).most_common()],
    }


def write_outputs(prefix: Path, summary: dict[str, Any], records: list[dict[str, Any]]):
    prefix.with_suffix(".json").write_text(json.dumps({"summary": summary, "records": records}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with prefix.with_suffix(".csv").open("w", encoding="utf-8", newline="") as f:
        cols = ["ip", "port", "probe_status", "protocol_match", "implementation", "version", "response_time_ms", "error"]
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for r in records:
            writer.writerow({"ip": r["ip"], "port": r["port"], "probe_status": r["probe_status"], "protocol_match": r["match"]["protocol_match"], "implementation": r["match"]["implementation"], "version": r["match"]["version"], "response_time_ms": r["response_time_ms"], "error": r["error"]})
    lines = ["# Online MySQL Reprobe", "", "## Metrics", "", "| metric | count | percent | percent_of_responded |", "|---|---:|---:|---:|"]
    for key, val in summary["metrics"].items():
        lines.append(f"| {key} | {val['count']} | {val['percent']}% | {val.get('percent_of_responded', '')}% |")
    lines.extend(["", "## Probe Status", "", "| status | count | percent |", "|---|---:|---:|"])
    for row in summary["probe_status"]:
        lines.append(f"| {row['status']} | {row['count']} | {row['percent']}% |")
    prefix.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")


async def async_main(args):
    if not args.confirm_authorized:
        raise SystemExit("Refusing active probes without --confirm-authorized")
    targets_by_ip = load_targets(args.source)
    seed, targets = sample_targets(targets_by_ip, args.fraction, args.seed, args.max_targets)
    library = json.loads(args.library.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    records = await run(targets, args.concurrency, args.timeout, args.max_bytes)
    for rec in records:
        rec["match"] = match_record(library, rec["record"])
    summary = summarize(records, len(targets_by_ip), len(targets), seed, args.fraction)
    prefix = args.output_dir / f"live_mysql_reprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    write_outputs(prefix, summary, records)
    print(json.dumps({"summary": summary, "files_prefix": str(prefix)}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("library", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--fraction", type=float, default=0.10)
    parser.add_argument("--max-targets", type=int, default=None)
    parser.add_argument("--seed", default=None)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--max-bytes", type=int, default=8192)
    parser.add_argument("--confirm-authorized", action="store_true")
    asyncio.run(async_main(parser.parse_args()))


if __name__ == "__main__":
    main()
