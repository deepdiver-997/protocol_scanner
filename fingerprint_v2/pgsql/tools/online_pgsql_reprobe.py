#!/usr/bin/env python3
"""
Authorized online PostgreSQL reprobe and fingerprint matcher.

The script samples unique IPs from a PGSQL scan corpus, sends SSLRequest and a
minimal StartupMessage, then matches the first server response. It never sends a
password or executes SQL.
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


PG_FIELD_TYPES = set("SEVCMDFHLPRWs")


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
            if str(proto.get("protocol", "")).upper() == "PGSQL":
                targets[ip].add(int(proto.get("port", 5432)))
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


def startup_message() -> bytes:
    params = b"user\x00probe\x00database\x00probe\x00application_name\x00protocol_scanner\x00\x00"
    body = struct.pack("!I", 196608) + params
    return struct.pack("!I", len(body) + 4) + body


def parse_error_fields(payload: bytes) -> tuple[str, dict[str, str]]:
    text = payload.decode("utf-8", errors="replace")
    fields: dict[str, str] = {}
    pos = 0
    while pos < len(text):
        typ = text[pos]
        if typ == "\x00":
            pos += 1
            continue
        if typ not in PG_FIELD_TYPES:
            break
        end = text.find("\x00", pos + 1)
        if end == -1:
            break
        fields[typ] = text[pos + 1:end]
        pos = end + 1
    banner = "".join(f"{k}{v}\x00" for k, v in fields.items()) + "\x00"
    return banner, fields


def record_from_response(port: int, ssl_response: str, data: bytes) -> dict[str, Any]:
    banner = f"SSLRequest:{ssl_response}" if ssl_response else ""
    fields = {}
    if len(data) >= 5:
        msg_type = chr(data[0])
        length = struct.unpack("!I", data[1:5])[0]
        payload = data[5:5 + max(0, length - 4)]
        if msg_type == "E":
            banner, fields = parse_error_fields(payload)
        elif msg_type == "R" and len(payload) >= 4:
            auth_code = struct.unpack("!I", payload[:4])[0]
            banner = "AuthenticationOk" if auth_code == 0 else f"Authentication{auth_code}"
        else:
            banner = f"{msg_type}:{payload[:120].decode('utf-8', errors='replace')}"
    return {
        "protocol": "PGSQL",
        "port": port,
        "accessible": True,
        "banner": banner,
        "vendor": "",
        "pgsql": {"protocol_version": 196608, "version": ""},
        "pgsql_fields": {
            "severity": fields.get("S", ""),
            "sqlstate": fields.get("C", ""),
            "message": fields.get("M", ""),
            "file": fields.get("F", ""),
            "routine": fields.get("R", ""),
            "line": fields.get("L", ""),
        },
    }


async def probe_one(ip: str, port: int, timeout: float, max_bytes: int) -> dict[str, Any]:
    start = time.perf_counter()
    result = {"ip": ip, "port": port, "probe_status": "unknown", "response_time_ms": None, "error": "", "record": None}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.write(struct.pack("!II", 8, 80877103))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        ssl_resp = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout)).decode("ascii", errors="replace")
        if ssl_resp == "S":
            result["probe_status"] = "ssl_supported"
            result["record"] = record_from_response(port, ssl_resp, b"")
        else:
            writer.write(startup_message())
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
            result["probe_status"] = "startup_response" if data else "empty_response"
            result["record"] = record_from_response(port, ssl_resp, data)
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
    return True


def match_record(library: dict[str, Any], record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {"protocol_match": False, "sqlstate": "", "message": "", "matched_rule_ids": []}
    ids = []
    for rule in library["rules"]:
        if condition_matches(rule, record):
            ids.append(rule["id"])
    return {
        "protocol_match": any(i.startswith("pgsql.protocol.") for i in ids),
        "sqlstate": get_path(record, "pgsql_fields.sqlstate"),
        "message": get_path(record, "pgsql_fields.message"),
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
    sqlstate = sum(1 for r in records if r["match"]["sqlstate"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": {"fraction": fraction, "random_seed": seed, "total_unique_ips": total_ips, "selected_ip_port_targets": selected_targets},
        "metrics": {
            "responded": {"count": responded, "percent": pct(responded)},
            "protocol_match": {"count": protocol, "percent": pct(protocol), "percent_of_responded": rpct(protocol)},
            "sqlstate_extraction": {"count": sqlstate, "percent": pct(sqlstate), "percent_of_responded": rpct(sqlstate)},
        },
        "probe_status": [{"status": k, "count": v, "percent": pct(v)} for k, v in Counter(r["probe_status"] for r in records).most_common()],
    }


def write_outputs(prefix: Path, summary: dict[str, Any], records: list[dict[str, Any]]):
    prefix.with_suffix(".json").write_text(json.dumps({"summary": summary, "records": records}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with prefix.with_suffix(".csv").open("w", encoding="utf-8", newline="") as f:
        cols = ["ip", "port", "probe_status", "protocol_match", "sqlstate", "message", "response_time_ms", "error"]
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for r in records:
            writer.writerow({"ip": r["ip"], "port": r["port"], "probe_status": r["probe_status"], "protocol_match": r["match"]["protocol_match"], "sqlstate": r["match"]["sqlstate"], "message": r["match"]["message"], "response_time_ms": r["response_time_ms"], "error": r["error"]})
    lines = ["# Online PGSQL Reprobe", "", "## Metrics", "", "| metric | count | percent | percent_of_responded |", "|---|---:|---:|---:|"]
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
    prefix = args.output_dir / f"live_pgsql_reprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
