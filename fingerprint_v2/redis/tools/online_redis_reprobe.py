#!/usr/bin/env python3
"""
Authorized online Redis reprobe and fingerprint matcher.

This script randomly samples 10% of unique IPs from a prior REDIS scan corpus,
reprobes only the Redis ports observed for those IPs, then matches live
responses against redis_fingerprints.json.

Run only on explicitly authorized targets.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import re
import secrets
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
            if str(proto.get("protocol", "")).upper() != "REDIS":
                continue
            try:
                port = int(proto.get("port"))
            except (TypeError, ValueError):
                continue
            targets[ip].add(port)
    return targets


def sample_targets(targets: dict[str, set[int]], fraction: float, seed: str | None) -> tuple[str, list[tuple[str, int]]]:
    ips = sorted(targets)
    if seed is None:
        seed = secrets.token_hex(16)
    rng = random.Random(seed)
    rng.shuffle(ips)
    sample_size = max(1, round(len(ips) * fraction))
    selected_ips = sorted(ips[:sample_size])
    selected = []
    for ip in selected_ips:
        for port in sorted(targets[ip]):
            selected.append((ip, port))
    return seed, selected


async def read_available(reader: asyncio.StreamReader, timeout: float, max_bytes: int) -> bytes:
    chunks = []
    total = 0
    while total < max_bytes:
        try:
            chunk = await asyncio.wait_for(reader.read(min(4096, max_bytes - total)), timeout=timeout)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
        if len(chunk) < 4096:
            break
    return b"".join(chunks)


async def probe_one(ip: str, port: int, timeout: float, read_timeout: float, max_bytes: int) -> dict[str, Any]:
    start = time.perf_counter()
    result = {
        "ip": ip,
        "port": port,
        "probe_status": "unknown",
        "ping_response": "",
        "info_response": "",
        "banner_for_match": "",
        "response_time_ms": None,
        "error": "",
    }
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception as exc:
        result["probe_status"] = "connect_failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return result

    try:
        writer.write(b"PING\r\n")
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        ping_bytes = await read_available(reader, read_timeout, 4096)
        result["ping_response"] = ping_bytes.decode("utf-8", errors="replace")

        if result["ping_response"]:
            writer.write(b"INFO server\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            info_bytes = await read_available(reader, read_timeout, max_bytes)
            result["info_response"] = info_bytes.decode("utf-8", errors="replace")

        if result["info_response"]:
            result["banner_for_match"] = result["info_response"]
            result["probe_status"] = "info_response"
        elif result["ping_response"]:
            result["banner_for_match"] = result["ping_response"]
            result["probe_status"] = "ping_only"
        else:
            result["probe_status"] = "empty_response"
    except Exception as exc:
        result["probe_status"] = "probe_failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
        if result["info_response"]:
            result["banner_for_match"] = result["info_response"]
        elif result["ping_response"]:
            result["banner_for_match"] = result["ping_response"]
    finally:
        result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return result


def compile_re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.MULTILINE | re.DOTALL)


def condition_matches(condition: dict[str, Any], banner: str, context: dict[str, Any]) -> bool:
    for key, expected in condition.get("requires_context", {}).items():
        if context.get(key) != expected:
            return False
    for pattern in condition.get("all", []):
        if not compile_re(pattern).search(banner):
            return False
    any_patterns = condition.get("any", [])
    if any_patterns and not any(compile_re(pattern).search(banner) for pattern in any_patterns):
        return False
    for pattern in condition.get("none", []):
        if compile_re(pattern).search(banner):
            return False
    return True


def extract(rule: dict[str, Any], banner: str) -> dict[str, str]:
    values = {}
    for extractor in rule.get("extract", []):
        match = compile_re(extractor["regex"]).search(banner)
        if not match:
            continue
        group = extractor.get("group")
        if group:
            values[extractor["field"]] = match.group(group).strip()
        elif match.groups():
            values[extractor["field"]] = match.group(1).strip()
        else:
            values[extractor["field"]] = match.group(0).strip()
    return values


def match_banner(library: dict[str, Any], banner: str) -> dict[str, Any]:
    context = {"scanner_protocol": "REDIS"}
    matches = []
    merged_extract: dict[str, str] = {}
    implementations = []
    modes = []
    protocol_match = False
    strong_protocol_match = False

    for rule in library["rules"]:
        if not condition_matches(rule["match"], banner, context):
            continue
        values = extract(rule, banner)
        merged_extract.update(values)
        labels = rule.get("labels", {})
        matches.append(
            {
                "id": rule["id"],
                "category": rule["category"],
                "confidence": rule["confidence"],
                "labels": labels,
                "extracted": values,
            }
        )
        if rule["category"] in {"protocol_identity", "protocol_identity_weak"}:
            protocol_match = True
            if rule["category"] == "protocol_identity":
                strong_protocol_match = True
        if rule["category"] == "implementation":
            implementations.append(labels.get("implementation", rule["id"]))
        if rule["category"] == "deployment_mode":
            modes.append(labels.get("mode", ""))

    return {
        "protocol_match": protocol_match,
        "strong_protocol_match": strong_protocol_match,
        "implementation": ",".join(sorted(set(filter(None, implementations)))) or "",
        "redis_version": merged_extract.get("redis_version") or merged_extract.get("version") or "",
        "mode": ",".join(sorted(set(filter(None, modes)))) or "",
        "matched_rule_ids": [m["id"] for m in matches],
        "matches": matches,
    }


async def run_probes(targets: list[tuple[str, int]], concurrency: int, timeout: float, read_timeout: float, max_bytes: int):
    semaphore = asyncio.Semaphore(concurrency)

    async def wrapped(ip: str, port: int):
        async with semaphore:
            return await probe_one(ip, port, timeout, read_timeout, max_bytes)

    tasks = [asyncio.create_task(wrapped(ip, port)) for ip, port in targets]
    results = []
    for task in asyncio.as_completed(tasks):
        results.append(await task)
    return results


def summarize(records: list[dict[str, Any]], total_unique_ips: int, selected_unique_ips: int, seed: str, fraction: float) -> dict[str, Any]:
    total = len(records)
    pct = lambda n: round(n * 100 / total, 2) if total else 0.0
    status_counts = Counter(r["probe_status"] for r in records)
    reachable = sum(1 for r in records if r["banner_for_match"])
    reachable_pct = lambda n: round(n * 100 / reachable, 2) if reachable else 0.0
    protocol = sum(1 for r in records if r["match"]["protocol_match"])
    strong = sum(1 for r in records if r["match"]["strong_protocol_match"])
    impl = sum(1 for r in records if r["match"]["implementation"])
    version = sum(1 for r in records if r["match"]["redis_version"])
    mode = sum(1 for r in records if r["match"]["mode"])
    impl_counts = Counter(r["match"]["implementation"] or "unknown" for r in records)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "fraction": fraction,
            "random_seed": seed,
            "total_unique_ips": total_unique_ips,
            "selected_unique_ips": selected_unique_ips,
            "selected_ip_port_targets": total,
        },
        "metrics": {
            "reachable_or_responded": {"count": reachable, "percent": pct(reachable)},
            "protocol_match": {"count": protocol, "percent": pct(protocol)},
            "strong_protocol_match": {"count": strong, "percent": pct(strong)},
            "implementation_match": {"count": impl, "percent": pct(impl)},
            "version_extraction": {"count": version, "percent": pct(version)},
            "mode_extraction": {"count": mode, "percent": pct(mode)},
        },
        "reachable_metrics": {
            "protocol_match": {"count": protocol, "percent_of_reachable": reachable_pct(protocol)},
            "strong_protocol_match": {"count": strong, "percent_of_reachable": reachable_pct(strong)},
            "implementation_match": {"count": impl, "percent_of_reachable": reachable_pct(impl)},
            "version_extraction": {"count": version, "percent_of_reachable": reachable_pct(version)},
            "mode_extraction": {"count": mode, "percent_of_reachable": reachable_pct(mode)},
        },
        "probe_status": [{"status": k, "count": v, "percent": pct(v)} for k, v in status_counts.most_common()],
        "implementation_distribution": [
            {"implementation": k, "count": v, "percent": pct(v)}
            for k, v in impl_counts.most_common()
        ],
    }


def write_csv(path: Path, records: list[dict[str, Any]]):
    columns = [
        "ip",
        "port",
        "probe_status",
        "protocol_match",
        "strong_protocol_match",
        "implementation",
        "redis_version",
        "mode",
        "matched_rule_ids",
        "response_time_ms",
        "error",
        "ping_preview",
        "info_preview",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for r in records:
            m = r["match"]
            writer.writerow(
                {
                    "ip": r["ip"],
                    "port": r["port"],
                    "probe_status": r["probe_status"],
                    "protocol_match": m["protocol_match"],
                    "strong_protocol_match": m["strong_protocol_match"],
                    "implementation": m["implementation"],
                    "redis_version": m["redis_version"],
                    "mode": m["mode"],
                    "matched_rule_ids": ";".join(m["matched_rule_ids"]),
                    "response_time_ms": r["response_time_ms"],
                    "error": r["error"],
                    "ping_preview": r["ping_response"][:120].replace("\r", "\\r").replace("\n", "\\n"),
                    "info_preview": r["info_response"][:120].replace("\r", "\\r").replace("\n", "\\n"),
                }
            )


def write_markdown(path: Path, summary: dict[str, Any]):
    lines = [
        "# Online Redis Reprobe Evaluation",
        "",
        f"- Generated at: `{summary['generated_at']}`",
        f"- Random seed: `{summary['sample']['random_seed']}`",
        f"- Total unique IPs: {summary['sample']['total_unique_ips']}",
        f"- Selected unique IPs: {summary['sample']['selected_unique_ips']}",
        f"- Selected IP:port targets: {summary['sample']['selected_ip_port_targets']}",
        "",
        "## Metrics",
        "",
        "| metric | count | percent |",
        "|---|---:|---:|",
    ]
    for key, value in summary["metrics"].items():
        lines.append(f"| {key} | {value['count']} | {value['percent']}% |")
    lines.extend(["", "## Metrics Among Responded Targets", "", "| metric | count | percent_of_reachable |", "|---|---:|---:|"])
    for key, value in summary["reachable_metrics"].items():
        lines.append(f"| {key} | {value['count']} | {value['percent_of_reachable']}% |")
    lines.extend(["", "## Probe Status", "", "| status | count | percent |", "|---|---:|---:|"])
    for row in summary["probe_status"]:
        lines.append(f"| {row['status']} | {row['count']} | {row['percent']}% |")
    lines.extend(["", "## Implementation Distribution", "", "| implementation | count | percent |", "|---|---:|---:|"])
    for row in summary["implementation_distribution"]:
        lines.append(f"| {row['implementation']} | {row['count']} | {row['percent']}% |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def async_main(args: argparse.Namespace):
    if not args.confirm_authorized:
        raise SystemExit("Refusing to run active probes without --confirm-authorized")

    source_targets = load_targets(args.source)
    seed, selected = sample_targets(source_targets, args.fraction, args.seed)
    library = json.loads(args.library.read_text(encoding="utf-8"))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = args.output_dir / f"live_reprobe_{run_id}"

    probe_results = await run_probes(selected, args.concurrency, args.timeout, args.read_timeout, args.max_bytes)
    for record in probe_results:
        record["match"] = match_banner(library, record["banner_for_match"])

    summary = summarize(
        probe_results,
        total_unique_ips=len(source_targets),
        selected_unique_ips=len({ip for ip, _ in selected}),
        seed=seed,
        fraction=args.fraction,
    )

    (prefix.with_suffix(".json")).write_text(
        json.dumps({"summary": summary, "records": probe_results}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_csv(prefix.with_suffix(".csv"), probe_results)
    write_markdown(prefix.with_suffix(".md"), summary)
    (args.output_dir / "latest_live_reprobe_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"summary": summary, "files_prefix": str(prefix)}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("library", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--fraction", type=float, default=0.10)
    parser.add_argument("--seed", default=None, help="Optional seed. Default: random each run.")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--read-timeout", type=float, default=0.75)
    parser.add_argument("--max-bytes", type=int, default=65536)
    parser.add_argument("--confirm-authorized", action="store_true")
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
