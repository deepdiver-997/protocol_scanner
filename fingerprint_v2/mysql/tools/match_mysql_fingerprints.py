#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


def get_path(record, dotted):
    cur = record
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return ""
        cur = cur[part]
    return cur


def regex_match(value, pattern):
    return re.search(pattern, str(value), re.IGNORECASE | re.DOTALL | re.MULTILINE) is not None


def condition_matches(rule, record):
    match = rule.get("match", {})
    for field, expected in match.get("field_equals", {}).items():
        if get_path(record, field) != expected:
            return False
    for field, pattern in match.get("field_regex", {}).items():
        if not regex_match(get_path(record, field), pattern):
            return False
    any_items = match.get("any_field_regex", [])
    if any_items and not any(regex_match(get_path(record, item["field"]), item["regex"]) for item in any_items):
        return False
    for item in match.get("none_field_regex", []):
        if regex_match(get_path(record, item["field"]), item["regex"]):
            return False
    for field in match.get("field_present", []):
        value = get_path(record, field)
        if value is None or value == "":
            return False
    return True


def parse_pg_fields(record):
    if record.get("protocol") != "PGSQL" or "pgsql_fields" in record:
        return record
    banner = record.get("banner", "")
    fields = {}
    pos = 0
    allowed = set("SEVCMDFHLPRWs")
    while pos < len(banner):
        typ = banner[pos]
        if typ == "\x00":
            pos += 1
            continue
        if typ not in allowed:
            break
        end = banner.find("\x00", pos + 1)
        if end == -1:
            break
        fields[typ] = banner[pos + 1:end]
        pos = end + 1
    record = dict(record)
    record["pgsql_fields"] = {
        "severity": fields.get("S", ""),
        "sqlstate": fields.get("C", ""),
        "message": fields.get("M", ""),
        "file": fields.get("F", ""),
        "routine": fields.get("R", ""),
        "line": fields.get("L", ""),
    }
    return record


def extract(rule, record):
    out = {}
    for spec in rule.get("extract", []):
        value = str(get_path(record, spec["source"]))
        pattern = spec.get("regex")
        if pattern:
            m = re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE)
            if not m:
                continue
            group = spec.get("group")
            out[spec["field"]] = (m.group(group) if group else m.group(1) if m.groups() else m.group(0)).strip()
        elif value:
            out[spec["field"]] = value.strip()
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=Path)
    parser.add_argument("record_json", type=Path, help="A single scanner protocol-result JSON object")
    args = parser.parse_args()
    library = json.loads(args.library.read_text(encoding="utf-8"))
    record = json.loads(args.record_json.read_text(encoding="utf-8"))
    record = parse_pg_fields(record)
    matches = []
    for rule in library["rules"]:
        if condition_matches(rule, record):
            matches.append({
                "id": rule["id"],
                "category": rule["category"],
                "confidence": rule["confidence"],
                "labels": rule.get("labels", {}),
                "extracted": extract(rule, record),
            })
    print(json.dumps({"matches": matches}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
