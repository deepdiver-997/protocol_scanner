#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


def compile_re(pattern):
    return re.compile(pattern, re.MULTILINE | re.DOTALL)


def condition_matches(condition, banner, context):
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


def extract(rule, banner):
    out = {}
    for extractor in rule.get("extract", []):
        match = compile_re(extractor["regex"]).search(banner)
        if not match:
            continue
        group = extractor.get("group")
        if group:
            out[extractor["field"]] = match.group(group).strip()
        elif match.groups():
            out[extractor["field"]] = match.group(1).strip()
        else:
            out[extractor["field"]] = match.group(0).strip()
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=Path)
    parser.add_argument("banner_file", type=Path)
    parser.add_argument("--scanner-protocol", default="")
    args = parser.parse_args()

    library = json.loads(args.library.read_text(encoding="utf-8"))
    banner = args.banner_file.read_text(encoding="utf-8", errors="replace")
    context = {"scanner_protocol": args.scanner_protocol} if args.scanner_protocol else {}

    matches = []
    for rule in library["rules"]:
        if condition_matches(rule["match"], banner, context):
            matches.append({
                "id": rule["id"],
                "category": rule["category"],
                "confidence": rule["confidence"],
                "labels": rule.get("labels", {}),
                "extracted": extract(rule, banner),
            })
    print(json.dumps({"matches": matches}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
