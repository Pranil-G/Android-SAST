from __future__ import annotations

import argparse
from pathlib import Path

from context_sast.engine import ContextAwareSASTEngine
from context_sast.reports import format_cli_summary, results_to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Context-aware Android SAST engine")
    parser.add_argument("--apk", help="Path to a single APK")
    parser.add_argument("--apk-dir", help="Directory containing APK files")
    parser.add_argument("--output", help="Optional path for JSON output")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum inter-procedural depth")
    parser.add_argument("--json-only", action="store_true", help="Suppress CLI summary and print JSON")
    parser.add_argument(
        "--show-near-code",
        action="store_true",
        help="Include nearby Java/XML evidence snippets in JSON output. This is slower because it resolves source snippets.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.apk and not args.apk_dir:
        parser.error("Provide either --apk or --apk-dir")

    targets = []
    if args.apk:
        targets.append(Path(args.apk))
    if args.apk_dir:
        targets.extend(sorted(Path(args.apk_dir).glob("*.apk")))

    engine = ContextAwareSASTEngine(max_depth=args.max_depth)
    results = tuple(engine.scan(str(target)) for target in targets)
    # Compute JSON whenever any JSON-related flag is active.
    need_json = args.output or args.json_only or args.show_near_code
    json_payload = (
        results_to_json(results, include_evidence=args.show_near_code) if need_json else None
    )

    if args.output and json_payload is not None:
        Path(args.output).write_text(json_payload, encoding="utf-8")

    if args.json_only and json_payload is not None:
        print(json_payload)
    elif args.show_near_code and not args.json_only and json_payload is not None:
        # --show-near-code without --json-only: print the JSON (evidence blocks
        # don't have a meaningful plain-text representation).
        print(json_payload)
    else:
        for result in results:
            print(format_cli_summary(result))
            print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
