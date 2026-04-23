from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from asa_pipeline.classifier_input import build_classifier_input_records
from asa_pipeline.features import build_session_summaries
from asa_pipeline.loader import iter_input_files, iter_log_lines
from asa_pipeline.normalizer import normalize_event
from asa_pipeline.parser import parse_line
from asa_pipeline.sessionizer import build_all_session_views


def run_pipeline(input_path: str | Path, outdir: str | Path) -> dict[str, Any]:
    input_path = Path(input_path)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    exclude_roots = {outdir.resolve()} if input_path.is_dir() else set()
    input_files = list(iter_input_files(input_path, exclude_roots=exclude_roots))
    parsed_events = [
        normalize_event(parse_line(raw_line))
        for _, _, raw_line in iter_log_lines(input_path, exclude_roots=exclude_roots)
    ]

    sessions = build_session_summaries(build_all_session_views(parsed_events))
    classifier_inputs = build_classifier_input_records(sessions)

    _write_jsonl(outdir / "parsed_events.jsonl", [event.to_dict() for event in parsed_events])
    _write_jsonl(outdir / "sessions.jsonl", [session.to_dict() for session in sessions])
    _write_jsonl(outdir / "classifier_inputs.jsonl", classifier_inputs)

    summary = {
        "input_path": str(input_path.resolve()),
        "files_processed": len(input_files),
        "lines_processed": len(parsed_events),
        "parsed_events": sum(1 for event in parsed_events if event.parse_status == "parsed"),
        "partial_events": sum(1 for event in parsed_events if event.parse_status == "partial"),
        "unparsed_events": sum(1 for event in parsed_events if event.parse_status == "unparsed"),
        "sessions_created": len(sessions),
        "sessions_by_view": _sessions_by_view(sessions),
        "classifier_inputs_created": len(classifier_inputs),
    }
    (outdir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse Cisco ASA logs into session-based classifier inputs.")
    parser.add_argument("input_path", help="Input log file or directory")
    parser.add_argument("--outdir", required=True, help="Output directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    run_pipeline(args.input_path, args.outdir)
    return 0


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")


def _sessions_by_view(sessions: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for session in sessions:
        counts[session.session_view] = counts.get(session.session_view, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


if __name__ == "__main__":
    raise SystemExit(main())
