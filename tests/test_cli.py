from __future__ import annotations

import json
from pathlib import Path
import shutil
from uuid import uuid4

from asa_pipeline.cli import main


def test_cli_processes_directory_input() -> None:
    base = Path.cwd() / f".cli-test-{uuid4().hex}"
    try:
        input_dir = base / "logs"
        input_dir.mkdir(parents=True)
        outdir = base / "out"

        log_one = input_dir / "one.log"
        log_two = input_dir / "two.log"
        log_one.write_text(
            "\n".join(
                [
                    'Apr 11 2026 10:00:00: %ASA-4-106023: Deny icmp src outside:203.0.113.10 dst inside:10.0.0.5 (type 8, code 0) by access-group "outside_access_in"',
                    "Apr 11 2026 10:00:30: %ASA-4-106015: Deny TCP (no connection) from 203.0.113.10/40000 to 10.0.0.5/22 flags SYN on interface outside",
                ]
            ),
            encoding="utf-8",
        )
        log_two.write_text(
            "\n".join(
                [
                    "Apr 11 2026 10:01:00: %ASA-6-302013: Built outbound TCP connection 12345 for inside:10.0.0.5/51514 (10.0.0.5/51514) to outside:198.51.100.20/443 (198.51.100.20/443)",
                    "Apr 11 2026 10:01:04: %ASA-6-302014: Teardown TCP connection 12345 for inside:10.0.0.5/51514 to outside:198.51.100.20/443 duration 0:00:04 bytes 532",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = main([str(input_dir), "--outdir", str(outdir)])

        assert exit_code == 0
        assert (outdir / "parsed_events.jsonl").exists()
        assert (outdir / "sessions.jsonl").exists()
        assert (outdir / "classifier_inputs.jsonl").exists()
        assert (outdir / "summary.json").exists()

        parsed_events = [
            json.loads(line)
            for line in (outdir / "parsed_events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        sessions = [
            json.loads(line)
            for line in (outdir / "sessions.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        classifier_inputs = [
            json.loads(line)
            for line in (outdir / "classifier_inputs.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        summary = json.loads((outdir / "summary.json").read_text(encoding="utf-8"))

        assert len(parsed_events) == 4
        assert all(event["raw_line"] for event in parsed_events)
        assert len(sessions) == 8
        assert classifier_inputs == []
        assert summary["classifier_inputs_created"] == 0
        assert summary["files_processed"] == 2
        assert summary["lines_processed"] == 4
    finally:
        shutil.rmtree(base, ignore_errors=True)
