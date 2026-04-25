# Attack Vector Classification for Cisco ASA Logs

`asa_pipeline` converts raw Cisco ASA firewall logs into structured, session-level records that can be used for attack vector classification and downstream security analysis.

## What This Project Does

The pipeline is designed for SOC and detection engineering workflows where unstructured ASA logs need to become machine-usable features. It performs:

- Parsing and normalization of ASA log lines
- Sessionization across multiple flow views
- Feature extraction for each session
- Generation of classifier-ready JSONL records

The output can be sent directly to ML classifiers or to LLM-based reasoning layers that enrich attack vector identification, helping automate core IDS triage steps.

## Input and Output

Input:

- A Cisco ASA log file (`.log`, `.txt`, `.csv`, or `.jsonl`) or a directory containing log files

Output (`--outdir`):

- `parsed_events.jsonl`: normalized events with parse status
- `sessions.jsonl`: sessionized activity summaries
- `classifier_inputs.jsonl`: records ready for attack-vector classification
- `summary.json`: pipeline counters and processing summary

## Quick Start

```bash
python -m pip install -e .
python -m asa_pipeline.cli "tests/data/cisco_asa_dos_flood_sample.log" --outdir out
```

For a directory of logs:

```bash
python -m asa_pipeline.cli "/path/to/asa-logs" --outdir out
```

## Example IDS Automation Flow

1. Export Cisco ASA firewall logs from your SIEM/syslog pipeline.
2. Run this project to produce structured classifier inputs.
3. Score records with your attack-vector classifier.
4. Send classifier output (plus evidence fields) to an LLM for contextual reasoning, incident summarization, and analyst-facing explanations.

This gives you a practical hybrid approach: deterministic log parsing + model-based classification + LLM-assisted interpretation.

## Notes

- This project is an analysis and enrichment component, not a full IDS replacement.
- Best results come from integrating outputs with existing alerting, case management, and response workflows.
