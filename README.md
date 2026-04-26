# Attack Vector Classification for Cisco ASA Logs

This project was built for a cybersecurity LLM workflow where the final system should be able to detect one or more attack vectors from Cisco ASA logs, such as:

- Port scanning
- DoS / flood behavior
- Brute force activity
- Lateral movement
- Privilege escalation indicators
- Suspicious or unknown activity
- Benign network behavior

## Why This Exists

Raw Cisco ASA logs are difficult for small LLMs and basic classifiers to analyze directly because:

- Important evidence is spread across many lines
- A single attack pattern may not be obvious from one log line. For example, a port scan becomes clear only after seeing many connection attempts across ports or destinations.
- Firewall logs are noisy and repetitive
- Normal traffic, denied connections, teardown messages, ICMP events, NAT translations, and connection events can all appear together.
- LLMs do not naturally understand network sessions
- A model may see tokens, but it does not automatically know which source IP, destination IP, port, protocol, and timestamp belong to the same behavior pattern.
- Long logs can exceed context limits
- Instead of giving the model thousands of raw lines, this pipeline compresses the evidence into structured summaries.

The parser and sessionizer solve this by turning raw logs into organized security evidence.

## What the Pipeline Does

The pipeline has three main stages:

### 1. Parse

The parser reads each raw Cisco ASA log line and extracts useful fields such as:

- Timestamp
- ASA message ID
- Severity
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Action or event type
- Raw message text
- Parse status

This converts unstructured log text into normalized JSON records.

### 2. Sessionize

The sessionizer groups related events into behavioral views. Instead of treating every line separately, it creates summaries of activity over time.

Example session views may include:

- Source IP behavior
- Destination IP behavior
- Source-to-destination flow behavior
- Destination port behavior
- Protocol behavior
- High-volume denied connection patterns

This helps reveal attack patterns such as:

- One source hitting many ports
- Many sources hitting one destination
- Repeated denied TCP connections
- High event rate over a short window
- Repeated ICMP or SYN-style probing
- Unusual traffic concentration

### 3. Generate Classifier Inputs

The final stage creates model-ready JSONL records that summarize the evidence in a format suitable for:

- Rule-based classifiers
- Traditional ML classifiers
- Fine-tuned open-source LLMs
- Local LLM inference through tools like LM Studio or Ollama
- Final incident explanation generation

## Repository Structure

```text
PythonParserSessionizer/
|
+-- asa_pipeline/
|   +-- cli.py
|   +-- parser.py
|   +-- sessionizer.py
|   +-- ...
|
+-- tests/
|   +-- data/
|       +-- sample Cisco ASA logs
|
+-- pyproject.toml
+-- README.md
+-- .gitignore
```

## Input

The pipeline accepts:

- A single Cisco ASA log file
- A directory containing multiple log files

Supported file types include:

- `.log`
- `.txt`
- `.csv`
- `.jsonl`

## Output

When the pipeline runs, it writes the following files to the selected output directory:

- `parsed_events.jsonl`
- `sessions.jsonl`
- `classifier_inputs.jsonl`
- `summary.json`

### `parsed_events.jsonl`

Contains one normalized JSON object per parsed log line.

Example:

```json
{
  "timestamp": "2025-03-01T12:00:01",
  "message_id": "106023",
  "severity": "4",
  "src_ip": "192.168.1.50",
  "src_port": 51522,
  "dst_ip": "10.0.0.5",
  "dst_port": 22,
  "protocol": "TCP",
  "action": "deny",
  "raw_message": "%ASA-4-106023: Deny tcp src outside:192.168.1.50/51522 dst inside:10.0.0.5/22"
}
```

### `sessions.jsonl`

Contains grouped behavior summaries.

Example:

```json
{
  "session_key": "src_ip=192.168.1.50",
  "event_count": 125,
  "unique_dst_ips": 3,
  "unique_dst_ports": 42,
  "denied_count": 119,
  "allowed_count": 6,
  "protocols": ["TCP", "ICMP"],
  "duration_seconds": 18,
  "events_per_second": 6.94
}
```

### `classifier_inputs.jsonl`

Contains model-ready evidence records.

Example:

```json
{
  "record_id": "session_0001",
  "evidence": "Source 192.168.1.50 generated 125 events in 18 seconds. It contacted 3 destination IPs and 42 unique destination ports. Most events were denied TCP connections.",
  "features": {
    "event_count": 125,
    "unique_dst_ports": 42,
    "denied_count": 119,
    "events_per_second": 6.94
  }
}
```

### `summary.json`

Contains pipeline counters and processing metadata.

Example:

```json
{
  "files_processed": 1,
  "lines_seen": 500,
  "events_parsed": 487,
  "events_failed": 13,
  "sessions_created": 28,
  "classifier_records_created": 28
}
```

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/vishnu2222222/PythonParserSessionizer.git
cd PythonParserSessionizer
```

### 2. Install the project

```bash
python -m pip install -e .
```

### 3. Run the pipeline on a sample log

```bash
python -m asa_pipeline.cli "tests/data/cisco_asa_dos_flood_sample.log" --outdir out
```

### 4. Run the pipeline on a directory of logs

```bash
python -m asa_pipeline.cli "/path/to/asa-logs" --outdir out
```

## End-to-End Workflow

The full workflow looks like this:

```text
Raw Cisco ASA log file
        v
Parser
        v
Normalized parsed events
        v
Sessionizer
        v
Behavior-level session summaries
        v
Classifier input generator
        v
ML model or LLM
        v
Final structured attack-vector result
```

## How This Helps the LLM

Instead of giving the model raw logs like this:

```text
%ASA-4-106023: Deny tcp src outside:192.168.1.50/51522 dst inside:10.0.0.5/22
%ASA-4-106023: Deny tcp src outside:192.168.1.50/51523 dst inside:10.0.0.5/23
%ASA-4-106023: Deny tcp src outside:192.168.1.50/51524 dst inside:10.0.0.5/80
```

The pipeline gives the model structured evidence like this:

- A single source IP attempted connections to many destination ports on the same internal host.
- Most attempts were denied.
- The activity occurred in a short time window.
- This pattern is consistent with port scanning behavior.

This makes the classification task easier, more consistent, and more explainable.

## Example Model Output

A downstream model or LLM should return structured output like:

```json
{
  "malicious": true,
  "attack_vectors": ["port_scan"],
  "reason": "A single external source contacted one internal destination across many unique ports with repeated denied TCP attempts in a short time window."
}
```

For multi-attack logs, the output can include multiple labels:

```json
{
  "malicious": true,
  "attack_vectors": ["port_scan", "dos_flood"],
  "reason": "The log shows both broad port probing and a high event rate of repeated denied traffic against the same destination."
}
```

## Intended Use

This project is intended for:

- Cybersecurity class projects
- SOC workflow prototyping
- Firewall log preprocessing
- LLM-assisted security analysis
- Attack-vector classification experiments
- Building training data for supervised fine-tuning

## Current Scope

This repository currently focuses on the preprocessing layer:

- Parsing Cisco ASA logs
- Creating normalized event records
- Grouping related activity into sessions
- Creating classifier-ready JSONL files

The actual fine-tuned model is expected to be a separate stage in the larger project.

## Not a Full IDS

This project does not replace:

- Cisco Secure Firewall
- SIEM correlation rules
- IDS / IPS tools
- EDR tools
- Human analyst review

It is an evidence preparation layer that makes firewall logs easier for a classifier or LLM to analyze.

## Planned Improvements

Potential next steps:

- Add more Cisco ASA message ID parsers
- Improve session grouping logic
- Add confidence scoring
- Add labeled training examples
- Add attack-vector ground truth files
- Add evaluation metrics
- Add model inference script
- Add support for batch classification
- Add a simple web or CLI demo
- Add more tests for different ASA log formats

## Example Attack Labels

The downstream classifier can use labels such as:

```json
[
  "benign",
  "port_scan",
  "dos_flood",
  "brute_force",
  "lateral_movement",
  "privilege_escalation",
  "web_attack",
  "c2_beacon",
  "dns_exfiltration",
  "unknown"
]
```

These labels can be adjusted depending on the final class requirements and available training data.

## Development Notes

Install in editable mode:

```bash
python -m pip install -e .
```

Run tests:

```bash
pytest
```

Run the CLI:

```bash
python -m asa_pipeline.cli "<input_log_or_directory>" --outdir "<output_directory>"
```

## Project Summary

This repository is the preprocessing foundation for a Cisco ASA attack-vector classification system.

The key idea is simple:

- Raw firewall logs are too messy for reliable model reasoning.
- Parsed and sessionized logs give the model cleaner evidence.
- Cleaner evidence leads to better attack-vector classification.
