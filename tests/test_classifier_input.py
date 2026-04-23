from pathlib import Path

from asa_pipeline.classifier_input import (
    ALLOWED_ATTACK_VECTORS,
    ATTACK_VECTOR_IMPORTANT_DISTINCTIONS,
    ATTACK_VECTOR_LABEL_HINTS,
    build_classifier_input_records,
)
from asa_pipeline.features import build_session_summaries
from asa_pipeline.models import SessionSummary
from asa_pipeline.normalizer import normalize_event
from asa_pipeline.parser import parse_line
from asa_pipeline.sessionizer import build_all_session_views

TEST_DATA_DIR = Path(__file__).with_name("data")


def _summary(
    session_id: str,
    session_view: str,
    **overrides: object,
) -> SessionSummary:
    defaults: dict[str, object] = {
        "group_key": {},
        "start_time": None,
        "end_time": None,
        "duration_seconds": 0.0,
        "event_count": 1,
        "parsed_event_count": 1,
        "unparsed_event_count": 0,
        "unique_src_ips": [],
        "unique_dst_ips": [],
        "src_ips": [],
        "dst_ips": [],
        "src_ip_count": 0,
        "dst_ip_count": 0,
        "unique_src_ports": [],
        "unique_dst_ports": [],
        "events_per_second": 0.0,
        "same_dst_port_ratio": 0.0,
        "same_dst_ip_ratio": 0.0,
        "top_dst_ports": [],
        "protocols": [],
        "protocol_counts": {},
        "action_counts": {},
        "denied_count": 0,
        "allowed_count": 0,
        "connect_start_count": 0,
        "connect_end_count": 0,
        "icmp_echo_count": 0,
        "tcp_syn_count": 0,
        "unique_services": [],
        "service_counts": {},
        "internal_to_internal_count": 0,
        "external_to_internal_count": 0,
        "inside_to_outside_count": 0,
        "unknown_direction_count": 0,
        "short_connection_count": 0,
        "very_low_byte_conn_count": 0,
        "periodic_gap_score": 0.0,
        "burstiness_score": 0.0,
        "domain_count": 0,
        "unique_domains": [],
        "avg_domain_length": 0.0,
        "long_domain_count": 0,
        "high_entropy_domain_count": 0,
        "notes": [],
        "raw_evidence_lines": [session_id],
    }
    defaults.update(overrides)
    return SessionSummary(
        session_id=session_id,
        session_view=session_view,
        **defaults,
    )


def _text_value(text: str, key: str) -> str:
    prefix = f"{key}="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    raise AssertionError(f"Missing classifier input field: {key}")


def _sample_lines(name: str) -> list[str]:
    return (TEST_DATA_DIR / name).read_text(encoding="utf-8").splitlines()


def test_classifier_generation_prefers_destination_sessions_for_flood_behavior() -> None:
    sessions = [
        _summary(
            "flow-000001",
            "flow",
            group_key={"src_ip": "198.51.100.23", "dst_ip": "172.16.2.77", "protocol": "tcp"},
            event_count=10,
            parsed_event_count=10,
            denied_count=5,
        ),
        _summary(
            "source-000001",
            "source",
            group_key={"src_ip": "198.51.100.23"},
            event_count=10,
            parsed_event_count=10,
            denied_count=5,
        ),
        _summary(
            "destination-000001",
            "destination",
            group_key={"dst_ip": "172.16.2.77", "dst_port": 443},
            event_count=12,
            parsed_event_count=12,
            unique_src_ips=["198.51.100.23", "203.0.113.10", "203.0.113.44", "104.21.45.202"],
            unique_dst_ips=["172.16.2.77"],
            unique_dst_ports=[443],
            events_per_second=0.2,
            same_dst_port_ratio=1.0,
            same_dst_ip_ratio=1.0,
            external_to_internal_count=12,
            connect_start_count=12,
        ),
    ]

    records = build_classifier_input_records(sessions)

    assert [record["session_id"] for record in records][:2] == [
        "destination-000001",
        "source-000001",
    ]


def test_classifier_record_includes_attack_vector_schema() -> None:
    records = build_classifier_input_records(
        [
            _summary(
                "source-000001",
                "source",
                group_key={"src_ip": "203.0.113.10"},
                event_count=8,
                parsed_event_count=8,
                denied_count=8,
            )
        ]
    )

    assert len(records) == 1

    schema = records[0]["attack_vector_schema"]

    assert schema == {
        "label_field": "attack_vector",
        "allowed_values": list(ALLOWED_ATTACK_VECTORS),
        "label_hints": ATTACK_VECTOR_LABEL_HINTS,
        "important_distinctions": ATTACK_VECTOR_IMPORTANT_DISTINCTIONS,
    }


def test_classifier_input_text_contains_only_evidence_sections() -> None:
    last_raw_evidence_line = (
        "Apr 11 2026 10:00:30: %ASA-4-106015: Deny TCP (no connection) from "
        "203.0.113.10/40000 to 10.0.0.5/22 flags SYN on interface outside"
    )
    records = build_classifier_input_records(
        [
            _summary(
                "source-000001",
                "source",
                group_key={"src_ip": "203.0.113.10"},
                event_count=8,
                parsed_event_count=8,
                denied_count=8,
                raw_evidence_lines=[
                    'Apr 11 2026 10:00:00: %ASA-4-106023: Deny icmp src outside:203.0.113.10 dst inside:10.0.0.5 (type 8, code 0) by access-group "outside_access_in"',
                    last_raw_evidence_line,
                ],
            )
        ]
    )

    assert len(records) == 1

    text = records[0]["text"]

    assert "[TASK]" not in text
    assert "Determine whether this session is malicious" not in text
    assert "Return valid JSON only" not in text
    assert text.index("[SESSION_METADATA]") < text.index("[BEHAVIOR_FEATURES]") < text.index("[RAW_EVIDENCE]")
    assert "[SESSION_METADATA]" in text
    assert "[BEHAVIOR_FEATURES]" in text
    assert "[RAW_EVIDENCE]" in text
    assert text.strip().endswith(last_raw_evidence_line)


def test_classifier_generation_drops_unknown_source_placeholder_when_better_session_exists() -> None:
    sessions = [
        _summary(
            "source-000001",
            "source",
            group_key={"src_ip": "<unknown>"},
            event_count=12,
            parsed_event_count=0,
            protocols=["tcp"],
            action_counts={"connect_start": 12},
        ),
        _summary(
            "destination-000001",
            "destination",
            group_key={"dst_ip": "192.168.2.99", "dst_port": 443},
            event_count=12,
            parsed_event_count=12,
            unique_src_ips=["104.21.45.202", "185.176.27.14", "34.93.22.10"],
            unique_dst_ips=["192.168.2.99"],
            unique_dst_ports=[443],
            same_dst_port_ratio=1.0,
            same_dst_ip_ratio=1.0,
            external_to_internal_count=12,
            connect_start_count=12,
        ),
    ]

    records = build_classifier_input_records(sessions)

    assert [record["session_id"] for record in records] == ["destination-000001"]


def test_source_session_is_preferred_over_flow_session_for_non_flood_behavior() -> None:
    sessions = [
        _summary(
            "flow-000001",
            "flow",
            group_key={"src_ip": "198.51.100.23", "dst_ip": "172.16.2.77", "protocol": "tcp"},
            event_count=10,
            parsed_event_count=10,
            denied_count=5,
        ),
        _summary(
            "source-000001",
            "source",
            group_key={"src_ip": "198.51.100.23"},
            event_count=10,
            parsed_event_count=10,
            denied_count=5,
        ),
    ]

    records = build_classifier_input_records(sessions)

    assert [record["session_id"] for record in records] == ["source-000001", "flow-000001"]


def test_dos_flood_pattern_selects_destination_classifier_input() -> None:
    lines = [
        "%ASA-6-302013: Mar 03 2025 07:46:32: %ASA-6-302013: Built outside TCP connection 531422667 for outside:104.21.45.202/2869 (104.21.45.202/2869) to inside:192.168.2.99/443 (192.168.2.99/443)",
        "%ASA-6-302013: Mar 03 2025 07:47:10: %ASA-6-302013: Built outside TCP connection 625304151 for outside:185.176.27.14/14374 (185.176.27.14/14374) to inside:192.168.2.99/443 (192.168.2.99/443)",
        "%ASA-6-302015: Mar 03 2025 07:47:32: %ASA-6-302015: Built inbound UDP connection 699279366 for outside:103.224.182.244/52840 (103.224.182.244/52840) to inside:192.168.2.99/443 (192.168.2.99/443)",
        "%ASA-6-302016: Mar 03 2025 07:47:53: %ASA-6-302016: Teardown UDP connection 844229207 for outside:103.224.182.244/52840 to inside:192.168.2.99/443 duration 0:00:01 bytes 222",
        "%ASA-6-302015: Mar 03 2025 07:48:19: %ASA-6-302015: Built inbound UDP connection 708554743 for outside:34.93.22.10/59422 (34.93.22.10/59422) to inside:192.168.2.99/443 (192.168.2.99/443)",
        "%ASA-6-302016: Mar 03 2025 07:48:53: %ASA-6-302016: Teardown UDP connection 441633709 for outside:34.93.22.10/59422 to inside:192.168.2.99/443 duration 0:00:01 bytes 187",
        "%ASA-6-302013: Mar 03 2025 07:49:19: %ASA-6-302013: Built outside TCP connection 461901122 for outside:51.38.194.16/26756 (51.38.194.16/26756) to inside:192.168.2.99/443 (192.168.2.99/443)",
        "%ASA-6-302013: Mar 03 2025 07:49:53: %ASA-6-302013: Built outside TCP connection 904696391 for outside:45.33.32.156/64481 (45.33.32.156/64481) to inside:192.168.2.99/443 (192.168.2.99/443)",
    ]

    normalized_events = [normalize_event(parse_line(line)) for line in lines]
    summaries = build_session_summaries(build_all_session_views(normalized_events))
    records = build_classifier_input_records(summaries)

    assert len(records) == 1
    selected = records[0]

    assert selected["session_view"] == "destination"
    assert selected["group_key"] == {"dst_ip": "192.168.2.99", "dst_port": 443}
    assert _text_value(selected["text"], "unique_dst_ips") == "[\"192.168.2.99\"]"
    assert _text_value(selected["text"], "unique_dst_ports") == "[443]"
    assert _text_value(selected["text"], "same_dst_ip_ratio") == "1.0"
    assert _text_value(selected["text"], "same_dst_port_ratio") == "1.0"
    assert "104.21.45.202" in _text_value(selected["text"], "unique_src_ips")
    assert "185.176.27.14" in _text_value(selected["text"], "unique_src_ips")
    assert _text_value(selected["text"], "external_to_internal_count") == "8"
    assert _text_value(selected["text"], "connect_start_count") == "6"
    assert (
        selected["attack_vector_schema"]["important_distinctions"][-1]
        == "If traffic is concentrated on one destination IP and one port, prefer dos_flood over port_scan."
    )


def test_dos_flood_sample_merges_destination_fragments_into_classifier_candidate() -> None:
    normalized_events = [
        normalize_event(parse_line(line))
        for line in _sample_lines("cisco_asa_dos_flood_sample.log")
    ]
    summaries = build_session_summaries(build_all_session_views(normalized_events))
    victim_sessions = [
        summary
        for summary in summaries
        if summary.session_view == "destination"
        and summary.group_key == {"dst_ip": "192.168.2.99", "dst_port": 443}
    ]

    assert len(victim_sessions) == 1

    merged_session = victim_sessions[0]
    assert merged_session.event_count >= 30
    assert len(merged_session.unique_src_ips) >= 8
    assert merged_session.same_dst_ip_ratio == 1.0
    assert merged_session.same_dst_port_ratio == 1.0

    records = build_classifier_input_records(summaries)

    assert records[0]["session_id"] == merged_session.session_id
    assert records[0]["session_view"] == "destination"
    assert records[0]["group_key"] == {"dst_ip": "192.168.2.99", "dst_port": 443}


def test_real_log_classifier_input_text_ends_at_raw_evidence() -> None:
    normalized_events = [
        normalize_event(parse_line(line))
        for line in _sample_lines("cisco_asa_dos_flood_sample.log")
    ]
    summaries = build_session_summaries(build_all_session_views(normalized_events))
    records = build_classifier_input_records(summaries)

    selected_record = records[0]
    selected_summary = next(
        summary for summary in summaries if summary.session_id == selected_record["session_id"]
    )
    text = selected_record["text"]

    assert "[TASK]" not in text
    assert "Return valid JSON only" not in text
    assert text.strip().endswith(selected_summary.raw_evidence_lines[-1])
