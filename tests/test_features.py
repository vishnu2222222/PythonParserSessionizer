from asa_pipeline.features import summarize_session
from asa_pipeline.models import ParsedEvent
from asa_pipeline.sessionizer import SessionWindow


def test_feature_summary_captures_counts_and_domain_signals() -> None:
    events = [
        ParsedEvent(
            timestamp_iso="2026-04-11T10:00:00",
            src_ip="10.0.0.5",
            dst_ip="198.51.100.20",
            src_port=51514,
            dst_port=443,
            protocol="tcp",
            action="connect_start",
            direction="inside_to_outside",
            service_hint="https",
            raw_line="built line",
            parse_status="parsed",
        ),
        ParsedEvent(
            timestamp_iso="2026-04-11T10:00:30",
            src_ip="10.0.0.5",
            dst_ip="198.51.100.20",
            src_port=51514,
            dst_port=443,
            protocol="tcp",
            action="connect_end",
            direction="inside_to_outside",
            service_hint="https",
            bytes_count=50,
            duration_seconds=4.0,
            raw_line="teardown line",
            parse_status="parsed",
        ),
        ParsedEvent(
            timestamp_iso="2026-04-11T10:01:00",
            src_ip="203.0.113.10",
            dst_ip="10.0.0.5",
            protocol="icmp",
            action="deny",
            direction="external_to_internal",
            icmp_type=8,
            domain="very-long-suspicious-domain-example.test",
            raw_line="icmp line",
            parse_status="partial",
        ),
    ]
    session = SessionWindow(
        session_id="flow-000001",
        session_view="flow",
        group_key={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.20", "protocol": "tcp"},
        events=events,
    )

    summary = summarize_session(session)

    assert summary.duration_seconds == 60.0
    assert summary.events_per_second == 0.05
    assert summary.event_count == 3
    assert summary.parsed_event_count == 2
    assert summary.unparsed_event_count == 0
    assert summary.unique_src_ips == ["10.0.0.5", "203.0.113.10"]
    assert summary.unique_dst_ips == ["10.0.0.5", "198.51.100.20"]
    assert summary.denied_count == 1
    assert summary.allowed_count == 2
    assert summary.connect_start_count == 1
    assert summary.connect_end_count == 1
    assert summary.icmp_echo_count == 1
    assert summary.same_dst_port_ratio == 0.6667
    assert summary.same_dst_ip_ratio == 0.6667
    assert summary.inside_to_outside_count == 2
    assert summary.external_to_internal_count == 1
    assert summary.short_connection_count == 1
    assert summary.very_low_byte_conn_count == 1
    assert summary.domain_count == 1
    assert summary.long_domain_count == 1
    assert summary.high_entropy_domain_count == 1
    assert summary.periodic_gap_score > 0.9
    assert summary.burstiness_score > 0.3
    assert "has_domain_activity" in summary.notes
    assert summary.raw_evidence_lines == ["built line", "teardown line", "icmp line"]
