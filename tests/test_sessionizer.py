from asa_pipeline.models import ParsedEvent
from asa_pipeline.sessionizer import (
    build_destination_sessions,
    build_destination_service_sessions,
    build_flow_sessions,
    build_source_sessions,
)


def _event(timestamp_iso: str, raw_line: str) -> ParsedEvent:
    return ParsedEvent(
        timestamp_iso=timestamp_iso,
        src_ip="203.0.113.10",
        dst_ip="10.0.0.5",
        protocol="tcp",
        src_port=40000,
        dst_port=22,
        service_hint="ssh",
        action="deny",
        raw_line=raw_line,
        parse_status="parsed",
    )


def test_sessionizer_splits_on_merge_gap() -> None:
    events = [
        _event("2026-04-11T10:00:00", "line-1"),
        _event("2026-04-11T10:01:20", "line-2"),
        _event("2026-04-11T10:03:30", "line-3"),
    ]

    flow_sessions = build_flow_sessions(events)
    source_sessions = build_source_sessions(events)
    destination_sessions = build_destination_sessions(events, post_merge_gap_seconds=120)

    assert [len(session.events) for session in flow_sessions] == [2, 1]
    assert [len(session.events) for session in source_sessions] == [2, 1]
    assert [len(session.events) for session in destination_sessions] == [2, 1]


def test_sessionizer_respects_rolling_window_even_with_small_gaps() -> None:
    events = [
        _event("2026-04-11T10:00:00", "line-1"),
        _event("2026-04-11T10:01:20", "line-2"),
        _event("2026-04-11T10:02:40", "line-3"),
        _event("2026-04-11T10:04:00", "line-4"),
        _event("2026-04-11T10:05:20", "line-5"),
    ]

    flow_sessions = build_flow_sessions(events)

    assert [len(session.events) for session in flow_sessions] == [4, 1]


def test_destination_sessions_group_many_sources_to_one_victim_port() -> None:
    events = [
        ParsedEvent(
            timestamp_iso=f"2025-03-03T07:{minute:02d}:00",
            src_interface="outside",
            src_ip=src_ip,
            src_port=src_port,
            dst_interface="inside",
            dst_ip="192.168.2.99",
            dst_port=443,
            protocol=protocol,
            action=action,
            raw_line=f"line-{index}",
            parse_status="parsed",
        )
        for index, (minute, src_ip, src_port, protocol, action) in enumerate(
            [
                (46, "104.21.45.202", 2869, "tcp", "connect_start"),
                (47, "185.176.27.14", 14374, "udp", "connect_start"),
                (48, "34.93.22.10", 59422, "udp", "connect_start"),
                (49, "34.93.22.10", 59422, "udp", "connect_end"),
            ],
            start=1,
        )
    ]

    destination_sessions = build_destination_service_sessions(events)

    assert len(destination_sessions) == 1
    assert destination_sessions[0].session_view == "destination"
    assert destination_sessions[0].group_key == {"dst_ip": "192.168.2.99", "dst_port": 443}
    assert len(destination_sessions[0].events) == 4


def test_destination_session_post_merge_only_applies_to_destination_view() -> None:
    events = [
        ParsedEvent(
            timestamp_iso=timestamp_iso,
            src_interface="outside",
            src_ip="203.0.113.10",
            src_port=src_port,
            dst_interface="inside",
            dst_ip="10.0.0.5",
            dst_port=443,
            protocol="tcp",
            action="deny",
            raw_line=f"line-{index}",
            parse_status="parsed",
        )
        for index, (timestamp_iso, src_port) in enumerate(
            [
                ("2026-04-11T10:00:00", 40000),
                ("2026-04-11T10:01:00", 40001),
                ("2026-04-11T10:04:45", 40002),
                ("2026-04-11T10:05:30", 40003),
                ("2026-04-11T10:09:30", 40004),
                ("2026-04-11T10:10:15", 40005),
            ],
            start=1,
        )
    ]

    flow_sessions = build_flow_sessions(events)
    source_sessions = build_source_sessions(events)
    destination_sessions = build_destination_sessions(events)
    unmerged_destination_sessions = build_destination_sessions(events, post_merge_gap_seconds=120)

    assert [len(session.events) for session in flow_sessions] == [2, 2, 2]
    assert [len(session.events) for session in source_sessions] == [2, 2, 2]
    assert [len(session.events) for session in destination_sessions] == [6]
    assert [len(session.events) for session in unmerged_destination_sessions] == [2, 2, 2]
