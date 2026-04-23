from __future__ import annotations

from collections import Counter
from datetime import datetime
from math import log2
from statistics import pstdev

from asa_pipeline.evidence import select_evidence_lines
from asa_pipeline.models import ParsedEvent, SessionSummary
from asa_pipeline.sessionizer import SessionWindow


def build_session_summaries(sessions: list[SessionWindow]) -> list[SessionSummary]:
    return [summarize_session(session) for session in sessions]


def summarize_session(session: SessionWindow) -> SessionSummary:
    events = list(session.events)
    timestamps = [_event_datetime(event) for event in events]
    valid_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    src_ips = _sorted_strings([event.src_ip for event in events])
    dst_ips = _sorted_strings([event.dst_ip for event in events])
    src_ports = _sorted_ints([event.src_port for event in events])
    dst_ports = _sorted_ints([event.dst_port for event in events])
    protocols = _sorted_strings([event.protocol for event in events])
    services = _sorted_strings([event.service_hint for event in events])
    domains = sorted({event.domain.lower() for event in events if event.domain})

    protocol_counts = _sorted_counter(Counter(event.protocol for event in events if event.protocol))
    action_counts = _sorted_counter(Counter(event.action for event in events if event.action))
    service_counts = _sorted_counter(Counter(event.service_hint for event in events if event.service_hint))
    dst_ip_counts = Counter(event.dst_ip for event in events if event.dst_ip)
    dst_port_counts = Counter(event.dst_port for event in events if event.dst_port is not None)

    denied_count = sum(1 for event in events if event.action == "deny")
    allowed_count = sum(1 for event in events if event.action in {"allow", "connect_start", "connect_end"})
    connect_start_count = sum(1 for event in events if event.action == "connect_start")
    connect_end_count = sum(1 for event in events if event.action == "connect_end")
    icmp_echo_count = sum(1 for event in events if event.protocol == "icmp" and event.icmp_type == 8)
    tcp_syn_count = sum(1 for event in events if event.protocol == "tcp" and "SYN" in event.tcp_flags)
    internal_to_internal_count = sum(1 for event in events if event.direction == "internal_to_internal")
    external_to_internal_count = sum(1 for event in events if event.direction == "external_to_internal")
    inside_to_outside_count = sum(1 for event in events if event.direction == "inside_to_outside")
    unknown_direction_count = sum(1 for event in events if event.direction in {None, "unknown"})
    short_connection_count = sum(
        1 for event in events if event.duration_seconds is not None and event.duration_seconds <= 5
    )
    very_low_byte_conn_count = sum(
        1 for event in events if event.bytes_count is not None and event.bytes_count <= 128
    )

    notes: list[str] = []
    if any(event.parse_status == "partial" for event in events):
        notes.append("contains_partial_events")
    if any(event.parse_status == "unparsed" for event in events):
        notes.append("contains_unparsed_events")
    if len(valid_timestamps) != len(events):
        notes.append("missing_timestamps")
    if domains:
        notes.append("has_domain_activity")
    if short_connection_count:
        notes.append("has_short_connections")
    if very_low_byte_conn_count:
        notes.append("has_low_byte_connections")

    start_time = min((event.timestamp_iso for event in events if event.timestamp_iso), default=None)
    end_time = max((event.timestamp_iso for event in events if event.timestamp_iso), default=None)
    duration_seconds = 0.0
    if valid_timestamps:
        duration_seconds = _round((max(valid_timestamps) - min(valid_timestamps)).total_seconds())
    events_per_second = _round(len(events) / max(duration_seconds, 1.0)) if events else 0.0
    same_dst_port_ratio = _dominant_ratio(dst_port_counts, len(events))
    same_dst_ip_ratio = _dominant_ratio(dst_ip_counts, len(events))

    return SessionSummary(
        session_id=session.session_id,
        session_view=session.session_view,
        group_key=session.group_key,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        event_count=len(events),
        parsed_event_count=sum(1 for event in events if event.parse_status == "parsed"),
        unparsed_event_count=sum(1 for event in events if event.parse_status == "unparsed"),
        unique_src_ips=src_ips,
        unique_dst_ips=dst_ips,
        src_ips=src_ips,
        dst_ips=dst_ips,
        src_ip_count=len(src_ips),
        dst_ip_count=len(dst_ips),
        unique_src_ports=src_ports,
        unique_dst_ports=dst_ports,
        events_per_second=events_per_second,
        same_dst_port_ratio=same_dst_port_ratio,
        same_dst_ip_ratio=same_dst_ip_ratio,
        top_dst_ports=[
            port
            for port, _ in sorted(dst_port_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        protocols=protocols,
        protocol_counts=protocol_counts,
        action_counts=action_counts,
        denied_count=denied_count,
        allowed_count=allowed_count,
        connect_start_count=connect_start_count,
        connect_end_count=connect_end_count,
        icmp_echo_count=icmp_echo_count,
        tcp_syn_count=tcp_syn_count,
        unique_services=services,
        service_counts=service_counts,
        internal_to_internal_count=internal_to_internal_count,
        external_to_internal_count=external_to_internal_count,
        inside_to_outside_count=inside_to_outside_count,
        unknown_direction_count=unknown_direction_count,
        short_connection_count=short_connection_count,
        very_low_byte_conn_count=very_low_byte_conn_count,
        periodic_gap_score=_periodic_gap_score(valid_timestamps),
        burstiness_score=_burstiness_score(valid_timestamps),
        domain_count=sum(1 for event in events if event.domain),
        unique_domains=domains,
        avg_domain_length=_average_domain_length(domains),
        long_domain_count=sum(1 for domain in domains if len(domain) >= 25),
        high_entropy_domain_count=sum(1 for domain in domains if _shannon_entropy(domain) >= 3.3),
        notes=notes,
        raw_evidence_lines=select_evidence_lines(events),
    )


def _event_datetime(event: ParsedEvent) -> datetime | None:
    if not event.timestamp_iso:
        return None
    try:
        return datetime.fromisoformat(event.timestamp_iso.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sorted_strings(values: list[str | None]) -> list[str]:
    return sorted({str(value) for value in values if value})


def _sorted_ints(values: list[int | None]) -> list[int]:
    return sorted({int(value) for value in values if value is not None})


def _sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _periodic_gap_score(timestamps: list[datetime]) -> float:
    if len(timestamps) < 3:
        return 0.0
    ordered = sorted(timestamps)
    gaps = [
        (ordered[index] - ordered[index - 1]).total_seconds()
        for index in range(1, len(ordered))
    ]
    if len(gaps) < 2:
        return 0.0
    mean_gap = sum(gaps) / len(gaps)
    if mean_gap <= 0:
        return 0.0
    coefficient = pstdev(gaps) / mean_gap
    score = max(0.0, 1.0 - min(coefficient, 1.5) / 1.5)
    return _round(score)


def _burstiness_score(timestamps: list[datetime]) -> float:
    if len(timestamps) < 2:
        return 0.0
    ordered = sorted(timestamps)
    anchor = ordered[0]
    bucket_counts: Counter[int] = Counter(
        int((timestamp - anchor).total_seconds() // 30) for timestamp in ordered
    )
    peak = max(bucket_counts.values(), default=0)
    return _round(peak / len(ordered))


def _average_domain_length(domains: list[str]) -> float:
    if not domains:
        return 0.0
    return _round(sum(len(domain) for domain in domains) / len(domains))


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * log2(probability)
    return entropy


def _round(value: float) -> float:
    return round(value, 4)


def _dominant_ratio(counter: Counter[object], total: int) -> float:
    if total <= 0 or not counter:
        return 0.0
    return _round(max(counter.values()) / total)
