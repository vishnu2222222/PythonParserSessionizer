from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ParseStatus = Literal["parsed", "partial", "unparsed"]


@dataclass(slots=True)
class ParsedEvent:
    timestamp_raw: str | None = None
    timestamp_iso: str | None = None
    message_code: str | None = None
    severity: int | None = None
    message_id: str | None = None
    action: str | None = None
    protocol: str | None = None
    src_interface: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_interface: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    tcp_flags: list[str] = field(default_factory=list)
    bytes_count: int | None = None
    duration_seconds: float | None = None
    url: str | None = None
    domain: str | None = None
    query_type: str | None = None
    direction: str | None = None
    service_hint: str | None = None
    raw_line: str = ""
    parse_status: ParseStatus = "unparsed"
    parse_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SessionSummary:
    session_id: str
    session_view: str
    group_key: dict[str, str | int | None]
    start_time: str | None
    end_time: str | None
    duration_seconds: float
    event_count: int
    parsed_event_count: int
    unparsed_event_count: int
    unique_src_ips: list[str] = field(default_factory=list)
    unique_dst_ips: list[str] = field(default_factory=list)
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    src_ip_count: int = 0
    dst_ip_count: int = 0
    unique_src_ports: list[int] = field(default_factory=list)
    unique_dst_ports: list[int] = field(default_factory=list)
    events_per_second: float = 0.0
    same_dst_port_ratio: float = 0.0
    same_dst_ip_ratio: float = 0.0
    top_dst_ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    action_counts: dict[str, int] = field(default_factory=dict)
    denied_count: int = 0
    allowed_count: int = 0
    connect_start_count: int = 0
    connect_end_count: int = 0
    icmp_echo_count: int = 0
    tcp_syn_count: int = 0
    unique_services: list[str] = field(default_factory=list)
    service_counts: dict[str, int] = field(default_factory=dict)
    internal_to_internal_count: int = 0
    external_to_internal_count: int = 0
    inside_to_outside_count: int = 0
    unknown_direction_count: int = 0
    short_connection_count: int = 0
    very_low_byte_conn_count: int = 0
    periodic_gap_score: float = 0.0
    burstiness_score: float = 0.0
    domain_count: int = 0
    unique_domains: list[str] = field(default_factory=list)
    avg_domain_length: float = 0.0
    long_domain_count: int = 0
    high_entropy_domain_count: int = 0
    notes: list[str] = field(default_factory=list)
    raw_evidence_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
