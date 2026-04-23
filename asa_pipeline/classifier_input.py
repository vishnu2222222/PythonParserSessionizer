from __future__ import annotations

import json

from asa_pipeline.models import SessionSummary

ALLOWED_CLASSIFIER_VIEWS = {"source", "flow", "destination"}
ALLOWED_ATTACK_VECTORS = (
    "benign",
    "port_scan",
    "dos_flood",
    "sql_injection",
    "xss",
    "c2_beacon",
    "dns_exfiltration",
    "priv_escalation",
    "lateral_movement",
    "cred_harvesting",
    "unknown",
)
ATTACK_VECTOR_LABEL_HINTS = {
    "benign": "normal traffic with no clear malicious pattern",
    "port_scan": "typically one source probing many ports or many hosts",
    "dos_flood": (
        "many repeated connections targeting the same destination IP and/or port, "
        "often from one or many sources, indicating flooding or resource exhaustion"
    ),
    "sql_injection": "database-related web requests containing SQL keywords or injection patterns",
    "xss": "web requests containing script payloads or browser-executed code patterns",
    "c2_beacon": "periodic, repeated connections to the same external endpoint with consistent timing",
    "dns_exfiltration": (
        "unusually high DNS activity, long/random-looking domains, or encoded data in DNS requests"
    ),
    "priv_escalation": "activity indicating privilege elevation or admin-level access attempts",
    "lateral_movement": (
        "internal host communicating with many internal systems over administrative ports "
        "or moving between internal hosts"
    ),
    "cred_harvesting": (
        "repeated authentication attempts or suspicious access to credential-related services"
    ),
    "unknown": "suspicious activity that does not clearly match any defined category",
}
ATTACK_VECTOR_IMPORTANT_DISTINCTIONS = [
    "port_scan = usually one source -> many ports or many hosts",
    (
        "dos_flood = traffic concentrated on one destination IP/port, often from many sources "
        "or repeated attempts"
    ),
    (
        "If traffic is concentrated on one destination IP and one port, prefer dos_flood "
        "over port_scan."
    ),
]


def build_classifier_input_record(summary: SessionSummary) -> dict[str, object]:
    return {
        "session_id": summary.session_id,
        "session_view": summary.session_view,
        "group_key": summary.group_key,
        "attack_vector_schema": build_attack_vector_schema(),
        "text": build_classifier_input_text(summary),
    }


def build_attack_vector_schema() -> dict[str, object]:
    return {
        "label_field": "attack_vector",
        "allowed_values": list(ALLOWED_ATTACK_VECTORS),
        "label_hints": ATTACK_VECTOR_LABEL_HINTS.copy(),
        "important_distinctions": list(ATTACK_VECTOR_IMPORTANT_DISTINCTIONS),
    }


def build_classifier_input_text(summary: SessionSummary) -> str:
    lines = [
        "[SESSION_METADATA]",
        f"session_id={summary.session_id}",
        f"session_view={summary.session_view}",
        f"group_key={json.dumps(summary.group_key, sort_keys=True)}",
        f"start_time={summary.start_time}",
        f"end_time={summary.end_time}",
        f"event_count={summary.event_count}",
        "[BEHAVIOR_FEATURES]",
        f"duration_seconds={summary.duration_seconds}",
        f"events_per_second={summary.events_per_second}",
        f"parsed_event_count={summary.parsed_event_count}",
        f"unparsed_event_count={summary.unparsed_event_count}",
        f"unique_src_ips={json.dumps(summary.unique_src_ips)}",
        f"unique_dst_ips={json.dumps(summary.unique_dst_ips)}",
        f"src_ips={json.dumps(summary.src_ips)}",
        f"dst_ips={json.dumps(summary.dst_ips)}",
        f"src_ip_count={summary.src_ip_count}",
        f"dst_ip_count={summary.dst_ip_count}",
        f"unique_src_ports={json.dumps(summary.unique_src_ports)}",
        f"unique_dst_ports={json.dumps(summary.unique_dst_ports)}",
        f"same_dst_port_ratio={summary.same_dst_port_ratio}",
        f"same_dst_ip_ratio={summary.same_dst_ip_ratio}",
        f"top_dst_ports={json.dumps(summary.top_dst_ports)}",
        f"protocols={json.dumps(summary.protocols)}",
        f"protocol_counts={json.dumps(summary.protocol_counts, sort_keys=True)}",
        f"action_counts={json.dumps(summary.action_counts, sort_keys=True)}",
        f"denied_count={summary.denied_count}",
        f"allowed_count={summary.allowed_count}",
        f"connect_start_count={summary.connect_start_count}",
        f"connect_end_count={summary.connect_end_count}",
        f"icmp_echo_count={summary.icmp_echo_count}",
        f"tcp_syn_count={summary.tcp_syn_count}",
        f"unique_services={json.dumps(summary.unique_services)}",
        f"service_counts={json.dumps(summary.service_counts, sort_keys=True)}",
        f"internal_to_internal_count={summary.internal_to_internal_count}",
        f"external_to_internal_count={summary.external_to_internal_count}",
        f"inside_to_outside_count={summary.inside_to_outside_count}",
        f"unknown_direction_count={summary.unknown_direction_count}",
        f"short_connection_count={summary.short_connection_count}",
        f"very_low_byte_conn_count={summary.very_low_byte_conn_count}",
        f"periodic_gap_score={summary.periodic_gap_score}",
        f"burstiness_score={summary.burstiness_score}",
        f"domain_count={summary.domain_count}",
        f"unique_domains={json.dumps(summary.unique_domains)}",
        f"avg_domain_length={summary.avg_domain_length}",
        f"long_domain_count={summary.long_domain_count}",
        f"high_entropy_domain_count={summary.high_entropy_domain_count}",
        f"notes={json.dumps(summary.notes)}",
        "[RAW_EVIDENCE]",
        *summary.raw_evidence_lines,
    ]
    return "\n".join(lines)


def build_classifier_input_records(sessions: list[SessionSummary]) -> list[dict[str, object]]:
    filtered_sessions = [
        session
        for session in sessions
        if session.session_view in ALLOWED_CLASSIFIER_VIEWS and session_is_classifier_worthy(session)
    ]
    filtered_sessions = _drop_unknown_source_placeholders(filtered_sessions)
    filtered_sessions.sort(key=_classifier_priority_tuple, reverse=True)
    return [build_classifier_input_record(session) for session in filtered_sessions]


def session_is_classifier_worthy(session: SessionSummary) -> bool:
    return (
        session.event_count >= 8
        or len(session.unique_dst_ports) >= 5
        or session.denied_count >= 5
        or session.icmp_echo_count >= 3
        or _looks_flood_like(session)
    )


def classifier_view_rank(session: SessionSummary) -> int:
    return _view_priority(session)


def _classifier_priority_tuple(session: SessionSummary) -> tuple[object, ...]:
    return (
        0 if _is_unknown_source_placeholder(session) else 1,
        1 if session.parsed_event_count > 0 else 0,
        1 if _looks_flood_like(session) else 0,
        _view_priority(session),
        session.parsed_event_count,
        session.event_count,
        len(_unique_src_ips(session)),
        len(session.unique_dst_ports),
        session.events_per_second,
        session.same_dst_port_ratio,
        session.same_dst_ip_ratio,
        session.session_id,
    )


def _drop_unknown_source_placeholders(sessions: list[SessionSummary]) -> list[SessionSummary]:
    kept_sessions: list[SessionSummary] = []
    priorities = {id(session): _classifier_priority_tuple(session) for session in sessions}
    for session in sessions:
        if not _is_unknown_source_placeholder(session):
            kept_sessions.append(session)
            continue
        if any(
            priorities[id(other)] > priorities[id(session)]
            for other in sessions
            if other is not session
        ):
            continue
        kept_sessions.append(session)
    return kept_sessions


def _view_priority(session: SessionSummary) -> int:
    if _looks_flood_like(session):
        return {"destination": 3, "flow": 2, "source": 1}.get(session.session_view, 0)
    return {"source": 3, "flow": 2, "destination": 1}.get(session.session_view, 0)


def _looks_flood_like(session: SessionSummary) -> bool:
    repeated_inbound_count = session.external_to_internal_count + session.denied_count
    return (
        session.event_count >= 6
        and len(_unique_src_ips(session)) >= 3
        and session.same_dst_ip_ratio >= 0.8
        and session.same_dst_port_ratio >= 0.8
        and repeated_inbound_count >= max(3, session.event_count // 2)
    )


def _is_unknown_source_placeholder(session: SessionSummary) -> bool:
    return session.session_view == "source" and session.group_key.get("src_ip") == "<unknown>"


def _unique_src_ips(session: SessionSummary) -> list[str]:
    if session.unique_src_ips:
        return session.unique_src_ips
    if session.src_ips:
        return session.src_ips
    return []
