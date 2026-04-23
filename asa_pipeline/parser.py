from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any
import re
from urllib.parse import urlparse

from asa_pipeline.models import ParsedEvent

ASA_TAG_RE = re.compile(r"%(?P<product>ASA)-(?P<severity>\d)-(?P<message_id>\d+):\s*(?P<body>.*)$")
ASA_DUPLICATE_PREFIX_RE = re.compile(
    r"^(?P<message_code>%ASA-(?P<severity>\d)-(?P<message_id>\d+)):\s+"
    r"(?P<timestamp_raw>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}):\s+"
    r"(?P=message_code):\s*(?P<body>.*)$"
)
ASA_TIMESTAMP_RE = re.compile(r"\b(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
QUERY_TYPE_RE = re.compile(
    r"\b(?:query(?:[-_\s]?type)?|qtype|rrtype)\s*[=:]?\s*(A|AAAA|TXT|MX|NS|CNAME|SRV|PTR|SOA)\b",
    re.IGNORECASE,
)
ICMP_DENY_RE = re.compile(
    r"^(?P<message_code>%ASA-(?P<severity>\d)-(?P<message_id>313001)):\s+"
    r"(?P<timestamp_raw>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}):\s+"
    r"%ASA-\d-313001:\s+Denied\s+ICMP\s+type=(?P<icmp_type>\d+),\s+code=(?P<icmp_code>\d+)\s+"
    r"from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+to\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"on\s+interface\s+(?P<src_interface>\S+)\s*$"
)
DENIED_ICMP_RE = re.compile(
    r"""
    \b(?P<action>deny|denied)\s+icmp\b.*?
    \bsrc\s+(?P<src_interface>[^:\s]+):(?P<src_ip>[0-9a-fA-F:.]+)\s+
    dst\s+(?P<dst_interface>[^:\s]+):(?P<dst_ip>[0-9a-fA-F:.]+).*?
    \(type\s+(?P<icmp_type>\d+),\s*code\s+(?P<icmp_code>\d+)\)
    """,
    re.IGNORECASE | re.VERBOSE,
)
DENIED_ICMP_313001_BODY_RE = re.compile(
    r"""
    ^denied\s+icmp\s+type=(?P<icmp_type>\d+),\s+code=(?P<icmp_code>\d+)\s+
    from\s+(?P<src_ip>[0-9a-fA-F:.]+)\s+to\s+(?P<dst_ip>[0-9a-fA-F:.]+)\s+
    on\s+interface\s+(?P<src_interface>\S+)\s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)
DENIED_TCP_NOCONN_RE = re.compile(
    r"""
    \b(?P<action>deny|denied)\s+tcp\b.*?
    (?:\(no\s+connection\)|no[-\s]connection).*?
    (?:from|src)\s+(?:(?P<src_interface>[^:\s]+):)?(?P<src_ip>[0-9a-fA-F:.]+)/(?P<src_port>\d+)\s+
    (?:to|dst)\s+(?:(?P<dst_interface>[^:\s]+):)?(?P<dst_ip>[0-9a-fA-F:.]+)/(?P<dst_port>\d+)
    (?:.*?\bflags\s+(?P<flags>[A-Z,\s]+?)(?=\s+on\s+interface|\s*$))?
    (?:.*?\bon\s+interface\s+(?P<iface_hint>[A-Za-z0-9_-]+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)
BUILT_CONNECTION_RE = re.compile(
    r"""
    \bbuilt\b(?:\s+(?P<connection_scope>inbound|outbound|inside|outside))?\s+
    (?P<protocol>tcp|udp)\s+connection\s+\d+\s+for\s+
    (?P<src_interface>[^:\s]+):(?P<src_ip>[0-9a-fA-F:.]+)/(?P<src_port>\d+)
    (?:\s+\([^)]+\))?\s+to\s+
    (?P<dst_interface>[^:\s]+):(?P<dst_ip>[0-9a-fA-F:.]+)/(?P<dst_port>\d+)
    """,
    re.IGNORECASE | re.VERBOSE,
)
TEARDOWN_CONNECTION_RE = re.compile(
    r"""
    \bteardown\s+(?P<protocol>tcp|udp)\s+connection\s+\d+\s+for\s+
    (?P<src_interface>[^:\s]+):(?P<src_ip>[0-9a-fA-F:.]+)/(?P<src_port>\d+)\s+to\s+
    (?P<dst_interface>[^:\s]+):(?P<dst_ip>[0-9a-fA-F:.]+)/(?P<dst_port>\d+)
    (?:.*?\bduration\s+(?P<duration>\d+:\d{2}:\d{2}))?
    (?:.*?\bbytes\s+(?P<bytes>\d+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)
GENERIC_ENDPOINT_RE = re.compile(
    r"""
    (?:src|from)\s+(?:(?P<src_interface>[^:\s]+):)?(?P<src_ip>[0-9a-fA-F:.]+)(?:/(?P<src_port>\d+))?.*?
    (?:dst|to)\s+(?:(?P<dst_interface>[^:\s]+):)?(?P<dst_ip>[0-9a-fA-F:.]+)(?:/(?P<dst_port>\d+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)
TCP_FLAG_RE = re.compile(r"[A-Z]+")


def parse_line(line: str) -> ParsedEvent:
    raw_line = line.rstrip("\r\n")
    base_event = ParsedEvent(raw_line=raw_line)

    icmp_match = ICMP_DENY_RE.match(raw_line)
    if icmp_match:
        event = ParsedEvent(
            timestamp_raw=icmp_match.group("timestamp_raw"),
            timestamp_iso=parse_asa_timestamp(icmp_match.group("timestamp_raw")),
            message_code=icmp_match.group("message_code"),
            severity=_coerce_int(icmp_match.group("severity")),
            message_id=icmp_match.group("message_id"),
            action="deny",
            protocol="icmp",
            src_interface=icmp_match.group("src_interface"),
            src_ip=icmp_match.group("src_ip"),
            dst_ip=icmp_match.group("dst_ip"),
            icmp_type=_coerce_int(icmp_match.group("icmp_type")),
            icmp_code=_coerce_int(icmp_match.group("icmp_code")),
            raw_line=raw_line,
            parse_status="parsed",
        )
        if event.timestamp_raw and not event.timestamp_iso:
            event.parse_notes.append("unparsed_timestamp")
        return _extract_context(event, raw_line)

    envelope = _extract_asa_envelope(raw_line)
    if not envelope:
        partial = _extract_context(base_event, raw_line)
        if partial.url or partial.domain or partial.query_type:
            partial.parse_status = "partial"
            partial.parse_notes.append("non_asa_line")
            return partial
        partial.parse_notes.append("missing_asa_message_code")
        return partial

    timestamp_raw = envelope["timestamp_raw"]
    timestamp_iso = parse_asa_timestamp(timestamp_raw)
    notes: list[str] = []
    if timestamp_raw and not timestamp_iso:
        notes.append("unparsed_timestamp")

    message_id = envelope["message_id"]
    body = envelope["body"]
    event = ParsedEvent(
        timestamp_raw=timestamp_raw,
        timestamp_iso=timestamp_iso,
        message_code=envelope["message_code"],
        severity=envelope["severity"],
        message_id=message_id,
        raw_line=raw_line,
        parse_status="partial",
        parse_notes=notes,
    )
    event = _extract_context(event, raw_line)

    for parser in (
        _parse_denied_icmp,
        _parse_denied_tcp_no_connection,
        _parse_built_connection,
        _parse_teardown_connection,
    ):
        parsed = parser(body, event)
        if parsed is not None:
            return _finalize_status(parsed, parsed_success=True)

    fallback = _apply_generic_hints(body, event)
    if fallback.parse_status == "partial":
        fallback.parse_notes.append("pattern_not_fully_matched")
    else:
        fallback.parse_notes.append("unsupported_asa_pattern")
    return _finalize_status(fallback, parsed_success=False)


def _parse_denied_icmp(body: str, event: ParsedEvent) -> ParsedEvent | None:
    asa_313001_match = DENIED_ICMP_313001_BODY_RE.search(body)
    if asa_313001_match:
        return replace(
            event,
            action="deny",
            protocol="icmp",
            src_interface=asa_313001_match.group("src_interface"),
            src_ip=asa_313001_match.group("src_ip"),
            dst_ip=asa_313001_match.group("dst_ip"),
            icmp_type=_coerce_int(asa_313001_match.group("icmp_type")),
            icmp_code=_coerce_int(asa_313001_match.group("icmp_code")),
        )

    match = DENIED_ICMP_RE.search(body)
    if not match:
        return None
    return replace(
        event,
        action="deny",
        protocol="icmp",
        src_interface=match.group("src_interface"),
        src_ip=match.group("src_ip"),
        dst_interface=match.group("dst_interface"),
        dst_ip=match.group("dst_ip"),
        icmp_type=_coerce_int(match.group("icmp_type")),
        icmp_code=_coerce_int(match.group("icmp_code")),
    )


def _parse_denied_tcp_no_connection(body: str, event: ParsedEvent) -> ParsedEvent | None:
    match = DENIED_TCP_NOCONN_RE.search(body)
    if not match:
        return None
    src_interface = match.group("src_interface") or match.group("iface_hint")
    return replace(
        event,
        action="deny",
        protocol="tcp",
        src_interface=src_interface,
        src_ip=match.group("src_ip"),
        src_port=_coerce_int(match.group("src_port")),
        dst_interface=match.group("dst_interface"),
        dst_ip=match.group("dst_ip"),
        dst_port=_coerce_int(match.group("dst_port")),
        tcp_flags=_extract_tcp_flags(match.group("flags")),
    )


def _parse_built_connection(body: str, event: ParsedEvent) -> ParsedEvent | None:
    match = BUILT_CONNECTION_RE.search(body)
    if not match:
        return None
    connection_scope = match.group("connection_scope")
    direction = _derive_connection_direction(
        src_interface=match.group("src_interface"),
        dst_interface=match.group("dst_interface"),
        connection_scope=connection_scope,
    )
    return replace(
        event,
        action="built",
        protocol=(match.group("protocol") or "").lower() or None,
        src_interface=match.group("src_interface"),
        src_ip=match.group("src_ip"),
        src_port=_coerce_int(match.group("src_port")),
        dst_interface=match.group("dst_interface"),
        dst_ip=match.group("dst_ip"),
        dst_port=_coerce_int(match.group("dst_port")),
        direction=direction,
    )


def _parse_teardown_connection(body: str, event: ParsedEvent) -> ParsedEvent | None:
    match = TEARDOWN_CONNECTION_RE.search(body)
    if not match:
        return None
    direction = _derive_connection_direction(
        src_interface=match.group("src_interface"),
        dst_interface=match.group("dst_interface"),
    )
    return replace(
        event,
        action="teardown",
        protocol=(match.group("protocol") or "").lower() or None,
        src_interface=match.group("src_interface"),
        src_ip=match.group("src_ip"),
        src_port=_coerce_int(match.group("src_port")),
        dst_interface=match.group("dst_interface"),
        dst_ip=match.group("dst_ip"),
        dst_port=_coerce_int(match.group("dst_port")),
        direction=direction,
        duration_seconds=_parse_duration_seconds(match.group("duration")),
        bytes_count=_coerce_int(match.group("bytes")),
    )


def _apply_generic_hints(body: str, event: ParsedEvent) -> ParsedEvent:
    action = event.action
    protocol = event.protocol
    lowered = body.lower()
    if action is None:
        if "deny" in lowered:
            action = "deny"
        elif "built" in lowered:
            action = "built"
        elif "teardown" in lowered:
            action = "teardown"
    if protocol is None:
        if "icmp" in lowered:
            protocol = "icmp"
        elif "tcp" in lowered:
            protocol = "tcp"

    updated = replace(event, action=action, protocol=protocol)
    endpoint_match = GENERIC_ENDPOINT_RE.search(body)
    if endpoint_match:
        updated = replace(
            updated,
            src_interface=updated.src_interface or endpoint_match.group("src_interface"),
            src_ip=updated.src_ip or endpoint_match.group("src_ip"),
            src_port=updated.src_port or _coerce_int(endpoint_match.group("src_port")),
            dst_interface=updated.dst_interface or endpoint_match.group("dst_interface"),
            dst_ip=updated.dst_ip or endpoint_match.group("dst_ip"),
            dst_port=updated.dst_port or _coerce_int(endpoint_match.group("dst_port")),
        )

    extracted_any = any(
        value is not None and value != []
        for value in (
            updated.action,
            updated.protocol,
            updated.src_ip,
            updated.dst_ip,
            updated.url,
            updated.domain,
            updated.query_type,
        )
    )
    updated.parse_status = "partial" if extracted_any else "unparsed"
    return updated


def _extract_context(event: ParsedEvent, raw_line: str) -> ParsedEvent:
    url = _extract_url(raw_line)
    domain = _extract_domain(raw_line, url)
    query_type = _extract_query_type(raw_line)
    return replace(
        event,
        url=event.url or url,
        domain=(event.domain or domain.lower()) if domain else event.domain,
        query_type=(event.query_type or query_type.upper()) if query_type else event.query_type,
    )


def _finalize_status(event: ParsedEvent, parsed_success: bool) -> ParsedEvent:
    complete = all((event.action, event.protocol, event.raw_line))
    if parsed_success and complete:
        event.parse_status = "parsed"
        return event
    if parsed_success:
        event.parse_status = "partial"
        return event
    return event


def _extract_timestamp(prefix: str) -> str | None:
    match = ASA_TIMESTAMP_RE.search(prefix)
    return match.group("ts") if match else None


def parse_asa_timestamp(ts_raw: str | None) -> str | None:
    if not ts_raw:
        return None
    try:
        return datetime.strptime(ts_raw, "%b %d %Y %H:%M:%S").isoformat()
    except ValueError:
        return None


def _extract_asa_envelope(raw_line: str) -> dict[str, Any] | None:
    duplicate_match = ASA_DUPLICATE_PREFIX_RE.match(raw_line)
    if duplicate_match:
        return {
            "message_code": duplicate_match.group("message_code"),
            "severity": _coerce_int(duplicate_match.group("severity")),
            "message_id": duplicate_match.group("message_id"),
            "timestamp_raw": duplicate_match.group("timestamp_raw"),
            "body": duplicate_match.group("body").strip(),
        }

    tag_match = ASA_TAG_RE.search(raw_line)
    if not tag_match:
        return None

    prefix = raw_line[: tag_match.start()].strip(" :")
    return {
        "message_code": f"%ASA-{tag_match.group('severity')}-{tag_match.group('message_id')}",
        "severity": _coerce_int(tag_match.group("severity")),
        "message_id": tag_match.group("message_id"),
        "timestamp_raw": _extract_timestamp(prefix),
        "body": tag_match.group("body").strip(),
    }


def _parse_timestamp_iso(timestamp_raw: str | None) -> str | None:
    if not timestamp_raw:
        return None

    return parse_asa_timestamp(timestamp_raw)


def _extract_url(raw_line: str) -> str | None:
    match = URL_RE.search(raw_line)
    return match.group(0) if match else None


def _extract_domain(raw_line: str, url: str | None = None) -> str | None:
    if url:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname
    match = DOMAIN_RE.search(raw_line)
    return match.group(0) if match else None


def _extract_query_type(raw_line: str) -> str | None:
    match = QUERY_TYPE_RE.search(raw_line)
    return match.group(1) if match else None


def _extract_tcp_flags(flags: str | None) -> list[str]:
    if not flags:
        return []
    seen: set[str] = set()
    ordered: list[str] = []
    for token in TCP_FLAG_RE.findall(flags.upper()):
        if token not in seen:
            seen.add(token)
            ordered.append(token)
    return ordered


def _parse_duration_seconds(duration: str | None) -> float | None:
    if not duration:
        return None
    parts = duration.split(":")
    if len(parts) != 3:
        return None
    hours, minutes, seconds = (int(part) for part in parts)
    return float(hours * 3600 + minutes * 60 + seconds)


def _derive_connection_direction(
    src_interface: str | None,
    dst_interface: str | None,
    connection_scope: str | None = None,
) -> str | None:
    src_side = _classify_interface(src_interface)
    dst_side = _classify_interface(dst_interface)
    if src_side == "internal" and dst_side == "internal":
        return "internal_to_internal"
    if src_side == "external" and dst_side == "internal":
        return "external_to_internal"
    if src_side == "internal" and dst_side == "external":
        return "inside_to_outside"
    if connection_scope:
        lowered = connection_scope.lower()
        if lowered in {"inbound", "outside"}:
            return "external_to_internal"
        if lowered in {"outbound", "inside"}:
            return "inside_to_outside"
    if src_side or dst_side:
        return "unknown"
    return None


def _classify_interface(interface_name: str | None) -> str | None:
    if not interface_name:
        return None
    lowered = interface_name.lower()
    if "inside" in lowered:
        return "internal"
    if "outside" in lowered:
        return "external"
    return None


def _coerce_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
