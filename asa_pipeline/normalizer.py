from __future__ import annotations

from dataclasses import replace

from asa_pipeline.models import ParsedEvent
from asa_pipeline.ports import infer_service_hint

ACTION_MAP = {
    "allow": "allow",
    "allowed": "allow",
    "built": "connect_start",
    "connect_start": "connect_start",
    "deny": "deny",
    "denied": "deny",
    "teardown": "connect_end",
    "connect_end": "connect_end",
}


def normalize_event(event: ParsedEvent) -> ParsedEvent:
    notes = list(event.parse_notes)
    action = _normalize_action(event.action)
    protocol = event.protocol.lower() if event.protocol else None
    src_port = _normalize_port(event.src_port, "src_port", notes)
    dst_port = _normalize_port(event.dst_port, "dst_port", notes)
    service_hint = event.service_hint or infer_service_hint(dst_port)
    direction = event.direction or infer_direction(event.src_interface, event.dst_interface)
    return replace(
        event,
        action=action,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        service_hint=service_hint,
        direction=direction,
        parse_notes=notes,
    )


def infer_direction(src_interface: str | None, dst_interface: str | None) -> str | None:
    src_side = _classify_interface(src_interface)
    dst_side = _classify_interface(dst_interface)
    if src_side == "internal" and dst_side == "internal":
        return "internal_to_internal"
    if src_side == "external" and dst_side == "internal":
        return "external_to_internal"
    if src_side == "internal" and dst_side == "external":
        return "inside_to_outside"
    if src_side or dst_side:
        return "unknown"
    return None


def _normalize_action(action: str | None) -> str | None:
    if not action:
        return None
    lowered = action.lower()
    return ACTION_MAP.get(lowered, lowered)


def _normalize_port(value: int | str | None, field_name: str, notes: list[str]) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        notes.append(f"invalid_{field_name}")
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
