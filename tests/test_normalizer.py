from asa_pipeline.models import ParsedEvent
from asa_pipeline.normalizer import infer_direction, normalize_event


def test_normalizer_maps_actions_ports_service_and_direction() -> None:
    event = ParsedEvent(
        action="Built",
        protocol="TCP",
        src_interface="inside",
        dst_interface="outside",
        src_port="51514",  # type: ignore[arg-type]
        dst_port="443",  # type: ignore[arg-type]
        raw_line="sample",
        parse_status="parsed",
    )

    normalized = normalize_event(event)

    assert normalized.action == "connect_start"
    assert normalized.protocol == "tcp"
    assert normalized.src_port == 51514
    assert normalized.dst_port == 443
    assert normalized.service_hint == "https"
    assert normalized.direction == "inside_to_outside"


def test_normalizer_handles_invalid_ports_without_crashing() -> None:
    event = ParsedEvent(
        action="Denied",
        protocol="TCP",
        dst_port="bad-port",  # type: ignore[arg-type]
        raw_line="sample",
    )

    normalized = normalize_event(event)

    assert normalized.action == "deny"
    assert normalized.protocol == "tcp"
    assert normalized.dst_port is None
    assert "invalid_dst_port" in normalized.parse_notes
    assert infer_direction("outside", "inside") == "external_to_internal"
