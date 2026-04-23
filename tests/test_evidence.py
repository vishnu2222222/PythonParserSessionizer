from asa_pipeline.evidence import select_evidence_lines
from asa_pipeline.models import ParsedEvent


def test_evidence_selection_is_deterministic_and_keeps_priority_lines() -> None:
    events = []
    for index in range(25):
        raw_line = f"dominant line {index:02d}"
        event = ParsedEvent(
            message_id="106015",
            action="deny",
            protocol="tcp",
            dst_port=22,
            service_hint="ssh",
            raw_line=raw_line,
            parse_status="parsed",
        )
        events.append(event)

    events[3].url = "http://example.com/login"
    events[3].raw_line = "url line"
    events[5].domain = "rare-domain.example"
    events[5].raw_line = "domain line"
    events[7].action = "connect_start"
    events[7].raw_line = "built line"
    events[12].message_id = "302014"
    events[12].action = "connect_end"
    events[12].raw_line = "teardown line"
    events[20].raw_line = "payload line with UNION SELECT password FROM users"

    first = select_evidence_lines(events)
    second = select_evidence_lines(events)

    assert first == second
    assert len(first) <= 20
    assert "dominant line 00" in first
    assert "dominant line 01" in first
    assert "dominant line 02" in first
    assert "dominant line 22" in first
    assert "dominant line 23" in first
    assert "dominant line 24" in first
    assert "url line" in first
    assert "domain line" in first
    assert "built line" in first
    assert "teardown line" in first
    assert "payload line with UNION SELECT password FROM users" in first
