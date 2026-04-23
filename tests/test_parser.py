from asa_pipeline.parser import parse_line


def test_parse_denied_icmp_line() -> None:
    line = (
        'Apr 11 2026 10:00:00: %ASA-4-106023: Deny icmp src outside:203.0.113.10 '
        'dst inside:10.0.0.5 (type 8, code 0) by access-group "outside_access_in"'
    )
    event = parse_line(line)

    assert event.parse_status == "parsed"
    assert event.timestamp_iso == "2026-04-11T10:00:00"
    assert event.message_code == "%ASA-4-106023"
    assert event.action == "deny"
    assert event.protocol == "icmp"
    assert event.src_interface == "outside"
    assert event.src_ip == "203.0.113.10"
    assert event.dst_interface == "inside"
    assert event.dst_ip == "10.0.0.5"
    assert event.icmp_type == 8
    assert event.icmp_code == 0
    assert event.raw_line == line


def test_parse_asa_313001_icmp_deny_line_fully() -> None:
    line = (
        "%ASA-6-313001: Mar 03 2025 07:30:25: %ASA-6-313001: "
        "Denied ICMP type=8, code=0 from 198.51.100.23 to 172.16.2.77 on interface outside"
    )

    event = parse_line(line)

    assert event.parse_status == "parsed"
    assert "pattern_not_fully_matched" not in event.parse_notes
    assert event.severity == 6
    assert event.message_code == "%ASA-6-313001"
    assert event.message_id == "313001"
    assert event.timestamp_raw == "Mar 03 2025 07:30:25"
    assert event.timestamp_iso == "2025-03-03T07:30:25"
    assert event.protocol == "icmp"
    assert event.action == "deny"
    assert event.icmp_type == 8
    assert event.icmp_code == 0
    assert event.src_ip == "198.51.100.23"
    assert event.dst_ip == "172.16.2.77"
    assert event.src_interface == "outside"


def test_parse_denied_tcp_and_teardown_lines() -> None:
    deny_line = (
        "Apr 11 2026 10:00:30: %ASA-4-106015: Deny TCP (no connection) from "
        "203.0.113.10/40000 to 10.0.0.5/22 flags SYN on interface outside"
    )
    teardown_line = (
        "Apr 11 2026 10:01:04: %ASA-6-302014: Teardown TCP connection 12345 for "
        "inside:10.0.0.5/51514 to outside:198.51.100.20/443 duration 0:00:04 bytes 532"
    )

    denied = parse_line(deny_line)
    teardown = parse_line(teardown_line)

    assert denied.parse_status == "parsed"
    assert denied.action == "deny"
    assert denied.protocol == "tcp"
    assert denied.src_port == 40000
    assert denied.dst_port == 22
    assert denied.tcp_flags == ["SYN"]

    assert teardown.parse_status == "parsed"
    assert teardown.action == "teardown"
    assert teardown.bytes_count == 532
    assert teardown.duration_seconds == 4.0


def test_parse_asa_connection_lines_for_dos_flood_patterns() -> None:
    built_outside_tcp_line = (
        "%ASA-6-302013: Mar 03 2025 07:46:32: %ASA-6-302013: "
        "Built outside TCP connection 531422667 for outside:104.21.45.202/2869 "
        "(104.21.45.202/2869) to inside:192.168.2.99/443 (192.168.2.99/443)"
    )
    built_inbound_udp_line = (
        "%ASA-6-302015: Mar 03 2025 07:49:19: %ASA-6-302015: "
        "Built inbound UDP connection 699279366 for outside:103.224.182.244/52840 "
        "(103.224.182.244/52840) to inside:192.168.2.99/443 (192.168.2.99/443)"
    )
    teardown_udp_line = (
        "%ASA-6-302016: Mar 03 2025 07:49:53: %ASA-6-302016: "
        "Teardown UDP connection 844229207 for outside:103.224.182.244/52840 "
        "to inside:192.168.2.99/443 duration 0:00:01 bytes 222"
    )

    built_outside_tcp = parse_line(built_outside_tcp_line)
    built_inbound_udp = parse_line(built_inbound_udp_line)
    teardown_udp = parse_line(teardown_udp_line)

    assert built_outside_tcp.parse_status == "parsed"
    assert built_outside_tcp.timestamp_iso == "2025-03-03T07:46:32"
    assert built_outside_tcp.message_id == "302013"
    assert built_outside_tcp.action == "built"
    assert built_outside_tcp.protocol == "tcp"
    assert built_outside_tcp.src_ip == "104.21.45.202"
    assert built_outside_tcp.dst_ip == "192.168.2.99"
    assert built_outside_tcp.src_port == 2869
    assert built_outside_tcp.dst_port == 443
    assert built_outside_tcp.direction == "external_to_internal"

    assert built_inbound_udp.parse_status == "parsed"
    assert built_inbound_udp.timestamp_iso == "2025-03-03T07:49:19"
    assert built_inbound_udp.message_id == "302015"
    assert built_inbound_udp.action == "built"
    assert built_inbound_udp.protocol == "udp"
    assert built_inbound_udp.src_ip == "103.224.182.244"
    assert built_inbound_udp.dst_ip == "192.168.2.99"
    assert built_inbound_udp.src_port == 52840
    assert built_inbound_udp.dst_port == 443
    assert built_inbound_udp.direction == "external_to_internal"

    assert teardown_udp.parse_status == "parsed"
    assert teardown_udp.timestamp_iso == "2025-03-03T07:49:53"
    assert teardown_udp.message_id == "302016"
    assert teardown_udp.action == "teardown"
    assert teardown_udp.protocol == "udp"
    assert teardown_udp.src_ip == "103.224.182.244"
    assert teardown_udp.dst_ip == "192.168.2.99"
    assert teardown_udp.src_port == 52840
    assert teardown_udp.dst_port == 443
    assert teardown_udp.direction == "external_to_internal"
    assert teardown_udp.duration_seconds == 1.0
    assert teardown_udp.bytes_count == 222


def test_extracts_timestamp_from_duplicate_asa_prefix_lines() -> None:
    tcp_line = (
        "%ASA-6-106015: Mar 03 2025 07:31:06: %ASA-6-106015: "
        "Deny TCP (no connection) from 198.51.100.23/49687 to 172.16.2.77/539 "
        "flags SYN on interface outside"
    )
    icmp_line = (
        "%ASA-6-313001: Mar 03 2025 07:30:25: %ASA-6-313001: "
        "Denied ICMP type=8, code=0 from 198.51.100.23 to 172.16.2.77 on interface outside"
    )

    tcp_event = parse_line(tcp_line)
    icmp_event = parse_line(icmp_line)

    assert tcp_event.timestamp_raw == "Mar 03 2025 07:31:06"
    assert tcp_event.timestamp_iso == "2025-03-03T07:31:06"
    assert icmp_event.timestamp_raw == "Mar 03 2025 07:30:25"
    assert icmp_event.timestamp_iso == "2025-03-03T07:30:25"


def test_parser_never_crashes_on_malformed_line() -> None:
    line = "this is not an asa line and should stay intact"
    event = parse_line(line)

    assert event.parse_status == "unparsed"
    assert event.raw_line == line
    assert "missing_asa_message_code" in event.parse_notes
