from __future__ import annotations

from collections import Counter, defaultdict
import re

from asa_pipeline.models import ParsedEvent

PAYLOAD_HINT_RE = re.compile(
    r"(union\s+select|select\s+.+\s+from|<script|cmd=|powershell|wget\s+|curl\s+|/bin/sh|\bbase64\b|[?&][a-z0-9_]+=)",
    re.IGNORECASE,
)


def select_evidence_lines(events: list[ParsedEvent], max_lines: int = 20) -> list[str]:
    if not events:
        return []

    selected_indices: list[int] = []
    selected_set: set[int] = set()

    def add_indices(indices: list[int], limit: int | None = None) -> None:
        remaining = max_lines - len(selected_indices)
        if remaining <= 0:
            return
        max_add = remaining if limit is None else min(remaining, limit)
        added = 0
        for index in indices:
            if index in selected_set:
                continue
            selected_set.add(index)
            selected_indices.append(index)
            added += 1
            if added >= max_add:
                break

    add_indices(list(range(min(3, len(events)))))
    add_indices(list(range(max(0, len(events) - 3), len(events))))
    add_indices(_rare_indices(events))
    add_indices(_dominant_behavior_indices(events), limit=10)

    ordered = sorted(selected_set)
    return [events[index].raw_line for index in ordered[:max_lines]]


def _rare_indices(events: list[ParsedEvent]) -> list[int]:
    message_counts = Counter(event.message_id or "" for event in events)
    rare: list[int] = []
    for index, event in enumerate(events):
        if (
            event.url
            or event.domain
            or event.query_type
            or _looks_payload_like(event.raw_line)
            or (event.message_id and message_counts[event.message_id] == 1)
            or event.action in {"connect_start", "connect_end", "built", "teardown"}
        ):
            rare.append(index)
    return rare


def _dominant_behavior_indices(events: list[ParsedEvent]) -> list[int]:
    signature_to_indices: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        signature_to_indices[_behavior_signature(event)].append(index)

    ranked_signatures = sorted(
        signature_to_indices.items(),
        key=lambda item: (-len(item[1]), item[0]),
    )
    dominant: list[int] = []
    for _, indices in ranked_signatures:
        for index in indices:
            dominant.append(index)
            if len(dominant) >= 10:
                return dominant
    return dominant


def _behavior_signature(event: ParsedEvent) -> tuple[str, ...]:
    return (
        event.message_id or "",
        event.action or "",
        event.protocol or "",
        event.service_hint or (str(event.dst_port) if event.dst_port is not None else ""),
        event.direction or "",
    )


def _looks_payload_like(raw_line: str) -> bool:
    return bool(PAYLOAD_HINT_RE.search(raw_line))
