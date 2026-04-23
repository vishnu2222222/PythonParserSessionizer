from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from asa_pipeline.models import ParsedEvent

DESTINATION_POST_MERGE_GAP_SECONDS = 600


@dataclass(slots=True)
class SessionWindow:
    session_id: str
    session_view: str
    group_key: dict[str, str | int | None]
    events: list[ParsedEvent] = field(default_factory=list)


def build_all_session_views(
    events: Iterable[ParsedEvent],
    destination_post_merge_gap_seconds: int = DESTINATION_POST_MERGE_GAP_SECONDS,
) -> list[SessionWindow]:
    ordered_events = list(events)
    return [
        *build_flow_sessions(ordered_events),
        *build_source_sessions(ordered_events),
        *build_destination_sessions(
            ordered_events,
            post_merge_gap_seconds=destination_post_merge_gap_seconds,
        ),
    ]


def build_flow_sessions(events: Iterable[ParsedEvent]) -> list[SessionWindow]:
    return _build_sessions(
        list(events),
        session_view="flow",
        window_seconds=300,
        merge_gap_seconds=90,
    )


def build_source_sessions(events: Iterable[ParsedEvent]) -> list[SessionWindow]:
    return _build_sessions(
        list(events),
        session_view="source",
        window_seconds=600,
        merge_gap_seconds=120,
    )


def build_destination_sessions(
    events: Iterable[ParsedEvent],
    post_merge_gap_seconds: int = DESTINATION_POST_MERGE_GAP_SECONDS,
) -> list[SessionWindow]:
    sessions = _build_sessions(
        list(events),
        session_view="destination",
        window_seconds=300,
        merge_gap_seconds=90,
    )
    return _merge_destination_sessions(sessions, merge_gap_seconds=post_merge_gap_seconds)


def build_destination_service_sessions(
    events: Iterable[ParsedEvent],
    post_merge_gap_seconds: int = DESTINATION_POST_MERGE_GAP_SECONDS,
) -> list[SessionWindow]:
    return build_destination_sessions(events, post_merge_gap_seconds=post_merge_gap_seconds)


def _build_sessions(
    events: list[ParsedEvent],
    session_view: str,
    window_seconds: int,
    merge_gap_seconds: int,
) -> list[SessionWindow]:
    grouped: dict[tuple[str, ...], list[ParsedEvent]] = defaultdict(list)
    for event in events:
        grouped[_session_key(event, session_view)].append(event)

    draft_sessions: list[tuple[dict[str, str | int | None], list[ParsedEvent]]] = []
    for key in sorted(grouped, key=_sortable_key):
        current_events: list[ParsedEvent] = []
        current_start_ts: datetime | None = None
        current_last_ts: datetime | None = None

        for event in grouped[key]:
            event_ts = _event_datetime(event)
            if current_events and _should_split(
                current_start_ts=current_start_ts,
                current_last_ts=current_last_ts,
                event_ts=event_ts,
                window_seconds=window_seconds,
                merge_gap_seconds=merge_gap_seconds,
            ):
                draft_sessions.append((_group_key_dict(key, session_view), current_events))
                current_events = []
                current_start_ts = None
                current_last_ts = None

            current_events.append(event)
            if event_ts is not None:
                if current_start_ts is None:
                    current_start_ts = event_ts
                current_last_ts = event_ts

        if current_events:
            draft_sessions.append((_group_key_dict(key, session_view), current_events))

    ordered = sorted(
        draft_sessions,
        key=lambda item: (
            _session_start_sort(item[1]),
            _sortable_key(tuple(str(value) for value in item[0].values())),
            item[1][0].raw_line if item[1] else "",
        ),
    )

    return _finalize_session_windows(
        session_view,
        [
            SessionWindow(
                session_id="",
                session_view=session_view,
                group_key=group_key,
                events=list(session_events),
            )
            for group_key, session_events in ordered
        ],
    )


def _merge_destination_sessions(
    sessions: list[SessionWindow],
    merge_gap_seconds: int,
) -> list[SessionWindow]:
    if len(sessions) < 2 or merge_gap_seconds < 0:
        return sessions

    grouped: dict[tuple[str, int], list[SessionWindow]] = defaultdict(list)
    passthrough: list[SessionWindow] = []
    for session in sessions:
        merge_key = _destination_merge_key(session)
        if merge_key is None:
            passthrough.append(session)
            continue
        grouped[merge_key].append(session)

    merged: list[SessionWindow] = []
    for merge_key in sorted(grouped, key=lambda item: _sortable_key((item[0], str(item[1])))):
        ordered_group = sorted(grouped[merge_key], key=_session_window_sort)
        current = ordered_group[0]
        current_events = list(current.events)
        current_end = _session_end_datetime(current)
        for next_session in ordered_group[1:]:
            next_start = _session_start_datetime(next_session)
            if _should_merge_destination_session(
                current_end=current_end,
                next_start=next_start,
                merge_gap_seconds=merge_gap_seconds,
            ):
                current_events.extend(next_session.events)
                next_end = _session_end_datetime(next_session)
                if next_end is not None and (current_end is None or next_end > current_end):
                    current_end = next_end
                continue

            merged.append(
                SessionWindow(
                    session_id="",
                    session_view="destination",
                    group_key=dict(current.group_key),
                    events=_sort_session_events(current_events),
                )
            )
            current = next_session
            current_events = list(next_session.events)
            current_end = _session_end_datetime(next_session)

        merged.append(
            SessionWindow(
                session_id="",
                session_view="destination",
                group_key=dict(current.group_key),
                events=_sort_session_events(current_events),
            )
        )

    return _finalize_session_windows("destination", [*passthrough, *merged])


def _session_key(event: ParsedEvent, session_view: str) -> tuple[str, ...]:
    unknown = "<unknown>"
    if session_view == "flow":
        return (
            event.src_ip or unknown,
            event.dst_ip or unknown,
            event.protocol or unknown,
        )
    if session_view == "source":
        return (event.src_ip or unknown,)
    if session_view == "destination":
        return (
            event.dst_ip or unknown,
            str(event.dst_port) if event.dst_port is not None else unknown,
        )
    raise ValueError(f"Unsupported session view: {session_view}")


def _group_key_dict(key: tuple[str, ...], session_view: str) -> dict[str, str | int | None]:
    if session_view == "flow":
        return {"src_ip": key[0], "dst_ip": key[1], "protocol": key[2]}
    if session_view == "source":
        return {"src_ip": key[0]}
    if session_view == "destination":
        return {"dst_ip": key[0], "dst_port": _coerce_group_port(key[1])}
    raise ValueError(f"Unsupported session view: {session_view}")


def _should_split(
    current_start_ts: datetime | None,
    current_last_ts: datetime | None,
    event_ts: datetime | None,
    window_seconds: int,
    merge_gap_seconds: int,
) -> bool:
    if event_ts is None:
        return False
    if current_last_ts is not None and (event_ts - current_last_ts).total_seconds() > merge_gap_seconds:
        return True
    if current_start_ts is not None and (event_ts - current_start_ts).total_seconds() > window_seconds:
        return True
    return False


def _event_datetime(event: ParsedEvent) -> datetime | None:
    if not event.timestamp_iso:
        return None
    try:
        return datetime.fromisoformat(event.timestamp_iso.replace("Z", "+00:00"))
    except ValueError:
        return None


def _session_start_sort(events: list[ParsedEvent]) -> tuple[int, str]:
    timestamps = [event.timestamp_iso for event in events if event.timestamp_iso]
    if timestamps:
        return (0, min(timestamps))
    return (1, events[0].raw_line if events else "")


def _finalize_session_windows(
    session_view: str,
    sessions: list[SessionWindow],
) -> list[SessionWindow]:
    ordered = sorted(sessions, key=_session_window_sort)
    finalized: list[SessionWindow] = []
    for index, session in enumerate(ordered, start=1):
        finalized.append(
            SessionWindow(
                session_id=f"{session_view}-{index:06d}",
                session_view=session_view,
                group_key=dict(session.group_key),
                events=_sort_session_events(session.events),
            )
        )
    return finalized


def _session_window_sort(session: SessionWindow) -> tuple[object, ...]:
    return (
        _session_start_sort(session.events),
        _sortable_key(tuple(str(value) for value in session.group_key.values())),
        session.events[0].raw_line if session.events else "",
    )


def _destination_merge_key(session: SessionWindow) -> tuple[str, int] | None:
    dst_ip = session.group_key.get("dst_ip")
    dst_port = session.group_key.get("dst_port")
    if dst_ip in {None, "<unknown>"}:
        return None
    if not isinstance(dst_port, int):
        return None
    return (str(dst_ip), dst_port)


def _should_merge_destination_session(
    current_end: datetime | None,
    next_start: datetime | None,
    merge_gap_seconds: int,
) -> bool:
    if current_end is None or next_start is None:
        return False
    return (next_start - current_end).total_seconds() <= merge_gap_seconds


def _session_start_datetime(session: SessionWindow) -> datetime | None:
    timestamps = [_event_datetime(event) for event in session.events]
    valid_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    return min(valid_timestamps, default=None)


def _session_end_datetime(session: SessionWindow) -> datetime | None:
    timestamps = [_event_datetime(event) for event in session.events]
    valid_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    return max(valid_timestamps, default=None)


def _sort_session_events(events: list[ParsedEvent]) -> list[ParsedEvent]:
    return sorted(events, key=_session_event_sort)


def _session_event_sort(event: ParsedEvent) -> tuple[object, ...]:
    if event.timestamp_iso:
        return (0, event.timestamp_iso, event.raw_line)
    return (1, event.raw_line)


def _sortable_key(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(value).lower() for value in values)


def _coerce_group_port(value: str) -> str | int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value
