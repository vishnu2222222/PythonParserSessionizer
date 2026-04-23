"""Cisco ASA log parsing and session feature extraction pipeline."""

from asa_pipeline.classifier_input import (
    ALLOWED_ATTACK_VECTORS,
    ATTACK_VECTOR_IMPORTANT_DISTINCTIONS,
    ATTACK_VECTOR_LABEL_HINTS,
    build_attack_vector_schema,
    build_classifier_input_record,
    build_classifier_input_records,
    build_classifier_input_text,
)
from asa_pipeline.features import build_session_summaries, summarize_session
from asa_pipeline.loader import iter_input_files, iter_log_lines
from asa_pipeline.models import ParsedEvent, SessionSummary
from asa_pipeline.normalizer import normalize_event
from asa_pipeline.parser import parse_line
from asa_pipeline.sessionizer import (
    SessionWindow,
    build_all_session_views,
    build_destination_sessions,
    build_destination_service_sessions,
    build_flow_sessions,
    build_source_sessions,
)

__all__ = [
    "ParsedEvent",
    "SessionSummary",
    "ALLOWED_ATTACK_VECTORS",
    "ATTACK_VECTOR_IMPORTANT_DISTINCTIONS",
    "ATTACK_VECTOR_LABEL_HINTS",
    "SessionWindow",
    "build_all_session_views",
    "build_attack_vector_schema",
    "build_classifier_input_record",
    "build_classifier_input_records",
    "build_classifier_input_text",
    "build_destination_sessions",
    "build_destination_service_sessions",
    "build_flow_sessions",
    "build_session_summaries",
    "build_source_sessions",
    "iter_input_files",
    "iter_log_lines",
    "normalize_event",
    "parse_line",
    "summarize_session",
]
