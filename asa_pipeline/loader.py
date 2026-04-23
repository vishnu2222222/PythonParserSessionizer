from __future__ import annotations

from pathlib import Path
from typing import Iterator


def iter_input_files(input_path: str | Path, exclude_roots: set[Path] | None = None) -> Iterator[Path]:
    path = Path(input_path)
    exclude_roots = {root.resolve() for root in (exclude_roots or set())}

    if path.is_file():
        resolved = path.resolve()
        if not _is_excluded(resolved, exclude_roots):
            yield resolved
        return

    if not path.exists():
        return

    base = path.resolve()
    for file_path in sorted(
        (candidate.resolve() for candidate in base.rglob("*") if candidate.is_file()),
        key=lambda item: str(item).lower(),
    ):
        if _is_excluded(file_path, exclude_roots):
            continue
        yield file_path


def iter_log_lines(
    input_path: str | Path,
    exclude_roots: set[Path] | None = None,
) -> Iterator[tuple[Path, int, str]]:
    for file_path in iter_input_files(input_path, exclude_roots=exclude_roots):
        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                yield file_path, line_number, line.rstrip("\r\n")


def _is_excluded(path: Path, exclude_roots: set[Path]) -> bool:
    return any(root == path or root in path.parents for root in exclude_roots)
