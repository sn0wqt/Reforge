"""Atomic writes and process-safe advisory file locking."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def atomic_json(path: Path, data: Any) -> None:
    import time

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(5):
            try:
                os.replace(name, path)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.02 * (2**attempt))
    finally:
        Path(name).unlink(missing_ok=True)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    import importlib

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(path.suffix + ".lock").open("a+b") as handle:
        if os.name == "nt":
            lock_api = importlib.import_module("msvcrt")
            handle.seek(0)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            lock_api.locking(handle.fileno(), lock_api.LK_LOCK, 1)
        else:
            lock_api = importlib.import_module("fcntl")
            lock_api.flock(handle.fileno(), lock_api.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                lock_api = importlib.import_module("msvcrt")
                handle.seek(0)
                lock_api.locking(handle.fileno(), lock_api.LK_UNLCK, 1)
            else:
                lock_api = importlib.import_module("fcntl")
                lock_api.flock(handle.fileno(), lock_api.LOCK_UN)
