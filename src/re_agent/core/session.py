"""JSON-backed persistent session state for tracking reversal progress."""

from __future__ import annotations

import importlib
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from re_agent.core.models import ReversalResult
from re_agent.utils.address import normalize_address

logger = logging.getLogger(__name__)
_SCHEMA_VERSION = 1


class Session:
    """Tracks reversal progress in a JSON file."""

    def __init__(self, path: str | Path = "re-agent-progress.json") -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = self._empty_data()
        self._thread_lock = threading.RLock()
        if self.path.exists():
            self.load()

    def load(self) -> None:
        """Load and validate session state, quarantining corrupt files."""
        with self._thread_lock, self._file_lock():
            self._data = self._read_data(quarantine=True)

    @staticmethod
    def _empty_data() -> dict[str, Any]:
        return {"schema_version": _SCHEMA_VERSION, "functions": {}, "runs": []}

    def _read_data(self, *, quarantine: bool) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("session root must be an object")
            version = raw.get("schema_version", _SCHEMA_VERSION)
            if version != _SCHEMA_VERSION:
                raise ValueError(f"unsupported session schema_version: {version!r}")
            functions = raw.get("functions", {})
            runs = raw.get("runs", [])
            if not isinstance(functions, dict) or not isinstance(runs, list):
                raise ValueError("session functions/runs have invalid types")
            valid_functions = {
                str(address): dict(entry) for address, entry in functions.items() if isinstance(entry, dict)
            }
            valid_runs = [dict(entry) for entry in runs if isinstance(entry, dict)]
            return {
                "schema_version": _SCHEMA_VERSION,
                "functions": valid_functions,
                "runs": valid_runs,
            }
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning("Invalid session state in %s: %s", self.path, exc)
            if quarantine and self.path.exists():
                quarantine_path = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time() * 1000)}")
                try:
                    os.replace(self.path, quarantine_path)
                    logger.warning("Corrupt session quarantined as %s", quarantine_path)
                except OSError:
                    logger.warning("Could not quarantine corrupt session", exc_info=True)
            return self._empty_data()

    def save(self) -> None:
        """Atomically replace the session file on POSIX and Windows."""
        with self._thread_lock, self._file_lock():
            self._save_unlocked()

    def _save_unlocked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                json.dump(self._data, temporary, indent=2)
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    @contextmanager
    def _file_lock(self, timeout_s: float = 10.0) -> Iterator[None]:
        """Hold a small cross-process lock file while merging and replacing state."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        with lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            deadline = time.monotonic() + timeout_s
            while True:
                try:
                    if os.name == "nt":
                        lock_api = importlib.import_module("msvcrt")
                        lock_api.locking(handle.fileno(), lock_api.LK_NBLCK, 1)
                    else:
                        lock_api = importlib.import_module("fcntl")
                        lock_api.flock(handle.fileno(), lock_api.LOCK_EX | lock_api.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Timed out locking session file: {self.path}") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    lock_api = importlib.import_module("msvcrt")
                    lock_api.locking(handle.fileno(), lock_api.LK_UNLCK, 1)
                else:
                    lock_api = importlib.import_module("fcntl")
                    lock_api.flock(handle.fileno(), lock_api.LOCK_UN)

    def record_result(self, result: ReversalResult) -> None:
        addr = normalize_address(result.target.address)
        entry = {
            "address": result.target.address,
            "class_name": result.target.class_name,
            "function_name": result.target.function_name,
            "success": result.success,
            "rounds_used": result.rounds_used,
            "verdict": result.checker_verdict.verdict.value if result.checker_verdict else None,
            "validation_verdict": (result.validation_verdict.verdict.value if result.validation_verdict else None),
            "parity_status": result.parity_status.value if result.parity_status else None,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with self._thread_lock, self._file_lock():
            # Merge against the latest on-disk state to avoid lost updates from
            # concurrent class/function workers.
            self._data = self._read_data(quarantine=False) if self.path.exists() else self._empty_data()
            self._data["functions"][addr] = entry
            self._data["runs"].append(entry)
            self._save_unlocked()

    def is_completed(self, address: str) -> bool:
        addr = normalize_address(address)
        func = self._data["functions"].get(addr)
        return func is not None and func.get("success", False)

    def is_attempted(self, address: str) -> bool:
        """Return True if this address has been attempted (pass or fail)."""
        addr = normalize_address(address)
        return addr in self._data["functions"]

    def attempt_count(self, address: str) -> int:
        """Return the number of recorded runs for an address."""
        addr = normalize_address(address)
        return sum(
            1 for entry in self._data.get("runs", []) if normalize_address(str(entry.get("address", ""))) == addr
        )

    def get_class_summary(self, class_name: str) -> dict[str, int]:
        total = 0
        passed = 0
        failed = 0
        for func in self._data["functions"].values():
            if func.get("class_name") == class_name:
                total += 1
                if func.get("success"):
                    passed += 1
                else:
                    failed += 1
        return {"total": total, "passed": passed, "failed": failed}

    def get_summary(self) -> dict[str, Any]:
        funcs = self._data["functions"]
        total = len(funcs)
        passed = sum(1 for f in funcs.values() if f.get("success"))
        failed = total - passed
        classes: set[str] = set()
        for f in funcs.values():
            cn = f.get("class_name", "")
            if cn:
                classes.add(cn)
        return {
            "total_functions": total,
            "passed": passed,
            "failed": failed,
            "classes_touched": len(classes),
        }

    def get_all_functions(self) -> list[dict[str, Any]]:
        return list(self._data["functions"].values())
