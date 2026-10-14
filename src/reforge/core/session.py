"""JSON-backed persistent session state for tracking reversal progress."""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from reforge.core.models import ReversalResult
from reforge.utils.address import normalize_address

logger = logging.getLogger(__name__)
_SCHEMA_VERSION = 1


class Session:
    """Tracks reversal progress in a JSON file."""

    def __init__(self, path: str | Path = "reforge-progress.json") -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = self._empty_data()
        self._thread_lock = threading.RLock()
        if self.path.exists():
            self.load()

    def load(self) -> None:
        """Load and validate session state."""
        with self._thread_lock, self._file_lock():
            self._data = self._read_data()

    @staticmethod
    def _empty_data() -> dict[str, Any]:
        return {"schema_version": _SCHEMA_VERSION, "functions": {}, "runs": [], "checkpoints": {}}

    def _read_data(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        schema_valid = (
            isinstance(raw, dict)
            and isinstance(raw.get("functions"), dict)
            and isinstance(raw.get("runs"), list)
        )
        if not schema_valid:
            logger.warning("Invalid session state in %s: schema mismatch", self.path)
            quarantine_path = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time() * 1000)}")
            try:
                os.replace(self.path, quarantine_path)
                logger.warning("Corrupt session quarantined as %s", quarantine_path)
            except OSError:
                logger.warning("Could not quarantine corrupt session", exc_info=True)
            return self._empty_data()

        checkpoints = raw.get("checkpoints", {})
        if not isinstance(checkpoints, dict):
            checkpoints = {}
        valid_functions = {
            str(address): dict(entry) for address, entry in raw["functions"].items() if isinstance(entry, dict)
        }
        valid_runs = [dict(entry) for entry in raw["runs"] if isinstance(entry, dict)]
        valid_checkpoints = {
            str(address): dict(entry) for address, entry in checkpoints.items() if isinstance(entry, dict)
        }
        out: dict[str, Any] = {
            "schema_version": raw.get("schema_version", _SCHEMA_VERSION),
            "functions": valid_functions,
            "runs": valid_runs,
            "checkpoints": valid_checkpoints,
        }
        if "identity" in raw:
            out["identity"] = raw["identity"]
        if "history" in raw and isinstance(raw["history"], list):
            out["history"] = raw["history"]
        return out

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

    def bind(self, identity: str) -> None:
        """Archive old results when the project/evidence/acceptance policy changes."""
        with self._thread_lock, self._file_lock():
            if self.path.exists():
                self._data = self._read_data()
            previous = self._data.get("identity")
            if previous != identity and (self._data["functions"] or self._data.get("checkpoints")):
                history = self._data.get("history", [])
                history.append({k: v for k, v in self._data.items() if k != "history"})
                self._data = {
                    "schema_version": _SCHEMA_VERSION,
                    "functions": {},
                    "runs": [],
                    "checkpoints": {},
                    "history": history,
                }
            self._data["identity"] = identity
            self._save_unlocked()

    def record_checkpoint(self, result: ReversalResult) -> None:
        from reforge.reports.formatter import _result_to_dict

        with self._thread_lock, self._file_lock():
            if self.path.exists():
                self._data = self._read_data()
            self._data.setdefault("checkpoints", {})[normalize_address(result.target.address)] = _result_to_dict(result)
            self._save_unlocked()

    def previous_feedback(self, address: str) -> str:
        with self._thread_lock:
            entry = self._data.get("checkpoints", {}).get(normalize_address(address))
            return json.dumps(entry, indent=2) if entry else ""

    def record_result(self, result: ReversalResult) -> None:
        addr = normalize_address(result.target.address)
        entry = {
            "address": result.target.address,
            "run_id": result.run_id,
            "error": result.error,
            "code_sha256": hashlib.sha256(result.code.encode()).hexdigest(),
            "code": result.code,
            "objective_verdict": result.objective_verdict.verdict.value if result.objective_verdict else None,
            "validation_verdict": (result.validation_verdict.verdict.value if result.validation_verdict else None),
            "validation_summary": result.validation_verdict.summary if result.validation_verdict else None,
            "validation_checks": result.validation_verdict.checks if result.validation_verdict else [],
            "validation_findings": result.validation_verdict.findings if result.validation_verdict else [],
            "candidate_overlay": result.validation_verdict.overlay_file if result.validation_verdict else None,
            "objective_findings": result.objective_verdict.findings if result.objective_verdict else [],
            "parity_findings": [asdict(f) for f in result.parity_findings],
            "class_name": result.target.class_name,
            "function_name": result.target.function_name,
            "success": result.success,
            "rounds_used": result.rounds_used,
            "verdict": result.checker_verdict.verdict.value if result.checker_verdict else None,
            "parity_status": result.parity_status.value if result.parity_status else None,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with self._thread_lock, self._file_lock():
            # Merge against the latest on-disk state to avoid lost updates from
            # concurrent class/function workers.
            self._data = self._read_data() if self.path.exists() else self._empty_data()
            self._data["functions"][addr] = entry
            self._data["runs"].append(entry)
            self._save_unlocked()

    def is_completed(self, address: str) -> bool:
        with self._thread_lock:
            addr = normalize_address(address)
            func = self._data["functions"].get(addr)
            return func is not None and func.get("success", False)

    def is_attempted(self, address: str) -> bool:
        """Return True if this address has been attempted (pass or fail)."""
        with self._thread_lock:
            addr = normalize_address(address)
            return addr in self._data["functions"]

    def attempt_count(self, address: str) -> int:
        """Return the number of recorded runs for an address."""
        with self._thread_lock:
            addr = normalize_address(address)
            return sum(
                1 for entry in self._data.get("runs", []) if normalize_address(str(entry.get("address", ""))) == addr
            )

    def get_class_summary(self, class_name: str) -> dict[str, int]:
        with self._thread_lock:
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
        with self._thread_lock:
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
        with self._thread_lock:
            return list(self._data["functions"].values())

    @property
    def identity(self) -> str | None:
        """Fingerprint of current records; reading never rebinds or archives them."""
        with self._thread_lock:
            value = self._data.get("identity")
            return value if isinstance(value, str) else None

    def get_checkpoint(self, address: str) -> dict[str, Any] | None:
        with self._thread_lock:
            value = self._data.get("checkpoints", {}).get(normalize_address(address))
            return dict(value) if isinstance(value, dict) else None

    def restore_checkpoint(self, address: str) -> ReversalResult | None:
        """Restore a previously recorded checkpoint as a ReversalResult."""
        raw = self.get_checkpoint(address)
        if raw is None:
            return None
        return ReversalResult.from_dict(raw)
