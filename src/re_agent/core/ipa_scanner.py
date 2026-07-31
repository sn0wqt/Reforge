"""IPA & Binary Asset String Scanner Module.

Scans extracted iOS IPA directories, Mach-O binaries, plists, SQLite databases,
and Unity asset files for target strings with Mach-O virtual address offset mapping.
"""

from __future__ import annotations

import logging
import plistlib
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from re_agent.core.engine_detector import iter_directory_files_bounded
from re_agent.core.macho import macho_vm_address_for_file_offset
from re_agent.core.swift_decoder import extract_swift_strings_from_bytes
from re_agent.utils.binary_magic import is_mach_o

logger = logging.getLogger(__name__)
MAX_SCAN_FILE_BYTES = 268_435_456
MAX_SCAN_TOTAL_BYTES = 536_870_912
MAX_SCAN_FILES = 10_000
MAX_SCAN_RESULTS = 10_000


class IPAScanner:
    """Scanner for iOS IPA packages, plists, databases, and binaries."""

    def __init__(self, ipa_dir: str | Path, min_length: int = 4, max_length: int = 1000) -> None:
        self.ipa_dir = Path(ipa_dir)
        self.min_length = min_length
        self.max_length = max_length



    def scan(self, search_query: str | None = None) -> list[dict[str, Any]]:
        """Recursively scan IPA directory for string matches."""
        results: list[dict[str, Any]] = []
        if not self.ipa_dir.exists():
            logger.warning("[IPAScanner] Directory does not exist: %s", self.ipa_dir)
            return results

        query_lower = search_query.lower() if search_query else None

        root = self.ipa_dir.resolve()
        scanned_files = 0
        remaining_bytes = MAX_SCAN_TOTAL_BYTES
        for file_path in iter_directory_files_bounded(root):
            if (
                len(results) >= MAX_SCAN_RESULTS
                or scanned_files >= MAX_SCAN_FILES
                or remaining_bytes <= 0
            ):
                break
            try:
                size = file_path.stat().st_size
            except OSError:
                continue
            if size > MAX_SCAN_FILE_BYTES:
                continue
            # Skip scanning third-party ad & analytics frameworks inside Frameworks/
            rel_str = str(file_path.relative_to(root)).casefold()
            if any(
                sdk in rel_str
                for sdk in (
                    "inmobisdk",
                    "bidmachine",
                    "googlemobileads",
                    "chartboost",
                    "applovin",
                    "appsflyer",
                    "singular",
                    "adjust",
                    "firebase",
                    "vungle",
                    "ironsource",
                    "unityads",
                    "mopub",
                )
            ):
                continue

            ext = file_path.suffix.lower()
            file_name = file_path.name
            scan_kind: str | None = None
            if ext in (".plist", ".strings") or file_name == "Info.plist":
                scan_kind = "plist"
            elif ext in (".db", ".sqlite", ".sqlite3"):
                scan_kind = "sqlite"
            elif (
                ext
                in (
                    ".dylib",
                    ".framework",
                    ".so",
                    ".assets",
                    ".resource",
                    ".unity3d",
                )
                or is_mach_o(file_path)
            ):
                scan_kind = "binary"
            if scan_kind is None or size > remaining_bytes:
                continue
            scanned_files += 1
            remaining_bytes -= size
            if scan_kind == "plist":
                results.extend(self._scan_plist(file_path, query_lower))
            elif scan_kind == "sqlite":
                results.extend(self._scan_sqlite(file_path, query_lower))
            else:
                results.extend(self._scan_binary(file_path, query_lower))

        return results[:MAX_SCAN_RESULTS]

    def _scan_plist(self, file_path: Path, query_lower: str | None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            with open(file_path, "rb") as f:
                plist_data = plistlib.load(f)
            plist_str = str(plist_data)
            if query_lower is None or query_lower in plist_str.lower():
                results.append(
                    {
                        "file": str(file_path.relative_to(self.ipa_dir)),
                        "type": "plist",
                        "match": query_lower or "all_plist_strings",
                        "snippet": plist_str[:200],
                    }
                )
        except Exception:
            pass
        return results

    def _scan_sqlite(self, file_path: Path, query_lower: str | None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            uri = f"{file_path.resolve().as_uri()}?mode=ro&immutable=1"
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                for t in tables:
                    t_name = str(t[0])
                    quoted_name = t_name.replace('"', '""')
                    cursor.execute(f'SELECT * FROM "{quoted_name}" LIMIT 500;')
                    rows = cursor.fetchall()
                    for row in rows:
                        row_str = str(row)
                        if query_lower is None or query_lower in row_str.lower():
                            results.append(
                                {
                                    "file": str(file_path.relative_to(self.ipa_dir)),
                                    "type": "sqlite",
                                    "match": query_lower or "database_row",
                                    "snippet": f"Table {t_name}: {row_str[:150]}",
                                }
                            )
                            if len(results) >= MAX_SCAN_RESULTS:
                                return results
        except Exception as err:
            logger.debug("[IPA Scanner] SQLite scan skipped for %s: %s", file_path, err)
        return results

    def _scan_binary(self, file_path: Path, query_lower: str | None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            extracted = extract_swift_strings_from_bytes(data)
            is_macho = is_mach_o(file_path)

            for item in extracted:
                if len(results) >= MAX_SCAN_RESULTS:
                    break
                val = item["string"]
                if not self.min_length <= len(val) <= self.max_length:
                    continue
                if query_lower is None or query_lower in val.lower():
                    virtual_address = (
                        macho_vm_address_for_file_offset(data, int(item["offset"]))
                        if is_macho
                        else None
                    )
                    address_text = (
                        f"Unslid VM: {hex(virtual_address)}"
                        if virtual_address is not None
                        else "Unslid VM: unresolved"
                    )
                    results.append(
                        {
                            "file": str(file_path.relative_to(self.ipa_dir)),
                            "type": f"binary:{item['type']}",
                            "match": val,
                            "offset": hex(item["offset"]),
                            "virtual_address": (
                                hex(virtual_address)
                                if virtual_address is not None
                                else None
                            ),
                            "address_kind": (
                                "unslid_macho_vmaddr"
                                if virtual_address is not None
                                else "file_offset_only"
                            ),
                            "snippet": (
                                f"{address_text} | "
                                f"Offset: {hex(item['offset'])} | String: {val[:100]}"
                            ),
                        }
                    )
        except Exception:
            pass
        return results
