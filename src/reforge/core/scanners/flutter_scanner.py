"""Static Flutter application and Dart AOT snapshot parser."""

from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

DART_SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
DART_PACKAGE_REGEX = re.compile(rb"package:([a-zA-Z0-9_]+)/")
DART_VERSION_REGEX = re.compile(rb"Dart VM version: ([^\x00\r\n]{3,60})")


@dataclass(frozen=True)
class FlutterBuildInfo:
    """Parsed Flutter application and Dart VM metadata."""

    snapshot_hash: str | None = None
    engine_build_id: str | None = None
    dart_version: str | None = None
    packages: tuple[str, ...] = ()
    abi: str | None = None

    @property
    def notes(self) -> tuple[str, ...]:
        entries: list[str] = ["engine: Flutter / Dart AOT"]
        if self.snapshot_hash:
            entries.append(f"dart snapshot: {self.snapshot_hash[:16]}...")
        if self.engine_build_id:
            entries.append(f"engine build-id: {self.engine_build_id[:16]}...")
        if self.dart_version:
            entries.append(f"dart version: {self.dart_version}")
        if self.packages:
            entries.append(f"packages: {', '.join(self.packages[:6])}")
        return tuple(entries)


class FlutterScanner:
    """Zero-dependency static parser for Flutter binaries and APK artifacts."""

    @classmethod
    def probe_bytes(cls, data: bytes) -> FlutterBuildInfo | None:
        """Scan raw binary bytes (libapp.so or libflutter.so) for Flutter/Dart metadata."""
        snapshot_hash = cls._extract_snapshot_hash(data)
        engine_build_id = cls._extract_gnu_build_id(data)
        dart_version = cls._extract_dart_version(data)
        packages = cls._extract_packages(data)

        if not snapshot_hash and not engine_build_id and not packages and not dart_version:
            return None

        return FlutterBuildInfo(
            snapshot_hash=snapshot_hash,
            engine_build_id=engine_build_id,
            dart_version=dart_version,
            packages=tuple(packages),
        )

    @classmethod
    def probe_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> FlutterBuildInfo | None:
        """Probe an executable file or APK archive for Flutter build metadata."""
        p = Path(path)
        if not p.is_file():
            return None

        # Check if file is an APK archive
        if p.suffix.lower() == ".apk" or zipfile.is_zipfile(p):
            return cls.probe_apk(p)

        try:
            with p.open("rb") as f:
                data = f.read(max_bytes)
            return cls.probe_bytes(data)
        except OSError:
            return None

    @classmethod
    def probe_apk(cls, apk_path: Path) -> FlutterBuildInfo | None:
        """Inspect APK ZIP archive for Flutter libraries."""
        try:
            with zipfile.ZipFile(apk_path, "r") as archive:
                names = archive.namelist()
                libapp_entry = next((n for n in names if n.endswith("libapp.so")), None)
                libflutter_entry = next((n for n in names if n.endswith("libflutter.so")), None)

                if not libapp_entry and not libflutter_entry:
                    return None

                abi = None
                if libapp_entry:
                    parts = libapp_entry.split("/")
                    if len(parts) >= 3 and parts[0] == "lib":
                        abi = parts[1]

                snapshot_hash = None
                packages: list[str] = []
                if libapp_entry:
                    with archive.open(libapp_entry) as f:
                        app_data = f.read(32 * 1024 * 1024)
                    snapshot_hash = cls._extract_snapshot_hash(app_data)
                    packages = cls._extract_packages(app_data)

                engine_build_id = None
                dart_ver = None
                if libflutter_entry:
                    with archive.open(libflutter_entry) as f:
                        flutter_data = f.read(16 * 1024 * 1024)
                    engine_build_id = cls._extract_gnu_build_id(flutter_data)
                    dart_ver = cls._extract_dart_version(flutter_data)

                return FlutterBuildInfo(
                    snapshot_hash=snapshot_hash,
                    engine_build_id=engine_build_id,
                    dart_version=dart_ver,
                    packages=tuple(packages),
                    abi=abi,
                )
        except (zipfile.BadZipFile, OSError):
            return None

    @classmethod
    def _extract_snapshot_hash(cls, data: bytes) -> str | None:
        """Locate Dart snapshot magic 0xf5 0xf5 0xdc 0xdc and extract 32-hex hash at +20."""
        pos = data.find(DART_SNAPSHOT_MAGIC)
        if pos == -1:
            return None
        hash_offset = pos + 20
        if hash_offset + 32 > len(data):
            return None
        candidate = data[hash_offset : hash_offset + 32]
        # Validate 32 lowercase hex characters
        if re.fullmatch(rb"[0-9a-f]{32}", candidate):
            return candidate.decode("ascii")
        return None

    @classmethod
    def _extract_gnu_build_id(cls, data: bytes) -> str | None:
        """Parse ELF PT_NOTE / SHT_NOTE for GNU build ID."""
        pos = data.find(b"GNU\x00")
        if pos == -1 or pos < 12:
            return None

        # Check namesz == 4 and type == 3 (NT_GNU_BUILD_ID)
        namesz, descsz, n_type = struct.unpack_from("<III", data, pos - 12)
        if namesz == 4 and n_type == 3 and 4 <= descsz <= 64:
            desc_offset = pos + 4
            if desc_offset + descsz <= len(data):
                desc_bytes = data[desc_offset : desc_offset + descsz]
                return desc_bytes.hex()
        return None

    @classmethod
    def _extract_dart_version(cls, data: bytes) -> str | None:
        """Scan ASCII text for Dart VM version string."""
        m = DART_VERSION_REGEX.search(data)
        if m:
            return m.group(1).decode("utf-8", errors="ignore").strip()
        return None

    @classmethod
    def _extract_packages(cls, data: bytes) -> list[str]:
        """Scan string pool for package:<name>/ references."""
        packages: list[str] = []
        for m in DART_PACKAGE_REGEX.finditer(data):
            pkg = m.group(1).decode("ascii", errors="ignore")
            if pkg not in packages and pkg not in ("flutter", "flutter_test"):
                packages.append(pkg)
            if len(packages) >= 16:
                break
        return packages
