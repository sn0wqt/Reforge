"""Pure-Python zero-dependency Chromium Pickle and ASAR archive reader.

Provides streaming and range-based member access, directory listing,
fail-closed path safety validation, companion ``<app>.unpacked`` resolution,
and SHA-256 integrity digest verification without unpacking gigabytes to disk.
"""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import struct
import tempfile
import types
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

# Default resource budgets matching Chromium and REA limits
DEFAULT_MAX_HEADER_BYTES = 16 * 1024 * 1024  # 16 MiB decode budget for header pickle
DEFAULT_MAX_LISTING_BYTES = 64 * 1024 * 1024  # 64 MiB expanded representation budget
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_MAX_MEMBER_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB per member
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB read chunks
PICKLE_MAGIC = 4

_WINDOWS_INVALID_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class AsarError(Exception):
    """Base exception for all ASAR archive operations."""


class AsarFormatError(AsarError, ValueError):
    """Raised when an ASAR container has an invalid pickle or malformed structure."""


class AsarSafetyError(AsarError, ValueError):
    """Raised when an ASAR entry violates safety bounds or resource limits."""


class AsarIntegrityError(AsarError, ValueError):
    """Raised when an ASAR entry contradicts its declared integrity digest."""


class AsarUnpackedUnavailableError(AsarError, FileNotFoundError):
    """Raised when a companion .unpacked directory or member file is missing."""


@dataclass(frozen=True)
class AsarLimits:
    """Resource budgets for ASAR header decoding and listing expansion."""

    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES
    max_listing_bytes: int = DEFAULT_MAX_LISTING_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES

    def __post_init__(self) -> None:
        if self.max_header_bytes <= 0:
            raise ValueError("max_header_bytes must be positive")
        if self.max_listing_bytes <= 0:
            raise ValueError("max_listing_bytes must be positive")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if self.max_member_bytes < 0:
            raise ValueError("max_member_bytes must be non-negative")


@dataclass(frozen=True)
class AsarIntegrity:
    """Declared cryptographic integrity metadata for an ASAR entry."""

    algorithm: str
    hash: str
    block_size: int | None = None
    blocks: tuple[str, ...] = ()


@dataclass(frozen=True)
class AsarEntry:
    """A member entry (file, directory, or symlink) within an ASAR container."""

    path: str
    size: int = 0
    offset: int | None = None
    data_offset: int | None = None
    unpacked: bool = False
    is_directory: bool = False
    is_symlink: bool = False
    link: str | None = None
    executable: bool = False
    integrity: AsarIntegrity | None = None
    sha256: str | None = None


def admit_asar_header(
    file_obj: BinaryIO,
    archive_size: int,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> tuple[int, int, int]:
    """Validate Chromium pickle header prefix extents before allocating memory.

    Returns:
        tuple of ``(header_bytes, payload_bytes, json_bytes)``.
    """
    if archive_size < 16:
        raise AsarFormatError("Truncated ASAR container: file size is less than 16 bytes")

    file_obj.seek(0)
    prefix = file_obj.read(16)
    if len(prefix) != 16:
        raise AsarFormatError("Truncated ASAR header prefix")

    magic, header_bytes, payload_bytes, json_bytes = struct.unpack("<4I", prefix)

    if magic != PICKLE_MAGIC:
        raise AsarFormatError(f"Truncated or invalid ASAR size pickle: expected magic {PICKLE_MAGIC}, got {magic}")

    if (
        header_bytes < 8
        or header_bytes > archive_size - 8
        or payload_bytes != header_bytes - 4
        or json_bytes > payload_bytes - 4
    ):
        raise AsarFormatError("ASAR header leaves its container or has invalid pickle extents")

    if header_bytes > max_header_bytes:
        raise AsarSafetyError(f"ASAR header exceeds the {max_header_bytes} byte decode budget")

    return header_bytes, payload_bytes, json_bytes


def read_asar_header_json(
    file_obj: BinaryIO,
    archive_size: int,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> tuple[dict[str, Any], int, int]:
    """Admit and decode the JSON header dictionary.

    Returns:
        tuple of ``(header_dict, header_bytes, base_data_offset)``.
    """
    header_bytes, _, json_bytes = admit_asar_header(file_obj, archive_size, max_header_bytes)
    file_obj.seek(16)
    raw_json = file_obj.read(json_bytes)
    if len(raw_json) != json_bytes:
        raise AsarFormatError(f"Truncated ASAR JSON header: expected {json_bytes} bytes, read {len(raw_json)}")

    try:
        header_text = raw_json.decode("utf-8")
        header_dict = json.loads(header_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise AsarFormatError(f"Malformed ASAR JSON header: {err}") from err

    if not isinstance(header_dict, dict):
        raise AsarFormatError("ASAR root header is not a JSON object")

    base_data_offset = 8 + header_bytes
    return header_dict, header_bytes, base_data_offset


def _validate_component_name(name: str) -> None:
    if not isinstance(name, str):
        raise AsarFormatError(f"ASAR path component must be text: {name!r}")
    if not name or name in {".", ".."}:
        raise AsarSafetyError(f"ASAR header has an unsafe path component: {name!r}")
    if "/" in name or "\x00" in name or "\\" in name:
        raise AsarSafetyError(f"ASAR header has an unsafe separator or NUL in component: {name!r}")
    if any(ord(c) < 32 for c in name):
        raise AsarSafetyError(f"ASAR header component contains control characters: {name!r}")
    if any(c in _WINDOWS_INVALID_CHARS for c in name):
        raise AsarSafetyError(f"ASAR header component contains non-portable characters: {name!r}")
    if name != name.rstrip(" ."):
        raise AsarSafetyError(f"ASAR header component has trailing dot or space: {name!r}")
    device_name = name.split(".", 1)[0].casefold()
    if device_name in _WINDOWS_RESERVED_NAMES:
        raise AsarSafetyError(f"ASAR header component uses reserved device name: {name!r}")


def _parse_entries_recursive(
    header_dict: dict[str, Any],
    base_data_offset: int,
    archive_size: int,
    limits: AsarLimits,
) -> dict[str, AsarEntry]:
    """Iteratively walk the JSON files tree and produce validated AsarEntry records."""
    if "files" not in header_dict or not isinstance(header_dict["files"], dict):
        raise AsarFormatError("ASAR root has no files table")

    entries: dict[str, AsarEntry] = {}
    pending: list[tuple[str, Iterator[tuple[str, Any]]]] = [("", iter(header_dict["files"].items()))]
    retained_bytes = 0

    while pending:
        parent, children = pending[-1]
        try:
            name, raw_metadata = next(children)
        except StopIteration:
            pending.pop()
            continue

        _validate_component_name(name)

        path = f"{parent}/{name}" if parent else name
        units = len(path)
        retained_bytes += units * 2 + 256
        if retained_bytes > limits.max_listing_bytes:
            raise AsarSafetyError(f"ASAR expanded listing exceeds representation budget: {limits.max_listing_bytes}")
        if len(entries) >= limits.max_entries:
            raise AsarSafetyError(f"ASAR entries count exceeds limit: {limits.max_entries}")

        if not isinstance(raw_metadata, dict):
            raise AsarFormatError(f"ASAR entry has invalid metadata object: {path!r}")

        if "files" in raw_metadata:
            # Directory node
            if not isinstance(raw_metadata["files"], dict):
                raise AsarFormatError(f"ASAR directory node has non-dict files table: {path!r}")
            dir_entry = AsarEntry(path=path, is_directory=True)
            entries[path] = dir_entry
            pending.append((path, iter(raw_metadata["files"].items())))

        elif "link" in raw_metadata:
            # Symbolic link
            target = raw_metadata["link"]
            if not isinstance(target, str):
                raise AsarFormatError(f"ASAR symlink target must be string: {path!r}")
            link_entry = AsarEntry(path=path, is_symlink=True, link=target)
            entries[path] = link_entry

        elif "size" in raw_metadata:
            # File node
            size = raw_metadata["size"]
            if not isinstance(size, int) or size < 0:
                raise AsarFormatError(f"ASAR entry has invalid size: {path!r}")
            if size > limits.max_member_bytes:
                raise AsarSafetyError(
                    f"ASAR entry exceeds max member size: {path!r} ({size} > {limits.max_member_bytes})"
                )

            is_unpacked = bool(raw_metadata.get("unpacked", False))
            is_executable = bool(raw_metadata.get("executable", False))

            raw_offset = raw_metadata.get("offset")
            offset: int | None = None
            data_offset: int | None = None

            if not is_unpacked:
                if raw_offset is None:
                    raise AsarFormatError(f"Packed ASAR entry missing offset: {path!r}")
                try:
                    offset = int(raw_offset)
                except (ValueError, TypeError) as err:
                    raise AsarFormatError(f"Packed ASAR entry has invalid offset {raw_offset!r}: {path!r}") from err
                if offset < 0:
                    raise AsarFormatError(f"Packed ASAR entry has negative offset: {path!r}")

                data_offset = base_data_offset + offset
                if data_offset > archive_size or size > (archive_size - data_offset):
                    raise AsarFormatError(
                        f"ASAR entry range is outside its container: {path!r} "
                        f"(start={data_offset}, size={size}, archive_size={archive_size})"
                    )

            # Integrity metadata
            integrity: AsarIntegrity | None = None
            raw_integrity = raw_metadata.get("integrity")
            if isinstance(raw_integrity, dict):
                algo = str(raw_integrity.get("algorithm", ""))
                digest_hash = str(raw_integrity.get("hash", ""))
                bs = raw_integrity.get("blockSize")
                block_size = bs if isinstance(bs, int) and bs > 0 else None
                raw_blocks = raw_integrity.get("blocks")
                blocks = tuple(str(b) for b in raw_blocks) if isinstance(raw_blocks, list) else ()
                integrity = AsarIntegrity(algorithm=algo, hash=digest_hash, block_size=block_size, blocks=blocks)

            sha256: str | None = None
            if integrity and integrity.algorithm.upper() == "SHA256" and len(integrity.hash) == 64:
                sha256 = integrity.hash.lower()

            file_entry = AsarEntry(
                path=path,
                size=size,
                offset=offset,
                data_offset=data_offset,
                unpacked=is_unpacked,
                executable=is_executable,
                integrity=integrity,
                sha256=sha256,
            )
            entries[path] = file_entry

        else:
            raise AsarFormatError(f"ASAR entry has no directory, link or file metadata: {path!r}")

    return entries


class SubrangeReader(io.RawIOBase):
    """Seekable read-only stream restricted to a contiguous subrange of a file."""

    def __init__(self, raw: BinaryIO, start: int, size: int, *, close_raw: bool = False) -> None:
        self._raw = raw
        self._start = start
        self._size = size
        self._pos = 0
        self._close_raw = close_raw
        self._closed = False

    def readable(self) -> bool:
        return not self._closed

    def seekable(self) -> bool:
        return not self._closed

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        self._check_closed()
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._check_closed()
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == os.SEEK_END:
            new_pos = self._size + offset
        else:
            raise ValueError(f"Invalid whence argument: {whence}")

        if new_pos < 0:
            raise ValueError(f"Negative seek position: {new_pos}")
        self._pos = new_pos
        return self._pos

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        self._check_closed()
        if self._pos >= self._size:
            return 0
        to_read = min(len(b), self._size - self._pos)
        if to_read == 0:
            return 0
        self._raw.seek(self._start + self._pos)
        chunk = self._raw.read(to_read)
        if not chunk:
            return 0
        b[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)

    def read(self, size: int = -1) -> bytes:
        self._check_closed()
        if self._pos >= self._size:
            return b""
        to_read = self._size - self._pos if size < 0 else min(size, self._size - self._pos)
        if to_read == 0:
            return b""
        self._raw.seek(self._start + self._pos)
        data = self._raw.read(to_read)
        self._pos += len(data)
        return data

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._close_raw:
                self._raw.close()

    def _check_closed(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed SubrangeReader")


class AsarReader:
    """Pure-Python zero-dependency reader for Electron ASAR archives.

    Supports:
    - Zero-copy / streaming range reads directly from packed member offsets.
    - Automatic resolution and verification of companion ``<archive>.unpacked`` files.
    - Strict Chromium Pickle header admission bounds.
    - Traversal protection and directory listing inspection.
    - Declared SHA-256 integrity digest validation.
    """

    def __init__(
        self,
        archive: str | Path | BinaryIO,
        *,
        unpacked_dir: str | Path | None = None,
        limits: AsarLimits | None = None,
    ) -> None:
        self._limits = limits or AsarLimits()
        self._unpacked_dir = Path(unpacked_dir) if unpacked_dir is not None else None
        self._close_file = False
        self._closed = False

        if isinstance(archive, (str, Path)):
            self._archive_path: Path | None = Path(archive).resolve()
            if not self._archive_path.is_file():
                raise AsarFormatError(f"ASAR container is not a regular file: {self._archive_path}")
            self._archive_size = self._archive_path.stat().st_size
            self._file: BinaryIO = open(self._archive_path, "rb")  # noqa: SIM115
            self._close_file = True
            if self._unpacked_dir is None:
                self._unpacked_dir = Path(f"{self._archive_path}.unpacked")
        else:
            self._archive_path = None
            self._file = archive
            # Determine size by seeking
            current = self._file.tell()
            self._file.seek(0, os.SEEK_END)
            self._archive_size = self._file.tell()
            self._file.seek(current)

        # Parse header
        self._header, self._header_size, self._base_data_offset = read_asar_header_json(
            self._file, self._archive_size, self._limits.max_header_bytes
        )

        # Parse directory listing
        self._entries = _parse_entries_recursive(self._header, self._base_data_offset, self._archive_size, self._limits)

    @property
    def archive_size(self) -> int:
        """Total size of the ASAR archive in bytes."""
        return self._archive_size

    @property
    def header_size(self) -> int:
        """Pickle payload header size in bytes."""
        return self._header_size

    @property
    def base_data_offset(self) -> int:
        """Absolute offset in the container where concatenated file payloads begin."""
        return self._base_data_offset

    @property
    def header(self) -> dict[str, Any]:
        """Raw decoded JSON header dictionary."""
        return self._header

    @property
    def entries(self) -> dict[str, AsarEntry]:
        """Mapping from normalized POSIX path to AsarEntry."""
        return self._entries

    def list_paths(self) -> list[str]:
        """Return all member paths sorted by codepoint order."""
        return sorted(self._entries.keys())

    def list_entries(self) -> list[AsarEntry]:
        """Return all AsarEntry objects sorted by path."""
        return [self._entries[p] for p in self.list_paths()]

    def has_entry(self, path: str) -> bool:
        """Check if an entry exists."""
        return self._normalize_query_path(path) in self._entries

    def get_entry(self, path: str) -> AsarEntry:
        """Retrieve the AsarEntry for a path, or raise KeyError."""
        normalized = self._normalize_query_path(path)
        entry = self._entries.get(normalized)
        if entry is None:
            raise KeyError(f"ASAR entry not found: {path!r}")
        return entry

    def _normalize_query_path(self, path: str) -> str:
        norm = path.replace("\\", "/").strip("/")
        return PurePosixPath(norm).as_posix() if norm else ""

    def _resolve_unpacked_path(self, entry: AsarEntry) -> Path:
        if self._unpacked_dir is None:
            raise AsarUnpackedUnavailableError(
                f"ASAR unpacked companion bytes are unavailable for {entry.path!r} "
                "(no archive path or unpacked_dir provided)"
            )
        if not self._unpacked_dir.is_dir():
            raise AsarUnpackedUnavailableError(f"ASAR unpacked companion directory is missing: {self._unpacked_dir}")
        if self._unpacked_dir.is_symlink():
            raise AsarSafetyError(f"ASAR unpacked companion directory is a symlink: {self._unpacked_dir}")

        canonical_root = self._unpacked_dir.resolve()
        candidate = (self._unpacked_dir / Path(*PurePosixPath(entry.path).parts)).resolve()

        try:
            candidate.relative_to(canonical_root)
        except ValueError:
            raise AsarSafetyError(f"ASAR unpacked entry escaped its companion directory: {entry.path!r}") from None

        if not candidate.exists():
            raise AsarUnpackedUnavailableError(
                f"ASAR unpacked member file is missing: {entry.path!r} (expected at {candidate})"
            )
        if not candidate.is_file() or candidate.is_symlink():
            raise AsarSafetyError(f"ASAR unpacked entry is not a regular file: {entry.path!r} ({candidate})")

        return candidate

    def open_file(self, path: str) -> BinaryIO:
        """Open a seekable read-only binary stream for a member file.

        Streams directly from packed container offsets without extracting to disk.
        For unpacked files, opens the companion file safely.
        """
        self._check_closed()
        entry = self.get_entry(path)

        if entry.is_directory:
            raise AsarFormatError(f"Cannot open directory as file: {path!r}")
        if entry.is_symlink:
            raise AsarFormatError(f"Cannot open symlink as regular file: {path!r} (target: {entry.link})")

        if entry.unpacked:
            unpacked_path = self._resolve_unpacked_path(entry)
            return open(unpacked_path, "rb")

        assert entry.data_offset is not None

        if self._archive_path is not None:
            # Independent handle for thread safety and concurrent streaming
            raw_handle = open(self._archive_path, "rb")  # noqa: SIM115
            return io.BufferedReader(SubrangeReader(raw_handle, entry.data_offset, entry.size, close_raw=True))

        # In-memory or shared stream
        return io.BufferedReader(SubrangeReader(self._file, entry.data_offset, entry.size, close_raw=False))

    def read_file(
        self,
        path: str,
        offset: int = 0,
        length: int | None = None,
    ) -> bytes:
        """Read full or subrange byte content of an ASAR member directly.

        Args:
            path: Normalized relative path within the archive.
            offset: Byte offset within the member (>= 0).
            length: Maximum bytes to read, or None to read through member EOF.
        """
        self._check_closed()
        entry = self.get_entry(path)

        if entry.is_directory:
            raise AsarFormatError(f"Cannot read directory as file: {path!r}")
        if entry.is_symlink:
            raise AsarFormatError(f"Cannot read symlink as regular file: {path!r} (target: {entry.link})")
        if offset < 0:
            raise ValueError(f"Offset must be non-negative: {offset}")
        if length is not None and length < 0:
            raise ValueError(f"Length must be non-negative: {length}")

        if offset >= entry.size:
            return b""

        available = entry.size - offset
        to_read = available if length is None else min(length, available)
        if to_read == 0:
            return b""

        if entry.unpacked:
            unpacked_path = self._resolve_unpacked_path(entry)
            with open(unpacked_path, "rb") as f:
                f.seek(offset)
                data = f.read(to_read)
                return data

        assert entry.data_offset is not None
        start = entry.data_offset + offset

        if self._archive_path is not None:
            with open(self._archive_path, "rb") as f:
                f.seek(start)
                data = f.read(to_read)
                if len(data) != to_read:
                    raise AsarFormatError(
                        f"Unexpected EOF reading packed member {path!r}: expected {to_read} bytes, got {len(data)}"
                    )
                return data

        self._file.seek(start)
        data = self._file.read(to_read)
        if len(data) != to_read:
            raise AsarFormatError(
                f"Unexpected EOF reading packed member {path!r}: expected {to_read} bytes, got {len(data)}"
            )
        return data

    def stream_file(
        self,
        path: str,
        offset: int = 0,
        length: int | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> Iterator[bytes]:
        """Yield chunks of an ASAR member's content without loading the entire file into memory."""
        self._check_closed()
        entry = self.get_entry(path)

        if entry.is_directory:
            raise AsarFormatError(f"Cannot stream directory as file: {path!r}")
        if entry.is_symlink:
            raise AsarFormatError(f"Cannot stream symlink as regular file: {path!r}")
        if offset < 0:
            raise ValueError(f"Offset must be non-negative: {offset}")
        if length is not None and length < 0:
            raise ValueError(f"Length must be non-negative: {length}")
        if chunk_size <= 0:
            raise ValueError(f"Chunk size must be positive: {chunk_size}")

        if offset >= entry.size:
            return

        available = entry.size - offset
        remaining = available if length is None else min(length, available)

        with self.open_file(path) as stream:
            if offset > 0:
                stream.seek(offset)
            while remaining > 0:
                to_read = min(chunk_size, remaining)
                chunk = stream.read(to_read)
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    def compute_sha256(self, path: str) -> str:
        """Compute the SHA-256 digest of an ASAR member by streaming its bytes."""
        hasher = hashlib.sha256()
        for chunk in self.stream_file(path, chunk_size=128 * 1024):
            hasher.update(chunk)
        return hasher.hexdigest()

    def verify_integrity(self, path: str, *, raise_on_mismatch: bool = False) -> bool:
        """Verify the integrity of a member against its declared ASAR digest.

        Validates both the overall SHA-256 and per-block hashes if declared.
        Returns True if the file matches or if no integrity is declared.
        """
        entry = self.get_entry(path)
        if entry.integrity is None or not entry.sha256:
            return True

        # Per-block integrity validation
        if entry.integrity.blocks and entry.integrity.block_size:
            block_size = entry.integrity.block_size
            full_hasher = hashlib.sha256()
            for current_block_idx, chunk in enumerate(self.stream_file(path, chunk_size=block_size)):
                full_hasher.update(chunk)
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                if current_block_idx < len(entry.integrity.blocks):
                    expected_block = entry.integrity.blocks[current_block_idx]
                    if chunk_hash.lower() != expected_block.lower():
                        if raise_on_mismatch:
                            raise AsarIntegrityError(
                                f"ASAR block integrity mismatch for {path!r} at block {current_block_idx}: "
                                f"expected {expected_block}, computed {chunk_hash}"
                            )
                        return False

            computed_full = full_hasher.hexdigest()
            if computed_full.lower() != entry.sha256.lower():
                if raise_on_mismatch:
                    raise AsarIntegrityError(
                        f"ASAR integrity mismatch for {path!r}: expected {entry.sha256}, computed {computed_full}"
                    )
                return False
            return True

        # Whole-file integrity validation
        computed = self.compute_sha256(path)
        if computed.lower() != entry.sha256.lower():
            if raise_on_mismatch:
                raise AsarIntegrityError(
                    f"ASAR integrity mismatch for {path!r}: expected {entry.sha256}, computed {computed}"
                )
            return False
        return True

    def extract_file(
        self,
        entry_path: str,
        destination_dir: str | Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        """Safely extract a single member file into destination_dir with containment validation."""
        self._check_closed()
        entry = self.get_entry(entry_path)

        if entry.is_directory:
            raise AsarFormatError(f"Cannot extract directory entry as file: {entry_path!r}")
        if entry.is_symlink:
            raise AsarFormatError(f"Cannot extract symlink entry as file: {entry_path!r}")

        dest_root = Path(destination_dir).resolve()
        dest_root.mkdir(parents=True, exist_ok=True)

        target = (dest_root / Path(*PurePosixPath(entry.path).parts)).resolve()
        try:
            target.relative_to(dest_root)
        except ValueError:
            raise AsarSafetyError(f"Extraction destination escapes directory: {entry_path!r}") from None

        if target.exists() and not overwrite:
            raise FileExistsError(f"Extraction destination file already exists: {target}")

        target.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write via temporary file
        temp_file = tempfile.NamedTemporaryFile(dir=target.parent, delete=False)  # noqa: SIM115
        temp_path = Path(temp_file.name)
        try:
            for chunk in self.stream_file(entry_path):
                temp_file.write(chunk)
            temp_file.close()
            os.replace(temp_path, target)
        except BaseException:
            temp_file.close()
            if temp_path.exists():
                temp_path.unlink()
            raise

        return target

    def extract_all(
        self,
        destination_dir: str | Path,
        *,
        overwrite: bool = False,
    ) -> list[Path]:
        """Extract all directories and files into destination_dir."""
        self._check_closed()
        dest_root = Path(destination_dir).resolve()
        dest_root.mkdir(parents=True, exist_ok=True)
        extracted: list[Path] = []

        for entry in self.list_entries():
            if entry.is_directory:
                target_dir = (dest_root / Path(*PurePosixPath(entry.path).parts)).resolve()
                try:
                    target_dir.relative_to(dest_root)
                except ValueError:
                    raise AsarSafetyError(f"Directory destination escapes root: {entry.path!r}") from None
                target_dir.mkdir(parents=True, exist_ok=True)
            elif entry.is_symlink:
                # Omit symlinks or record limitation, matching REA behavior
                continue
            else:
                out = self.extract_file(entry.path, destination_dir, overwrite=overwrite)
                extracted.append(out)

        return extracted

    def close(self) -> None:
        """Release underlying archive file resources."""
        if not self._closed:
            self._closed = True
            if self._close_file:
                self._file.close()

    def _check_closed(self) -> None:
        if self._closed:
            raise AsarError("I/O operation on closed AsarReader")

    def __enter__(self) -> AsarReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.close()


def create_asar_bytes(
    files: Mapping[str, bytes | str],
    *,
    unpacked_files: set[str] | None = None,
    symlinks: Mapping[str, str] | None = None,
    include_integrity: bool = True,
    block_size: int = 4 * 1024 * 1024,
) -> tuple[bytes, dict[str, bytes]]:
    """Build a valid in-memory ASAR container from a mapping of files and symlinks.

    Returns:
        tuple of ``(archive_bytes, unpacked_files_dict)``.
    """
    unpacked_set = unpacked_files or set()
    links = symlinks or {}

    root: dict[str, Any] = {"files": {}}
    unpacked_result: dict[str, bytes] = {}
    packed_payload = bytearray()
    current_offset = 0

    def insert_entry(rel_path: str, metadata: dict[str, Any]) -> None:
        parts = PurePosixPath(rel_path).parts
        curr = root["files"]
        for part in parts[:-1]:
            if part not in curr:
                curr[part] = {"files": {}}
            curr = curr[part]["files"]
        curr[parts[-1]] = metadata

    # Process all regular files
    for raw_path in sorted(files.keys()):
        norm_path = PurePosixPath(raw_path.replace("\\", "/").strip("/")).as_posix()
        content = files[raw_path]
        data = content.encode("utf-8") if isinstance(content, str) else content

        entry_meta: dict[str, Any] = {"size": len(data)}

        if include_integrity:
            sha = hashlib.sha256(data).hexdigest()
            blocks: list[str] = []
            for i in range(0, len(data), block_size):
                blocks.append(hashlib.sha256(data[i : i + block_size]).hexdigest())
            if not blocks:
                blocks = [hashlib.sha256(b"").hexdigest()]
            entry_meta["integrity"] = {
                "algorithm": "SHA256",
                "hash": sha,
                "blockSize": block_size,
                "blocks": blocks,
            }

        if norm_path in unpacked_set:
            entry_meta["unpacked"] = True
            unpacked_result[norm_path] = data
        else:
            entry_meta["offset"] = str(current_offset)
            packed_payload.extend(data)
            current_offset += len(data)

        insert_entry(norm_path, entry_meta)

    # Process symlinks
    for raw_path, target in sorted(links.items()):
        norm_path = PurePosixPath(raw_path.replace("\\", "/").strip("/")).as_posix()
        insert_entry(norm_path, {"link": target})

    json_bytes = json.dumps(root, separators=(",", ":")).encode("utf-8")
    padding_len = (4 - (len(json_bytes) % 4)) % 4
    padded_json = json_bytes + b"\x00" * padding_len

    header_bytes = 8 + len(padded_json)
    payload_bytes = header_bytes - 4
    prefix = struct.pack("<4I", PICKLE_MAGIC, header_bytes, payload_bytes, len(json_bytes))

    archive_bytes = prefix + padded_json + bytes(packed_payload)
    return archive_bytes, unpacked_result


def pack_asar(
    source_dir: str | Path,
    output_path: str | Path,
    *,
    unpack_patterns: list[str] | None = None,
    include_integrity: bool = True,
) -> Path:
    """Pack an on-disk folder into an ASAR archive and optional companion ``.unpacked`` directory."""
    src = Path(source_dir).resolve()
    out = Path(output_path).resolve()
    patterns = unpack_patterns or []

    files_map: dict[str, bytes] = {}
    unpacked_set: set[str] = set()

    for root_dir, _, filenames in os.walk(src):
        for fname in filenames:
            full_path = Path(root_dir) / fname
            rel_path = full_path.relative_to(src).as_posix()
            files_map[rel_path] = full_path.read_bytes()
            if any(fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(fname, pat) for pat in patterns):
                unpacked_set.add(rel_path)

    archive_bytes, unpacked_dict = create_asar_bytes(
        files_map,
        unpacked_files=unpacked_set,
        include_integrity=include_integrity,
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(archive_bytes)

    if unpacked_dict:
        unpacked_root = Path(f"{out}.unpacked")
        for u_path, u_data in unpacked_dict.items():
            dest = unpacked_root / Path(*PurePosixPath(u_path).parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(u_data)

    return out


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_HEADER_BYTES",
    "DEFAULT_MAX_LISTING_BYTES",
    "DEFAULT_MAX_MEMBER_BYTES",
    "PICKLE_MAGIC",
    "AsarEntry",
    "AsarError",
    "AsarFormatError",
    "AsarIntegrityError",
    "AsarLimits",
    "AsarReader",
    "AsarSafetyError",
    "AsarUnpackedUnavailableError",
    "SubrangeReader",
    "admit_asar_header",
    "create_asar_bytes",
    "pack_asar",
    "read_asar_header_json",
]
