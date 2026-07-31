"""Fail-closed ZIP/APK/IPA validation and bounded streaming extraction."""

from __future__ import annotations

import ntpath
import os
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_MEMBER_BYTES = 1_073_741_824
MAX_ARCHIVE_TOTAL_BYTES = 4_294_967_296
MAX_COMPRESSION_RATIO = 1_000.0
_COPY_CHUNK_BYTES = 1024 * 1024
_WINDOWS_REPARSE_POINT = 0x0400
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


class ArchiveSafetyError(ValueError):
    """Raised when an archive violates structural or resource limits."""


@dataclass(frozen=True)
class ArchiveLimits:
    """Resource limits applied before and during ZIP extraction."""

    max_entries: int = MAX_ARCHIVE_ENTRIES
    max_member_bytes: int = MAX_ARCHIVE_MEMBER_BYTES
    max_total_bytes: int = MAX_ARCHIVE_TOTAL_BYTES
    max_compression_ratio: float = MAX_COMPRESSION_RATIO

    def __post_init__(self) -> None:
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if self.max_member_bytes < 0:
            raise ValueError("max_member_bytes must be non-negative")
        if self.max_total_bytes < 0:
            raise ValueError("max_total_bytes must be non-negative")
        if self.max_compression_ratio <= 0:
            raise ValueError("max_compression_ratio must be positive")


def _effective_limits(limits: ArchiveLimits | None) -> ArchiveLimits:
    if limits is not None:
        return limits
    # Construct this at call time to retain compatibility with callers/tests
    # that override the legacy module-level limits.
    return ArchiveLimits(
        max_entries=MAX_ARCHIVE_ENTRIES,
        max_member_bytes=MAX_ARCHIVE_MEMBER_BYTES,
        max_total_bytes=MAX_ARCHIVE_TOTAL_BYTES,
        max_compression_ratio=MAX_COMPRESSION_RATIO,
    )


def _portable_component_key(component: str) -> str:
    return unicodedata.normalize("NFC", component).casefold()


def _portable_path_key(name: str) -> str:
    return "/".join(_portable_component_key(part) for part in PurePosixPath(name).parts)


def normalized_member_name(name: str) -> str:
    """Return a portable POSIX-relative member name or raise.

    Backslashes are treated as separators because an archive may be created on
    one operating system and extracted on another. The returned value does not
    retain a directory entry's trailing slash; directory status comes from its
    :class:`zipfile.ZipInfo`.
    """

    if not isinstance(name, str):
        raise ArchiveSafetyError("archive member name must be text")
    if not name:
        raise ArchiveSafetyError("archive member name is empty")
    if "\x00" in name:
        raise ArchiveSafetyError("archive member contains NUL")

    normalized = name.replace("\\", "/")
    drive, _ = ntpath.splitdrive(name)
    if drive or normalized.startswith("/"):
        raise ArchiveSafetyError(f"absolute or drive-qualified archive member: {name!r}")

    raw_parts = normalized.split("/")
    if raw_parts[-1] == "":
        raw_parts = raw_parts[:-1]
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise ArchiveSafetyError(f"unsafe archive member path: {name!r}")

    for component in raw_parts:
        if any(ord(character) < 32 for character in component):
            raise ArchiveSafetyError(f"archive member contains a control character: {name!r}")
        if any(character in _WINDOWS_INVALID_CHARS for character in component):
            raise ArchiveSafetyError(f"archive member is not portable across filesystems: {name!r}")
        if component != component.rstrip(" ."):
            raise ArchiveSafetyError(f"archive member has a trailing dot or space: {name!r}")
        device_name = component.split(".", 1)[0].casefold()
        if device_name in _WINDOWS_RESERVED_NAMES:
            raise ArchiveSafetyError(f"archive member uses a reserved device name: {name!r}")

    return PurePosixPath(*raw_parts).as_posix()


def _member_is_directory(info: zipfile.ZipInfo) -> bool:
    name_is_directory = info.is_dir()
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    unix_type = stat.S_IFMT(unix_mode)
    dos_attributes = info.external_attr & 0xFFFF
    dos_is_directory = bool(dos_attributes & 0x10)

    if unix_type == stat.S_IFLNK:
        raise ArchiveSafetyError(f"symbolic-link archive member rejected: {info.filename!r}")
    if unix_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise ArchiveSafetyError(f"special-file archive member rejected: {info.filename!r}")
    if dos_attributes & _WINDOWS_REPARSE_POINT:
        raise ArchiveSafetyError(f"reparse-point archive member rejected: {info.filename!r}")

    metadata_is_directory = unix_type == stat.S_IFDIR or dos_is_directory
    if unix_type == stat.S_IFREG and name_is_directory:
        raise ArchiveSafetyError(f"conflicting archive member type: {info.filename!r}")
    is_directory = name_is_directory or metadata_is_directory
    if is_directory and info.file_size != 0:
        raise ArchiveSafetyError(f"directory archive member contains data: {info.filename!r}")
    return is_directory


def _validate_member_sizes(info: zipfile.ZipInfo, limits: ArchiveLimits) -> None:
    if info.file_size < 0 or info.compress_size < 0:
        raise ArchiveSafetyError(f"archive member has an invalid size: {info.filename!r}")
    if info.file_size > limits.max_member_bytes:
        raise ArchiveSafetyError(f"archive member exceeds size limit: {info.filename!r}")
    if info.file_size:
        if info.compress_size == 0:
            raise ArchiveSafetyError(f"archive member has an infinite compression ratio: {info.filename!r}")
        if info.file_size / info.compress_size > limits.max_compression_ratio:
            raise ArchiveSafetyError(f"archive member exceeds compression-ratio limit: {info.filename!r}")


def _inspect_archive_index(
    archive: zipfile.ZipFile,
    limits: ArchiveLimits,
) -> tuple[tuple[zipfile.ZipInfo, ...], dict[str, zipfile.ZipInfo]]:
    infos = tuple(archive.infolist())
    if len(infos) > limits.max_entries:
        raise ArchiveSafetyError(f"archive contains too many entries ({len(infos)} > {limits.max_entries})")

    total = 0
    by_key: dict[str, zipfile.ZipInfo] = {}
    entry_is_directory: dict[str, bool] = {}
    required_directories: set[str] = set()

    for info in infos:
        original_name = getattr(info, "orig_filename", info.filename)
        normalized = normalized_member_name(original_name)
        key = _portable_path_key(normalized)
        is_directory = _member_is_directory(info)

        if key in by_key:
            previous = by_key[key]
            raise ArchiveSafetyError(
                f"duplicate or aliased archive members: {previous.filename!r} and {info.filename!r}"
            )

        parts = PurePosixPath(normalized).parts
        for index in range(1, len(parts)):
            parent_key = "/".join(_portable_component_key(part) for part in parts[:index])
            if entry_is_directory.get(parent_key) is False:
                raise ArchiveSafetyError(f"archive file/directory conflict at {info.filename!r}")
            required_directories.add(parent_key)
        if not is_directory and key in required_directories:
            raise ArchiveSafetyError(f"archive file/directory conflict at {info.filename!r}")

        if info.flag_bits & 0x1:
            raise ArchiveSafetyError(f"encrypted archive member rejected: {info.filename!r}")
        _validate_member_sizes(info, limits)
        total += info.file_size
        if total > limits.max_total_bytes:
            raise ArchiveSafetyError(
                f"archive exceeds total uncompressed-size limit ({total} > {limits.max_total_bytes})"
            )

        by_key[key] = info
        entry_is_directory[key] = is_directory

    return infos, by_key


def inspect_archive(
    archive: zipfile.ZipFile,
    *,
    limits: ArchiveLimits | None = None,
) -> tuple[zipfile.ZipInfo, ...]:
    """Validate names, entry types, encryption, sizes, and compression ratios."""

    effective_limits = _effective_limits(limits)
    infos, _ = _inspect_archive_index(archive, effective_limits)
    return infos


def get_archive_member(
    archive: zipfile.ZipFile,
    member: str,
    *,
    limits: ArchiveLimits | None = None,
) -> zipfile.ZipInfo:
    """Return one validated member selected by its normalized portable name."""

    effective_limits = _effective_limits(limits)
    _, by_key = _inspect_archive_index(archive, effective_limits)
    key = _portable_path_key(normalized_member_name(member))
    info = by_key.get(key)
    if info is None:
        raise ArchiveSafetyError(f"archive member not found exactly once: {member!r}")
    return info


def _is_reparse_path(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if callable(is_junction) else False


def _reject_existing_reparse_components(root: Path, relative: Path) -> None:
    current = root
    if current.exists() and _is_reparse_path(current):
        raise ArchiveSafetyError(f"archive destination root is a link or junction: {root}")
    for part in relative.parts:
        current /= part
        if current.exists() and _is_reparse_path(current):
            raise ArchiveSafetyError(f"archive destination crosses a link or junction: {current}")


def _contained_destination(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ArchiveSafetyError(f"unsafe extraction destination: {relative}")

    root_absolute = root.absolute()
    _reject_existing_reparse_components(root_absolute, relative)
    root_resolved = root_absolute.resolve()
    destination = (root_absolute / relative).resolve()
    try:
        destination.relative_to(root_resolved)
    except ValueError:
        raise ArchiveSafetyError(f"archive destination escapes extraction root: {relative}") from None
    return destination


def resolve_member_destination(destination_root: Path, member: str) -> Path:
    """Resolve a member below ``destination_root`` and enforce containment."""

    normalized = normalized_member_name(member)
    relative = Path(*PurePosixPath(normalized).parts)
    return _contained_destination(Path(destination_root), relative)


def _ensure_explicit_destination_contained(destination: Path, root: Path | None) -> None:
    if root is None:
        return
    root_absolute = root.absolute()
    destination_absolute = destination.absolute()
    try:
        relative = destination_absolute.relative_to(root_absolute)
    except ValueError:
        raise ArchiveSafetyError(f"archive destination escapes extraction root: {destination}") from None
    _contained_destination(root_absolute, relative)


def _stream_info_to_path(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    *,
    limits: ArchiveLimits,
    destination_root: Path | None,
    total_written: list[int] | None = None,
) -> None:
    _ensure_explicit_destination_contained(destination, destination_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.is_dir():
        raise ArchiveSafetyError(f"archive file would replace a directory: {destination}")

    temporary_path: Path | None = None
    try:
        with (
            archive.open(info, "r") as source,
            tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as target,
        ):
            temporary_path = Path(target.name)
            copied = 0
            while True:
                chunk = source.read(_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > limits.max_member_bytes or copied > info.file_size:
                    raise ArchiveSafetyError("archive member exceeded extraction limit")
                if total_written is not None:
                    total_written[0] += len(chunk)
                    if total_written[0] > limits.max_total_bytes:
                        raise ArchiveSafetyError("archive exceeded total extraction limit")
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if copied != info.file_size:
            raise ArchiveSafetyError("archive member length did not match central directory")
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def extract_member_bounded(
    archive: zipfile.ZipFile,
    member: str,
    destination: Path,
    *,
    limits: ArchiveLimits | None = None,
    destination_root: Path | None = None,
) -> None:
    """Atomically extract one validated regular member with streaming limits."""

    effective_limits = _effective_limits(limits)
    info = get_archive_member(archive, member, limits=effective_limits)
    if _member_is_directory(info):
        raise ArchiveSafetyError(f"cannot extract a directory as a file: {member!r}")
    _stream_info_to_path(
        archive,
        info,
        Path(destination),
        limits=effective_limits,
        destination_root=Path(destination_root) if destination_root is not None else None,
    )


def extract_archive_bounded(
    archive: zipfile.ZipFile,
    destination_root: Path,
    *,
    limits: ArchiveLimits | None = None,
) -> tuple[Path, ...]:
    """Validate the whole archive, then stream every member below one root."""

    effective_limits = _effective_limits(limits)
    infos, _ = _inspect_archive_index(archive, effective_limits)
    root = Path(destination_root)
    root.mkdir(parents=True, exist_ok=True)
    if _is_reparse_path(root):
        raise ArchiveSafetyError(f"archive destination root is a link or junction: {root}")

    extracted: list[Path] = []
    total_written = [0]
    for info in infos:
        destination = resolve_member_destination(root, info.filename)
        if _member_is_directory(info):
            destination.mkdir(parents=True, exist_ok=True)
            resolve_member_destination(root, info.filename)
        else:
            _stream_info_to_path(
                archive,
                info,
                destination,
                limits=effective_limits,
                destination_root=root,
                total_written=total_written,
            )
        extracted.append(destination)
    return tuple(extracted)


def read_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    max_bytes: int,
    limits: ArchiveLimits | None = None,
) -> bytes:
    """Read one validated member into memory under a caller-specific cap."""

    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    effective_limits = _effective_limits(limits)
    selected = get_archive_member(archive, info.filename, limits=effective_limits)
    if selected is not info:
        # A ZipInfo supplied from another archive must never select by name.
        raise ArchiveSafetyError(f"archive member does not belong to this archive: {info.filename!r}")
    if _member_is_directory(info):
        raise ArchiveSafetyError(f"cannot read a directory as a file: {info.filename!r}")
    if info.file_size > max_bytes:
        raise ArchiveSafetyError(f"archive member exceeds parser limit: {info.filename!r}")

    chunks: list[bytes] = []
    size = 0
    with archive.open(info, "r") as source:
        while True:
            remaining_plus_one = max_bytes - size + 1
            chunk = source.read(min(_COPY_CHUNK_BYTES, remaining_plus_one))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes or size > info.file_size:
                raise ArchiveSafetyError("archive member exceeded parser read limit")
            chunks.append(chunk)
    if size != info.file_size:
        raise ArchiveSafetyError("archive member length did not match central directory")
    return b"".join(chunks)
