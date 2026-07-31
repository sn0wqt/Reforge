"""Best-effort application identity discovery for artifact directory names."""

from __future__ import annotations

import os
import plistlib
import struct
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Final

from re_agent.utils.archives import (
    ArchiveSafetyError,
    inspect_archive,
    read_member_bounded,
)
from re_agent.utils.paths import safe_filename

_ANDROID_NS: Final[str] = "http://schemas.android.com/apk/res/android"
_MAX_MANIFEST_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_INFO_PLIST_BYTES: Final[int] = 8 * 1024 * 1024
_RES_STRING_POOL_TYPE: Final[int] = 0x0001
_RES_XML_START_ELEMENT_TYPE: Final[int] = 0x0102
_UTF8_FLAG: Final[int] = 0x00000100
_TYPE_STRING: Final[int] = 0x03
_NO_STRING: Final[int] = 0xFFFFFFFF
_GENERIC_NAMES: Final[frozenset[str]] = frozenset(
    {
        "android",
        "app",
        "application",
        "base",
        "debug",
        "index",
        "main",
        "release",
        "universal",
    }
)


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated binary XML")
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated binary XML")
    return int(struct.unpack_from("<I", data, offset)[0])


def _decode_length8(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        if offset + 1 >= len(data):
            raise ValueError("truncated UTF-8 string length")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _decode_length16(data: bytes, offset: int) -> tuple[int, int]:
    first = _u16(data, offset)
    if first & 0x8000:
        return ((first & 0x7FFF) << 16) | _u16(data, offset + 2), offset + 4
    return first, offset + 2


def _parse_string_pool(data: bytes, chunk_offset: int) -> list[str]:
    header_size = _u16(data, chunk_offset + 2)
    chunk_size = _u32(data, chunk_offset + 4)
    string_count = _u32(data, chunk_offset + 8)
    flags = _u32(data, chunk_offset + 16)
    strings_start = _u32(data, chunk_offset + 20)
    chunk_end = chunk_offset + chunk_size
    if (
        header_size < 28
        or chunk_size < header_size
        or chunk_end > len(data)
        or string_count > 1_000_000
        or header_size + (string_count * 4) > chunk_size
    ):
        raise ValueError("invalid binary XML string pool")

    strings: list[str] = []
    utf8 = bool(flags & _UTF8_FLAG)
    for index in range(string_count):
        relative = _u32(data, chunk_offset + header_size + (index * 4))
        cursor = chunk_offset + strings_start + relative
        if not chunk_offset <= cursor < chunk_end:
            raise ValueError("invalid binary XML string offset")
        if utf8:
            _, cursor = _decode_length8(data, cursor)
            byte_length, cursor = _decode_length8(data, cursor)
            end = cursor + byte_length
            if end > chunk_end:
                raise ValueError("truncated binary XML UTF-8 string")
            strings.append(data[cursor:end].decode("utf-8", errors="replace"))
        else:
            code_units, cursor = _decode_length16(data, cursor)
            end = cursor + (code_units * 2)
            if end > chunk_end:
                raise ValueError("truncated binary XML UTF-16 string")
            strings.append(data[cursor:end].decode("utf-16le", errors="replace"))
    return strings


def _pool_string(strings: list[str], index: int) -> str | None:
    return strings[index] if index != _NO_STRING and 0 <= index < len(strings) else None


def _binary_android_manifest_identity(data: bytes) -> tuple[str | None, str | None]:
    """Return ``(display_name, package_name)`` from Android binary XML."""

    if len(data) < 8 or _u16(data, 0) != 0x0003:
        return None, None
    root_header_size = _u16(data, 2)
    root_size = min(_u32(data, 4), len(data))
    if root_header_size < 8 or root_header_size > root_size:
        return None, None

    strings: list[str] | None = None
    display_name: str | None = None
    package_name: str | None = None
    offset = root_header_size
    while offset + 8 <= root_size:
        chunk_type = _u16(data, offset)
        header_size = _u16(data, offset + 2)
        chunk_size = _u32(data, offset + 4)
        if header_size < 8 or chunk_size < header_size or offset + chunk_size > root_size:
            break
        if chunk_type == _RES_STRING_POOL_TYPE and strings is None:
            strings = _parse_string_pool(data, offset)
        elif (
            chunk_type == _RES_XML_START_ELEMENT_TYPE
            and strings is not None
            and header_size >= 16
            and chunk_size >= 36
        ):
            element_name = _pool_string(strings, _u32(data, offset + 20))
            attribute_start = _u16(data, offset + 24)
            attribute_size = _u16(data, offset + 26)
            attribute_count = _u16(data, offset + 28)
            attributes_offset = offset + 16 + attribute_start
            if attribute_size < 20 or attributes_offset < offset + header_size:
                offset += chunk_size
                continue
            if attributes_offset + (attribute_size * attribute_count) > offset + chunk_size:
                offset += chunk_size
                continue
            for index in range(attribute_count):
                attribute_offset = attributes_offset + (index * attribute_size)
                name = _pool_string(strings, _u32(data, attribute_offset + 4))
                raw_value = _pool_string(strings, _u32(data, attribute_offset + 8))
                value_type = data[attribute_offset + 15]
                typed_value = _u32(data, attribute_offset + 16)
                value = raw_value
                if value is None and value_type == _TYPE_STRING:
                    value = _pool_string(strings, typed_value)
                if element_name == "manifest" and name == "package" and value:
                    package_name = value
                elif (
                    element_name == "application"
                    and name == "label"
                    and value
                    and not value.startswith("@")
                ):
                    display_name = value
        offset += chunk_size
    return display_name, package_name


def _text_android_manifest_identity(data: bytes) -> tuple[str | None, str | None]:
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return None, None
    package_name = root.attrib.get("package")
    application = root.find("application")
    display_name = None
    if application is not None:
        display_name = application.attrib.get(f"{{{_ANDROID_NS}}}label")
        if display_name and display_name.startswith("@"):
            display_name = None
    return display_name, package_name


def _android_archive_identity(path: Path) -> tuple[str | None, str | None]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = inspect_archive(archive)
            manifest = next(
                (
                    info
                    for info in infos
                    if info.filename.replace("\\", "/").casefold() == "androidmanifest.xml"
                ),
                None,
            )
            if manifest is None:
                return None, None
            data = read_member_bounded(archive, manifest, max_bytes=_MAX_MANIFEST_BYTES)
    except (ArchiveSafetyError, OSError, zipfile.BadZipFile):
        return None, None

    try:
        if data.lstrip().startswith(b"<"):
            return _text_android_manifest_identity(data)
        return _binary_android_manifest_identity(data)
    except (IndexError, UnicodeError, ValueError):
        return None, None


def _ios_archive_identity(path: Path) -> tuple[str | None, str | None]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = inspect_archive(archive)
            info_plists = sorted(
                (
                    info
                    for info in infos
                    if info.filename.replace("\\", "/").casefold().startswith("payload/")
                    and info.filename.replace("\\", "/").casefold().endswith(".app/info.plist")
                ),
                key=lambda info: (info.filename.count("/"), info.filename.casefold()),
            )
            if not info_plists:
                return None, None
            data = read_member_bounded(
                archive,
                info_plists[0],
                max_bytes=_MAX_INFO_PLIST_BYTES,
            )
        plist = plistlib.loads(data)
    except (
        ArchiveSafetyError,
        OSError,
        ValueError,
        TypeError,
        zipfile.BadZipFile,
        plistlib.InvalidFileException,
    ):
        return None, None
    if not isinstance(plist, dict):
        return None, None
    display_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName")
    bundle_id = plist.get("CFBundleIdentifier")
    return (
        display_name if isinstance(display_name, str) else None,
        bundle_id if isinstance(bundle_id, str) else None,
    )


def _identifier_name(identifier: str | None) -> str | None:
    if not identifier:
        return None
    parts = [part for part in identifier.rsplit(".", maxsplit=8) if part]
    for part in reversed(parts):
        if part.casefold() not in _GENERIC_NAMES and len(part) > 1:
            return part
    return parts[-1] if parts else None


def detect_application_name(path: str | Path) -> str:
    """Detect a stable, filesystem-safe application name from an input artifact."""

    target = Path(path)
    display_name: str | None = None
    identifier: str | None = None
    if target.is_file() and target.suffix.casefold() == ".apk":
        display_name, identifier = _android_archive_identity(target)
    elif target.is_file() and target.suffix.casefold() == ".ipa":
        display_name, identifier = _ios_archive_identity(target)

    candidate = display_name or _identifier_name(identifier)
    if not candidate:
        stem = target.name if target.is_dir() else target.stem
        if stem.casefold() in _GENERIC_NAMES and target.parent.name:
            stem = target.parent.name
        candidate = stem
    return safe_filename(candidate)


def default_pipeline_output_dir(
    input_path: str | Path,
    *,
    desktop_root: Path | None = None,
) -> Path:
    """Return the conventional Desktop ``<app-name>_output`` directory."""

    if desktop_root is None:
        user_home = Path(os.environ.get("USERPROFILE") or Path.home())
        desktop_root = user_home / "Desktop"
    return desktop_root / f"{detect_application_name(input_path)}_output"
