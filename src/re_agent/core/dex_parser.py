"""Pure-Python Android DEX (.dex / .apk) parser for Java/Kotlin class and method recovery."""
from __future__ import annotations

import logging
import struct
import zipfile
from pathlib import Path
from typing import Any

from re_agent.utils.archives import ArchiveSafetyError, inspect_archive, read_member_bounded

logger = logging.getLogger(__name__)
MAX_DEX_BYTES = 268_435_456


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int] | None:
    """Read one bounded unsigned LEB128 value."""
    value = 0
    for index in range(5):
        position = offset + index
        if position >= len(data):
            return None
        byte = data[position]
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, position + 1
    return None


def _descriptor_to_frida_type(descriptor: str) -> str | None:
    """Convert one DEX type descriptor to the name expected by Frida."""
    primitive_types = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    if descriptor in primitive_types:
        return primitive_types[descriptor]
    if descriptor.startswith("L") and descriptor.endswith(";") and len(descriptor) > 2:
        return descriptor[1:-1].replace("/", ".")
    if descriptor.startswith("["):
        component = descriptor.lstrip("[")
        if not component or _descriptor_to_frida_type(component) is None:
            return None
        # Frida overloads use JNI array spellings, with dotted object names.
        return descriptor.replace("/", ".")
    return None


def _read_proto_parameters(
    dex_bytes: bytes,
    parameters_off: int,
    types: list[str],
) -> tuple[str, ...] | None:
    """Read a DEX ``type_list`` without trusting its declared length."""
    if parameters_off == 0:
        return ()
    if parameters_off > len(dex_bytes) - 4:
        return None
    parameter_count = struct.unpack_from("<I", dex_bytes, parameters_off)[0]
    if parameter_count > 65_535:
        return None
    byte_count = parameter_count * 2
    start = parameters_off + 4
    if byte_count > len(dex_bytes) - start:
        return None
    descriptors: list[str] = []
    for index in range(parameter_count):
        type_index = struct.unpack_from("<H", dex_bytes, start + index * 2)[0]
        if type_index >= len(types) or _descriptor_to_frida_type(types[type_index]) is None:
            return None
        descriptors.append(types[type_index])
    return tuple(descriptors)


def parse_dex_file(dex_bytes: bytes) -> list[dict[str, Any]]:
    """Parse a single DEX binary byte array to extract classes, methods, and descriptors."""
    if len(dex_bytes) < 112 or not dex_bytes.startswith(b"dex\n"):
        return []
    if len(dex_bytes) > MAX_DEX_BYTES:
        return []

    try:
        declared_size, header_size, endian_tag = struct.unpack("<III", dex_bytes[32:44])
        if declared_size != len(dex_bytes) or header_size != 112 or endian_tag != 0x12345678:
            return []
        string_ids_size, string_ids_off = struct.unpack("<II", dex_bytes[56:64])
        type_ids_size, type_ids_off = struct.unpack("<II", dex_bytes[64:72])
        proto_ids_size, proto_ids_off = struct.unpack("<II", dex_bytes[72:80])
        field_ids_size, field_ids_off = struct.unpack("<II", dex_bytes[80:88])
        method_ids_size, method_ids_off = struct.unpack("<II", dex_bytes[88:96])
        class_defs_size, class_defs_off = struct.unpack("<II", dex_bytes[96:104])
        table_specs = (
            (string_ids_size, string_ids_off, 4),
            (type_ids_size, type_ids_off, 4),
            (proto_ids_size, proto_ids_off, 12),
            (field_ids_size, field_ids_off, 8),
            (method_ids_size, method_ids_off, 8),
            (class_defs_size, class_defs_off, 32),
        )
        if any(
            size > 2_000_000
            or offset > len(dex_bytes)
            or size * width > len(dex_bytes) - offset
            for size, offset, width in table_specs
        ):
            return []

        # 1. Read String Table
        strings: list[str] = []
        for i in range(string_ids_size):
            off_pos = string_ids_off + i * 4
            if off_pos + 4 > len(dex_bytes):
                break
            str_off = struct.unpack("<I", dex_bytes[off_pos : off_pos + 4])[0]
            if str_off >= len(dex_bytes):
                strings.append("")
                continue
            pos = str_off
            length = 0
            shift = 0
            uleb_count = 0
            while pos < len(dex_bytes) and uleb_count < 5:
                b = dex_bytes[pos]
                pos += 1
                uleb_count += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            else:
                strings.append("")
                continue
            end = pos + min(length * 3, 500)
            str_data = dex_bytes[pos:end].split(b"\x00")[0]
            try:
                strings.append(str_data.decode("utf-8", errors="ignore"))
            except Exception:
                strings.append("")

        # 2. Read Type Table
        types: list[str] = []
        for i in range(type_ids_size):
            off_pos = type_ids_off + i * 4
            if off_pos + 4 > len(dex_bytes):
                break
            descriptor_idx = struct.unpack("<I", dex_bytes[off_pos : off_pos + 4])[0]
            if descriptor_idx < len(strings):
                types.append(strings[descriptor_idx])
            else:
                types.append("")

        # 3. Read Prototype Table. Retain one entry per proto_idx, including
        # invalid entries, so malformed evidence cannot shift later indices.
        prototypes: list[dict[str, Any] | None] = []
        for i in range(proto_ids_size):
            off_pos = proto_ids_off + i * 12
            shorty_idx, return_type_idx, parameters_off = struct.unpack_from(
                "<III",
                dex_bytes,
                off_pos,
            )
            del shorty_idx  # The full type descriptors below are authoritative.
            if return_type_idx >= len(types):
                prototypes.append(None)
                continue
            return_descriptor = types[return_type_idx]
            return_type = _descriptor_to_frida_type(return_descriptor)
            parameter_descriptors = _read_proto_parameters(
                dex_bytes,
                parameters_off,
                types,
            )
            if return_type is None or parameter_descriptors is None:
                prototypes.append(None)
                continue
            parameter_types = tuple(
                type_name
                for descriptor in parameter_descriptors
                if (type_name := _descriptor_to_frida_type(descriptor)) is not None
            )
            if len(parameter_types) != len(parameter_descriptors):
                prototypes.append(None)
                continue
            prototypes.append(
                {
                    "descriptor": f"({''.join(parameter_descriptors)}){return_descriptor}",
                    "parameter_types": parameter_types,
                    "return_type": return_type,
                }
            )

        # 4. Read Method Table
        method_definitions: dict[int, dict[str, Any]] = {}
        for class_def_index in range(class_defs_size):
            class_def_offset = class_defs_off + class_def_index * 32
            (
                class_idx,
                _class_access,
                _superclass_idx,
                _interfaces_off,
                _source_file_idx,
                _annotations_off,
                class_data_off,
                _static_values_off,
            ) = struct.unpack_from("<IIIIIIII", dex_bytes, class_def_offset)
            if class_idx >= len(types) or class_data_off == 0:
                continue
            if class_data_off >= len(dex_bytes):
                return []
            cursor = class_data_off
            counts: list[int] = []
            for _count_index in range(4):
                parsed = _read_uleb128(dex_bytes, cursor)
                if parsed is None:
                    return []
                count, cursor = parsed
                if count > 2_000_000:
                    return []
                counts.append(count)
            static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size = counts

            # Fields do not carry object-layout offsets in DEX. Advance over
            # them without manufacturing native offsets.
            for _field_index in range(static_fields_size + instance_fields_size):
                field_diff = _read_uleb128(dex_bytes, cursor)
                if field_diff is None:
                    return []
                _field_index_diff, cursor = field_diff
                field_access = _read_uleb128(dex_bytes, cursor)
                if field_access is None:
                    return []
                _access_flags, cursor = field_access

            for method_count, method_kind in (
                (direct_methods_size, "direct"),
                (virtual_methods_size, "virtual"),
            ):
                method_index = 0
                for _method_number in range(method_count):
                    method_diff = _read_uleb128(dex_bytes, cursor)
                    if method_diff is None:
                        return []
                    method_index_diff, cursor = method_diff
                    method_index += method_index_diff
                    access = _read_uleb128(dex_bytes, cursor)
                    if access is None:
                        return []
                    access_flags, cursor = access
                    code = _read_uleb128(dex_bytes, cursor)
                    if code is None:
                        return []
                    code_off, cursor = code
                    if method_index >= method_ids_size or code_off >= len(dex_bytes):
                        return []
                    if method_index in method_definitions:
                        return []
                    is_native = bool(access_flags & 0x100)
                    is_abstract = bool(access_flags & 0x400)
                    method_definitions[method_index] = {
                        "declaring_class_idx": class_idx,
                        "access_flags": access_flags,
                        "code_off": code_off,
                        "method_kind": method_kind,
                        "is_static": bool(access_flags & 0x8),
                        "is_native": is_native,
                        "is_abstract": is_abstract,
                        "is_constructor": bool(access_flags & 0x10000),
                        "is_executable": (code_off > 0 or is_native) and not is_abstract,
                    }

        methods: list[dict[str, Any]] = []
        for i in range(method_ids_size):
            off_pos = method_ids_off + i * 8
            if off_pos + 8 > len(dex_bytes):
                break
            class_idx, proto_idx, name_idx = struct.unpack("<HHI", dex_bytes[off_pos : off_pos + 8])
            raw_cls = types[class_idx] if class_idx < len(types) else ""
            m_name = strings[name_idx] if name_idx < len(strings) else ""
            prototype = prototypes[proto_idx] if proto_idx < len(prototypes) else None
            definition = method_definitions.get(i)

            # Format Lcom/example/ClassName; -> com.example.ClassName
            clean_cls = raw_cls.strip(";").lstrip("L").replace("/", ".")
            framework_prefixes = (
                "android.", "java.", "javax.", "kotlin.", "kotlinx.", "androidx.",
                "com.google.", "com.facebook.", "io.sentry.", "org.apache.", "org.json.",
                "com.squareup.", "com.appsflyer.", "com.adjust.", "com.unity3d.", "com.android.",
                "com.amazon.", "com.amplitude.", "com.braze.", "com.onesignal.",
            )
            if not clean_cls or clean_cls.startswith(framework_prefixes):
                continue

            methods.append(
                {
                    "class_name": clean_cls,
                    "method_name": m_name,
                    "class_descriptor": raw_cls,
                    "raw_descriptor": prototype["descriptor"] if prototype else "",
                    "descriptor": prototype["descriptor"] if prototype else "",
                    "parameter_types": (
                        prototype["parameter_types"] if prototype else ()
                    ),
                    "return_type": prototype["return_type"] if prototype else "",
                    "is_declared": definition is not None,
                    "is_executable": (
                        bool(definition["is_executable"]) if definition else False
                    ),
                    "is_static": (
                        bool(definition["is_static"]) if definition else None
                    ),
                    "is_native": (
                        bool(definition["is_native"]) if definition else False
                    ),
                    "is_abstract": (
                        bool(definition["is_abstract"]) if definition else False
                    ),
                    "is_constructor": (
                        bool(definition["is_constructor"]) if definition else False
                    ),
                    "access_flags": (
                        int(definition["access_flags"]) if definition else None
                    ),
                    "code_off": int(definition["code_off"]) if definition else None,
                }
            )

        return methods
    except Exception as exc:
        logger.warning("[DEXParser] Failed parsing dex bytes: %s", exc)
        return []


def parse_apk_or_dex(target_path: str | Path) -> dict[str, Any]:
    """Extract all Java/Kotlin classes and methods from an APK or .dex file."""
    path = Path(target_path)
    if not path.exists():
        return {"classes": {}, "methods": []}

    all_methods: list[dict[str, Any]] = []
    class_map: dict[str, list[dict[str, Any]]] = {}

    if path.suffix.lower() == ".apk" or zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as z:
                for info in inspect_archive(z):
                    if info.filename.endswith(".dex"):
                        dex_bytes = read_member_bounded(z, info, max_bytes=MAX_DEX_BYTES)
                        methods = parse_dex_file(dex_bytes)
                        all_methods.extend(methods)
        except (ArchiveSafetyError, OSError, zipfile.BadZipFile) as e:
            logger.warning("[DEXParser] Zip error reading APK %s: %s", path, e)
    elif path.suffix.lower() == ".dex":
        try:
            if path.stat().st_size > MAX_DEX_BYTES:
                raise ValueError("DEX exceeds parser size limit")
            dex_bytes = path.read_bytes()
            all_methods = parse_dex_file(dex_bytes)
        except Exception as e:
            logger.warning("[DEXParser] Error reading DEX %s: %s", path, e)

    # Referenced method IDs are not hookable definitions. Retain them for
    # diagnostics, but expose only declared executable methods as candidates.
    method_references = list(all_methods)
    all_methods = [
        method
        for method in all_methods
        if method.get("is_declared") is True
        and method.get("is_executable") is True
    ]

    # Group executable methods by class name.
    for m in all_methods:
        cls_name = m["class_name"]
        class_map.setdefault(cls_name, []).append(m)

    return {
        "classes": class_map,
        "methods": all_methods,
        "method_references": method_references,
    }
