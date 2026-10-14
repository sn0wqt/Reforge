"""Unit and security boundary tests for pure-Python zero-dependency ASAR reader."""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
from pathlib import Path

import pytest

from reforge.utils.asar import (
    PICKLE_MAGIC,
    AsarError,
    AsarFormatError,
    AsarIntegrityError,
    AsarLimits,
    AsarReader,
    AsarSafetyError,
    AsarUnpackedUnavailableError,
    SubrangeReader,
    admit_asar_header,
    create_asar_bytes,
    pack_asar,
    read_asar_header_json,
)


def _make_raw_asar(
    json_str: str,
    payload: bytes = b"",
    *,
    magic: int = PICKLE_MAGIC,
    header_size_delta: int = 0,
    payload_size_delta: int = 0,
    json_bytes_override: int | None = None,
) -> bytes:
    """Helper to craft raw ASAR bytes with precise Pickle header field control."""
    text = json_str.encode("utf-8")
    padding = (4 - (len(text) % 4)) % 4
    padded = text + b"\x00" * padding

    header_size = 8 + len(padded) + header_size_delta
    payload_size = (header_size - 4) + payload_size_delta
    json_len = len(text) if json_bytes_override is None else json_bytes_override

    prefix = struct.pack("<4I", magic, header_size, payload_size, json_len)
    return prefix + padded + payload


# ---------------------------------------------------------------------------
# 1. Header Admission & Chromium Pickle Tests
# ---------------------------------------------------------------------------


def test_admit_header_accepts_valid_archive() -> None:
    raw = _make_raw_asar('{"files":{"test.txt":{"size":4,"offset":"0"}}}', b"1234")
    stream = io.BytesIO(raw)
    header_bytes, payload_bytes, json_bytes = admit_asar_header(stream, len(raw))

    assert header_bytes > 8
    assert payload_bytes == header_bytes - 4
    assert json_bytes <= payload_bytes - 4


def test_admit_header_rejects_truncated_file() -> None:
    stream = io.BytesIO(b"\x04\x00\x00\x00\x10\x00")
    with pytest.raises(AsarFormatError, match="less than 16 bytes"):
        admit_asar_header(stream, 6)


def test_admit_header_rejects_invalid_magic() -> None:
    raw = _make_raw_asar('{"files":{}}', magic=99)
    stream = io.BytesIO(raw)
    with pytest.raises(AsarFormatError, match="invalid ASAR size pickle"):
        admit_asar_header(stream, len(raw))


def test_admit_header_rejects_extents_leaving_container() -> None:
    # Header claims to be 1000 bytes, but archive is only 50 bytes
    raw = _make_raw_asar('{"files":{}}', header_size_delta=1000)
    stream = io.BytesIO(raw)
    with pytest.raises(AsarFormatError, match="leaves its container"):
        admit_asar_header(stream, 50)


def test_admit_header_rejects_invalid_pickle_extents() -> None:
    # Mismatched payload_bytes
    raw = _make_raw_asar('{"files":{}}', payload_size_delta=10)
    stream = io.BytesIO(raw)
    with pytest.raises(AsarFormatError, match="invalid pickle extents"):
        admit_asar_header(stream, len(raw))


def test_admit_header_rejects_json_exceeding_payload() -> None:
    # json_bytes claims to be larger than payload
    raw = _make_raw_asar('{"files":{}}', json_bytes_override=9999)
    stream = io.BytesIO(raw)
    with pytest.raises(AsarFormatError, match="invalid pickle extents"):
        admit_asar_header(stream, len(raw))


def test_admit_header_rejects_exceeding_decode_budget() -> None:
    raw = _make_raw_asar('{"files":{}}')
    stream = io.BytesIO(raw)
    with pytest.raises(AsarSafetyError, match="decode budget"):
        admit_asar_header(stream, len(raw), max_header_bytes=10)


def test_read_header_json_rejects_malformed_json() -> None:
    raw = _make_raw_asar("{not valid json!}")
    stream = io.BytesIO(raw)
    with pytest.raises(AsarFormatError, match="Malformed ASAR JSON"):
        read_asar_header_json(stream, len(raw))


def test_read_header_json_rejects_non_dict_root() -> None:
    raw = _make_raw_asar("[1, 2, 3]")
    stream = io.BytesIO(raw)
    with pytest.raises(AsarFormatError, match="not a JSON object"):
        read_asar_header_json(stream, len(raw))


# ---------------------------------------------------------------------------
# 2. Directory Listing & Path Safety Tests
# ---------------------------------------------------------------------------


def test_reader_rejects_root_without_files() -> None:
    raw = _make_raw_asar('{"other": 123}')
    with pytest.raises(AsarFormatError, match="has no files table"):
        AsarReader(io.BytesIO(raw))


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "",
        ".",
        "..",
        "sub/dir",
        r"sub\dir",
        "file\x00name",
        "control\x1fname",
        "colon:name",
        "pipe|name",
        "question?name",
        "asterisk*name",
        "trailing_dot.",
        "trailing_space ",
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "LPT1",
    ],
)
def test_reader_rejects_unsafe_path_components(unsafe_name: str) -> None:
    json_str = json.dumps({"files": {unsafe_name: {"size": 0, "offset": "0"}}})
    raw = _make_raw_asar(json_str)
    with pytest.raises(AsarSafetyError):
        AsarReader(io.BytesIO(raw))


def test_reader_rejects_entry_without_metadata() -> None:
    raw = _make_raw_asar('{"files":{"empty":{}}}')
    with pytest.raises(AsarFormatError, match="no directory, link or file metadata"):
        AsarReader(io.BytesIO(raw))


def test_reader_rejects_file_missing_offset() -> None:
    raw = _make_raw_asar('{"files":{"f1":{"size":10}}}')
    with pytest.raises(AsarFormatError, match="missing offset"):
        AsarReader(io.BytesIO(raw))


def test_reader_rejects_packed_file_negative_offset() -> None:
    raw = _make_raw_asar('{"files":{"f1":{"size":10,"offset":"-5"}}}')
    with pytest.raises(AsarFormatError, match="negative offset"):
        AsarReader(io.BytesIO(raw))


def test_reader_rejects_packed_file_out_of_bounds() -> None:
    # Offset + size goes beyond archive
    raw = _make_raw_asar('{"files":{"f1":{"size":1000,"offset":"0"}}}', b"short")
    with pytest.raises(AsarFormatError, match="outside its container"):
        AsarReader(io.BytesIO(raw))


def test_reader_enforces_max_entries_budget() -> None:
    files = {f"file_{i}.txt": f"data_{i}" for i in range(10)}
    archive_bytes, _ = create_asar_bytes(files)
    limits = AsarLimits(max_entries=5)
    with pytest.raises(AsarSafetyError, match="entries count exceeds limit"):
        AsarReader(io.BytesIO(archive_bytes), limits=limits)


def test_reader_enforces_max_listing_bytes_budget() -> None:
    files = {"nested/deeply/located/file.txt": "content"}
    archive_bytes, _ = create_asar_bytes(files)
    limits = AsarLimits(max_listing_bytes=100)
    with pytest.raises(AsarSafetyError, match="listing exceeds representation budget"):
        AsarReader(io.BytesIO(archive_bytes), limits=limits)


# ---------------------------------------------------------------------------
# 3. Packed Member Reads & Range-Stream Tests
# ---------------------------------------------------------------------------


def test_read_file_and_subranges() -> None:
    files: dict[str, bytes | str] = {
        "hello.txt": "Hello, ASAR world!",
        "nested/test.bin": b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
        "empty.txt": "",
    }
    archive_bytes, _ = create_asar_bytes(files)

    with AsarReader(io.BytesIO(archive_bytes)) as reader:
        # Full reads
        assert reader.read_file("hello.txt") == b"Hello, ASAR world!"
        assert reader.read_file("nested/test.bin") == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        assert reader.read_file("empty.txt") == b""

        # Subrange reads
        assert reader.read_file("hello.txt", offset=7, length=4) == b"ASAR"
        assert reader.read_file("hello.txt", offset=7) == b"ASAR world!"
        assert reader.read_file("hello.txt", offset=0, length=5) == b"Hello"
        assert reader.read_file("hello.txt", offset=100) == b""
        assert reader.read_file("hello.txt", offset=7, length=500) == b"ASAR world!"

        # Query normalization
        assert reader.read_file(r"nested\test.bin") == b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        assert reader.read_file("/hello.txt") == b"Hello, ASAR world!"

        # Boundaries
        with pytest.raises(ValueError, match="Offset must be non-negative"):
            reader.read_file("hello.txt", offset=-1)
        with pytest.raises(ValueError, match="Length must be non-negative"):
            reader.read_file("hello.txt", length=-1)
        with pytest.raises(KeyError):
            reader.read_file("nonexistent.txt")


def test_directory_and_symlink_member_checks() -> None:
    files = {"src/index.js": "console.log('main');"}
    symlinks = {"src/link.js": "index.js"}
    archive_bytes, _ = create_asar_bytes(files, symlinks=symlinks)

    with AsarReader(io.BytesIO(archive_bytes)) as reader:
        entries = reader.list_entries()
        assert len(entries) == 3
        paths = reader.list_paths()
        assert paths == ["src", "src/index.js", "src/link.js"]

        dir_entry = reader.get_entry("src")
        assert dir_entry.is_directory is True
        with pytest.raises(AsarFormatError, match="directory as file"):
            reader.read_file("src")

        link_entry = reader.get_entry("src/link.js")
        assert link_entry.is_symlink is True
        assert link_entry.link == "index.js"
        with pytest.raises(AsarFormatError, match="symlink as regular file"):
            reader.read_file("src/link.js")


def test_stream_file_yields_chunks() -> None:
    content = b"0123456789" * 1000  # 10,000 bytes
    archive_bytes, _ = create_asar_bytes({"large.bin": content})

    with AsarReader(io.BytesIO(archive_bytes)) as reader:
        chunks = list(reader.stream_file("large.bin", chunk_size=1024))
        assert len(chunks) == 10
        assert b"".join(chunks) == content

        # Subrange streaming
        slice_chunks = list(reader.stream_file("large.bin", offset=500, length=2500, chunk_size=1000))
        assert b"".join(slice_chunks) == content[500:3000]


def test_open_file_seekable_stream() -> None:
    content = b"abcdefghijklmnopqrstuvwxyz"
    archive_bytes, _ = create_asar_bytes({"alphabet.txt": content})

    with AsarReader(io.BytesIO(archive_bytes)) as reader, reader.open_file("alphabet.txt") as stream:
        assert stream.readable() is True
        assert stream.seekable() is True
        assert stream.writable() is False

        assert stream.read(4) == b"abcd"
        assert stream.tell() == 4
        stream.seek(10, os.SEEK_SET)
        assert stream.tell() == 10
        assert stream.read(5) == b"klmno"
        stream.seek(-3, os.SEEK_CUR)
        assert stream.read(3) == b"mno"
        stream.seek(-5, os.SEEK_END)
        assert stream.read() == b"vwxyz"


# ---------------------------------------------------------------------------
# 4. Companion .unpacked Directory Tests
# ---------------------------------------------------------------------------


def test_unpacked_member_reads_and_ranges(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "app.js": "const app = 1;",
        "native.node": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00native_code",
    }
    archive_path = tmp_path / "app.asar"
    unpacked_dir = tmp_path / "app.asar.unpacked"

    archive_bytes, unpacked_dict = create_asar_bytes(files, unpacked_files={"native.node"})
    archive_path.write_bytes(archive_bytes)

    unpacked_dir.mkdir()
    for rel_path, data in unpacked_dict.items():
        target = unpacked_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    with AsarReader(archive_path) as reader:
        # Check metadata
        entry = reader.get_entry("native.node")
        assert entry.unpacked is True
        assert entry.offset is None
        assert entry.data_offset is None

        # Read unpacked file
        assert reader.read_file("native.node") == files["native.node"]
        assert reader.read_file("native.node", offset=4, length=4) == b"\x02\x01\x01\x00"

        # Stream unpacked file
        chunks = list(reader.stream_file("native.node", chunk_size=4))
        assert b"".join(chunks) == files["native.node"]

        # Open unpacked stream
        with reader.open_file("native.node") as f:
            assert f.read(4) == b"\x7fELF"


def test_unpacked_companion_missing_raises_unavailable(tmp_path: Path) -> None:
    files = {"native.node": b"binary_data"}
    archive_path = tmp_path / "app.asar"
    archive_bytes, _ = create_asar_bytes(files, unpacked_files={"native.node"})
    archive_path.write_bytes(archive_bytes)
    # Note: companion .unpacked directory is NOT created

    with (
        AsarReader(archive_path) as reader,
        pytest.raises(AsarUnpackedUnavailableError, match="companion directory is missing"),
    ):
        reader.read_file("native.node")


def test_unpacked_member_missing_raises_unavailable(tmp_path: Path) -> None:
    files = {"native.node": b"binary_data"}
    archive_path = tmp_path / "app.asar"
    unpacked_dir = tmp_path / "app.asar.unpacked"
    archive_bytes, _ = create_asar_bytes(files, unpacked_files={"native.node"})
    archive_path.write_bytes(archive_bytes)
    unpacked_dir.mkdir()
    # native.node is missing inside unpacked_dir

    with (
        AsarReader(archive_path) as reader,
        pytest.raises(AsarUnpackedUnavailableError, match="member file is missing"),
    ):
        reader.read_file("native.node")


# ---------------------------------------------------------------------------
# 5. Integrity Verification Tests
# ---------------------------------------------------------------------------


def test_integrity_validation_success() -> None:
    code_text = "function test() { return 42; }"
    files: dict[str, bytes | str] = {
        "code.js": code_text,
        "data.bin": b"1234567890" * 100,
    }
    archive_bytes, _ = create_asar_bytes(files, include_integrity=True)

    with AsarReader(io.BytesIO(archive_bytes)) as reader:
        entry = reader.get_entry("code.js")
        assert entry.sha256 is not None
        assert entry.sha256 == hashlib.sha256(code_text.encode("utf-8")).hexdigest()

        # Both compute and verify match
        assert reader.compute_sha256("code.js") == entry.sha256
        assert reader.verify_integrity("code.js") is True
        assert reader.verify_integrity("data.bin") is True


def test_integrity_validation_tampered_fails() -> None:
    files = {"code.js": "original code"}
    archive_bytes, _ = create_asar_bytes(files, include_integrity=True)

    # Tamper with the packed payload byte
    tampered_bytes = bytearray(archive_bytes)
    tampered_bytes[-1] = ord("X")

    with AsarReader(io.BytesIO(tampered_bytes)) as reader:
        assert reader.verify_integrity("code.js", raise_on_mismatch=False) is False
        with pytest.raises(AsarIntegrityError, match="integrity mismatch"):
            reader.verify_integrity("code.js", raise_on_mismatch=True)


def test_integrity_validation_blocks_tampering() -> None:
    # 3 blocks of data with custom block_size
    block_size = 16
    data = b"A" * 16 + b"B" * 16 + b"C" * 16
    archive_bytes, _ = create_asar_bytes({"test.bin": data}, block_size=block_size)

    with AsarReader(io.BytesIO(archive_bytes)) as reader:
        assert reader.verify_integrity("test.bin") is True

    # Tamper with block 1
    tampered = bytearray(archive_bytes)
    # The payload starts after the header. Find "B" and change one
    idx = tampered.find(b"B")
    assert idx != -1
    tampered[idx] = ord("Z")

    with AsarReader(io.BytesIO(tampered)) as reader:
        assert reader.verify_integrity("test.bin", raise_on_mismatch=False) is False
        with pytest.raises(AsarIntegrityError, match="block integrity mismatch"):
            reader.verify_integrity("test.bin", raise_on_mismatch=True)


def test_unpacked_integrity_validation_tampered(tmp_path: Path) -> None:
    files = {"binary.node": b"valid_native_code"}
    archive_path = tmp_path / "app.asar"
    unpacked_dir = tmp_path / "app.asar.unpacked"

    archive_bytes, unpacked_dict = create_asar_bytes(files, unpacked_files={"binary.node"})
    archive_path.write_bytes(archive_bytes)

    unpacked_dir.mkdir()
    # Write stripped/tampered bytes into companion directory (common packaging behavior)
    (unpacked_dir / "binary.node").write_bytes(b"tampered_or_stripped_native_code")

    with AsarReader(archive_path) as reader:
        assert reader.verify_integrity("binary.node", raise_on_mismatch=False) is False
        with pytest.raises(AsarIntegrityError, match="integrity mismatch"):
            reader.verify_integrity("binary.node", raise_on_mismatch=True)


# ---------------------------------------------------------------------------
# 6. Extraction Tests
# ---------------------------------------------------------------------------


def test_extract_file_and_extract_all(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "index.html": "<h1>Hello</h1>",
        "scripts/main.js": "console.log('hi');",
        "assets/images/logo.png": b"\x89PNG\r\n\x1a\nlogo_data",
    }
    archive_path = tmp_path / "bundle.asar"
    archive_bytes, _ = create_asar_bytes(files)
    archive_path.write_bytes(archive_bytes)

    dest_dir = tmp_path / "extracted"

    with AsarReader(archive_path) as reader:
        # Extract single file
        single = reader.extract_file("scripts/main.js", dest_dir)
        assert single.exists()
        assert single.read_text(encoding="utf-8") == "console.log('hi');"

        # Duplicate extraction without overwrite raises
        with pytest.raises(FileExistsError):
            reader.extract_file("scripts/main.js", dest_dir, overwrite=False)

        # Overwrite works
        single_overwritten = reader.extract_file("scripts/main.js", dest_dir, overwrite=True)
        assert single_overwritten.exists()

        # Extract all
        all_extracted = reader.extract_all(dest_dir, overwrite=True)
        assert len(all_extracted) == 3
        assert (dest_dir / "index.html").read_text(encoding="utf-8") == "<h1>Hello</h1>"
        assert (dest_dir / "assets/images/logo.png").read_bytes() == b"\x89PNG\r\n\x1a\nlogo_data"


# ---------------------------------------------------------------------------
# 7. Pack ASAR Utility Tests
# ---------------------------------------------------------------------------


def test_pack_asar_on_disk(tmp_path: Path) -> None:
    src_dir = tmp_path / "source"
    src_dir.mkdir()
    (src_dir / "package.json").write_text('{"name": "test"}', encoding="utf-8")
    sub = src_dir / "lib"
    sub.mkdir()
    (sub / "util.js").write_text("module.exports = {};", encoding="utf-8")
    (sub / "addon.node").write_bytes(b"native_binary_module")

    out_asar = tmp_path / "output.asar"
    packed_path = pack_asar(src_dir, out_asar, unpack_patterns=["*.node"])

    assert packed_path.exists()
    assert (tmp_path / "output.asar.unpacked" / "lib" / "addon.node").exists()

    with AsarReader(packed_path) as reader:
        entries = reader.list_paths()
        assert "package.json" in entries
        assert "lib/util.js" in entries
        assert "lib/addon.node" in entries

        assert reader.read_file("package.json") == b'{"name": "test"}'
        assert reader.read_file("lib/util.js") == b"module.exports = {};"
        assert reader.read_file("lib/addon.node") == b"native_binary_module"

        assert reader.get_entry("lib/addon.node").unpacked is True
        assert reader.get_entry("lib/util.js").unpacked is False


# ---------------------------------------------------------------------------
# 8. SubrangeReader and Lifecycle Tests
# ---------------------------------------------------------------------------


def test_subrange_reader_seek_tell_boundaries() -> None:
    raw = io.BytesIO(b"0123456789ABCDEF")
    sub = SubrangeReader(raw, start=4, size=8)  # view over "456789AB"

    assert sub.tell() == 0
    assert sub.read(4) == b"4567"
    assert sub.tell() == 4

    sub.seek(2, os.SEEK_SET)
    assert sub.tell() == 2
    assert sub.read(2) == b"67"

    sub.seek(2, os.SEEK_CUR)
    assert sub.tell() == 6
    assert sub.read() == b"AB"
    assert sub.read() == b""

    sub.seek(-4, os.SEEK_END)
    assert sub.read() == b"89AB"

    with pytest.raises(ValueError, match="Negative seek"):
        sub.seek(-1, os.SEEK_SET)

    sub.close()
    with pytest.raises(ValueError, match="closed"):
        sub.read()


def test_reader_closed_lifecycle() -> None:
    archive_bytes, _ = create_asar_bytes({"test.txt": "hello"})
    reader = AsarReader(io.BytesIO(archive_bytes))
    assert reader.read_file("test.txt") == b"hello"
    reader.close()

    with pytest.raises(AsarError, match="closed"):
        reader.read_file("test.txt")
    with pytest.raises(AsarError, match="closed"):
        reader.open_file("test.txt")
    with pytest.raises(AsarError, match="closed"):
        list(reader.stream_file("test.txt"))
