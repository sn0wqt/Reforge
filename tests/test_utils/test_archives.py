"""Adversarial archive validation and bounded extraction tests."""

from __future__ import annotations

import io
import os
import stat
import zipfile
from pathlib import Path

import pytest

from re_agent.utils.archives import (
    ArchiveLimits,
    ArchiveSafetyError,
    extract_archive_bounded,
    extract_member_bounded,
    inspect_archive,
    normalized_member_name,
    read_member_bounded,
    resolve_member_destination,
)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "\x00evil",
        "../assets/index.android.bundle",
        r"..\assets\index.android.bundle",
        "/absolute/file",
        r"\rooted\file",
        "C:/drive/file",
        r"C:\drive\file",
        "C:drive-relative",
        r"\\server\share\file",
        "a/../../b",
        "a/./b",
        "a//b",
        "a/CON.txt",
        "a/trailing.",
        "a/trailing ",
        "a/file:stream",
        "a/control\x1fchar",
    ],
)
def test_archive_member_unsafe_or_nonportable_paths_are_rejected(name: str) -> None:
    with pytest.raises(ArchiveSafetyError):
        normalized_member_name(name)


def test_archive_member_name_normalizes_separators_and_directory_suffix() -> None:
    assert normalized_member_name(r"assets\nested\file.bin") == "assets/nested/file.bin"
    assert normalized_member_name("assets/nested/") == "assets/nested"


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("classes.dex", "classes.dex"),
        ("Assets/File.bin", "assets/file.bin"),
        (r"assets\nested\file.bin", "assets/nested/file.bin"),
        ("café.bin", "cafe\u0301.bin"),
        ("directory", "directory/"),
    ],
)
def test_archive_duplicate_or_aliased_members_are_rejected(
    tmp_path: Path,
    first: str,
    second: str,
) -> None:
    path = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(first, b"one")
        archive.writestr(second, b"two")

    with zipfile.ZipFile(path) as archive, pytest.raises(ArchiveSafetyError):
        inspect_archive(archive)


@pytest.mark.parametrize(
    "members",
    [
        (("parent", b"file"), ("parent/child", b"child")),
        (("parent/child", b"child"), ("parent", b"file")),
    ],
)
def test_archive_file_directory_conflicts_are_rejected(
    tmp_path: Path,
    members: tuple[tuple[str, bytes], tuple[str, bytes]],
) -> None:
    path = tmp_path / "conflict.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)

    with (
        zipfile.ZipFile(path) as archive,
        pytest.raises(
            ArchiveSafetyError,
            match="file/directory conflict",
        ),
    ):
        inspect_archive(archive)


def test_archive_symbolic_link_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(link, "../outside")

    with (
        zipfile.ZipFile(path) as archive,
        pytest.raises(
            ArchiveSafetyError,
            match="symbolic-link",
        ),
    ):
        inspect_archive(archive)


def test_archive_special_file_is_rejected() -> None:
    info = zipfile.ZipInfo("pipe")
    info.create_system = 3
    info.external_attr = (stat.S_IFIFO | 0o600) << 16

    class SpecialArchive:
        def infolist(self):
            return [info]

    with pytest.raises(ArchiveSafetyError, match="special-file"):
        inspect_archive(SpecialArchive())  # type: ignore[arg-type]


def test_archive_windows_reparse_entry_is_rejected() -> None:
    info = zipfile.ZipInfo("junction")
    info.create_system = 0
    info.external_attr = 0x0400

    class ReparseArchive:
        def infolist(self):
            return [info]

    with pytest.raises(ArchiveSafetyError, match="reparse-point"):
        inspect_archive(ReparseArchive())  # type: ignore[arg-type]


def test_archive_encrypted_member_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("secret.bin", b"secret")

    with zipfile.ZipFile(path) as archive:
        archive.infolist()[0].flag_bits |= 0x1
        with pytest.raises(ArchiveSafetyError, match="encrypted"):
            inspect_archive(archive)


def test_archive_resource_limits_are_configurable(tmp_path: Path) -> None:
    path = tmp_path / "limits.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("one.bin", b"123")
        archive.writestr("two.bin", b"456")

    with zipfile.ZipFile(path) as archive:
        with pytest.raises(ArchiveSafetyError, match="too many entries"):
            inspect_archive(archive, limits=ArchiveLimits(max_entries=1))
        with pytest.raises(ArchiveSafetyError, match="member exceeds size"):
            inspect_archive(
                archive,
                limits=ArchiveLimits(max_member_bytes=2),
            )
        with pytest.raises(ArchiveSafetyError, match="total uncompressed-size"):
            inspect_archive(
                archive,
                limits=ArchiveLimits(max_total_bytes=5),
            )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_entries": 0},
        {"max_member_bytes": -1},
        {"max_total_bytes": -1},
        {"max_compression_ratio": 0},
    ],
)
def test_archive_limits_reject_invalid_values(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        ArchiveLimits(**kwargs)


def test_archive_extreme_compression_ratio_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/index.android.bundle", b"\0" * 2_000_000)

    with (
        zipfile.ZipFile(path) as archive,
        pytest.raises(
            ArchiveSafetyError,
            match="compression-ratio",
        ),
    ):
        inspect_archive(archive, limits=ArchiveLimits(max_compression_ratio=100))


def test_nonempty_member_with_zero_compressed_size_is_rejected() -> None:
    info = zipfile.ZipInfo("impossible.bin")
    info.file_size = 1
    info.compress_size = 0

    class ImpossibleArchive:
        def infolist(self):
            return [info]

    with pytest.raises(ArchiveSafetyError, match="infinite compression ratio"):
        inspect_archive(ImpossibleArchive())  # type: ignore[arg-type]


def test_extract_archive_streams_nested_members_below_root(tmp_path: Path) -> None:
    path = tmp_path / "safe.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("assets/", b"")
        archive.writestr("assets/config.json", b'{"safe": true}')
        archive.writestr("classes.dex", b"dex\n")

    destination = tmp_path / "unpacked"
    with zipfile.ZipFile(path) as archive:
        extracted = extract_archive_bounded(archive, destination)

    assert (destination / "assets" / "config.json").read_bytes() == b'{"safe": true}'
    assert (destination / "classes.dex").read_bytes() == b"dex\n"
    assert len(extracted) == 3
    assert all(path.resolve().is_relative_to(destination.resolve()) for path in extracted)


def test_explicit_destination_must_stay_inside_declared_root(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("file.bin", b"safe")

    root = tmp_path / "root"
    outside = tmp_path / "outside.bin"
    with (
        zipfile.ZipFile(archive_path) as archive,
        pytest.raises(
            ArchiveSafetyError,
            match="escapes extraction root",
        ),
    ):
        extract_member_bounded(
            archive,
            "file.bin",
            outside,
            destination_root=root,
        )
    assert not outside.exists()


def test_resolved_destination_rejects_existing_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    try:
        os.symlink(outside, root / "linked", target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(ArchiveSafetyError, match="link or junction"):
        resolve_member_destination(root, "linked/file.bin")


def test_failed_streaming_extraction_is_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    info = zipfile.ZipInfo("assets/index.android.bundle")
    info.file_size = 1
    info.compress_size = 1

    class OversizedArchive:
        def infolist(self):
            return [info]

        def open(self, selected, mode):
            assert selected is info
            assert mode == "r"
            return io.BytesIO(b"xx")

    monkeypatch.setattr("re_agent.utils.archives.MAX_ARCHIVE_MEMBER_BYTES", 1)
    destination = tmp_path / "bundle.js"
    destination.write_bytes(b"existing")

    with pytest.raises(ArchiveSafetyError, match="exceeded extraction limit"):
        extract_member_bounded(OversizedArchive(), info.filename, destination)  # type: ignore[arg-type]

    assert destination.read_bytes() == b"existing"
    assert not list(tmp_path.glob(".bundle.js.*.tmp"))


def test_read_member_bounded_enforces_caller_cap_and_identity(tmp_path: Path) -> None:
    first_path = tmp_path / "first.zip"
    second_path = tmp_path / "second.zip"
    for path in (first_path, second_path):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("value.bin", b"1234")

    with zipfile.ZipFile(first_path) as first, zipfile.ZipFile(second_path) as second:
        first_info = first.infolist()[0]
        second_info = second.infolist()[0]
        assert read_member_bounded(first, first_info, max_bytes=4) == b"1234"
        with pytest.raises(ArchiveSafetyError, match="parser limit"):
            read_member_bounded(first, first_info, max_bytes=3)
        with pytest.raises(ArchiveSafetyError, match="does not belong"):
            read_member_bounded(first, second_info, max_bytes=4)
