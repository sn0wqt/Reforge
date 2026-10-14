from __future__ import annotations

import zipfile
from argparse import Namespace
from pathlib import Path

import pytest

from reforge.cli.cmd_pipeline import cmd_pipeline
from reforge.packaging.split_apks import (
    SplitApkError,
    resolve_android_package_set,
    validate_installer_package,
    write_split_deployment_artifacts,
)


def _write_apk(path: Path, *, package: str, dex: bool) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", f'<manifest package="{package}" />')
        if dex:
            archive.writestr("classes.dex", b"dex\n035\x00")


def test_resolves_base_and_config_splits_from_outer_archive(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    base = source_dir / "base.apk"
    abi = source_dir / "split_config.arm64_v8a.apk"
    language = source_dir / "split_config.en.apk"
    _write_apk(base, package="com.example.app", dex=True)
    _write_apk(abi, package="com.example.app", dex=False)
    _write_apk(language, package="com.example.app", dex=False)
    outer = tmp_path / "bundle.xapk"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.write(base, "base.apk")
        archive.write(abi, "splits/split_config.arm64_v8a.apk")
        archive.write(language, "splits/split_config.en.apk")

    package_set = resolve_android_package_set(outer, tmp_path / "extracted")

    assert package_set is not None
    assert package_set.base_apk.name.endswith("base.apk")
    assert len(package_set.split_apks) == 2
    assert package_set.source_kind == "archive"


def test_rejects_cross_package_and_executable_feature_splits(tmp_path: Path) -> None:
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    _write_apk(package_dir / "base.apk", package="com.example.app", dex=True)
    _write_apk(package_dir / "split_config.en.apk", package="com.other.app", dex=False)

    with pytest.raises(SplitApkError, match="identifiers do not match"):
        resolve_android_package_set(package_dir, tmp_path / "unused")

    (package_dir / "split_config.en.apk").unlink()
    _write_apk(package_dir / "feature-chat.apk", package="com.example.app", dex=True)
    with pytest.raises(SplitApkError, match="Dynamic-feature"):
        resolve_android_package_set(package_dir, tmp_path / "unused")


def test_deployment_notes_are_explicit_about_installer_metadata(tmp_path: Path) -> None:
    install_dir = tmp_path / "signed"
    install_dir.mkdir()
    base = install_dir / "base.apk"
    split = install_dir / "split-001.apk"
    base.write_bytes(b"base")
    split.write_bytes(b"split")

    notes, archive = write_split_deployment_artifacts(
        tmp_path,
        (base, split),
        base_apk=base,
        installer_package="com.android.vending",
    )

    text = notes.read_text(encoding="utf-8")
    assert 'adb install-multiple -r -i "com.android.vending"' in text
    assert "Select every APK" in text
    assert "does not reproduce store licensing" in text
    with zipfile.ZipFile(archive) as packaged:
        assert set(packaged.namelist()) == {
            "base.apk",
            "split-001.apk",
            "INSTALL_SPLIT_APKS.txt",
        }


@pytest.mark.parametrize("value", ["", "com", "bad package", "-i.example"])
def test_installer_package_validation_rejects_invalid_values(value: str) -> None:
    with pytest.raises(SplitApkError):
        validate_installer_package(value)


def test_pipeline_wrapper_analyzes_the_resolved_base_apk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path / "base.apk"
    split = tmp_path / "split_config.en.apk"
    _write_apk(base, package="com.example.app", dex=True)
    _write_apk(split, package="com.example.app", dex=False)
    outer = tmp_path / "package.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.write(base, "base.apk")
        archive.write(split, "split_config.en.apk")
    observed: dict[str, object] = {}

    def fake_pipeline(args: Namespace) -> int:
        observed["binary"] = Path(args.binary)
        observed["package_set"] = args._android_package_set
        return 17

    monkeypatch.setattr("reforge.cli.cmd_pipeline._cmd_pipeline_impl", fake_pipeline)

    result = cmd_pipeline(Namespace(binary=str(outer)))

    assert result == 17
    assert Path(observed["binary"]).name.endswith("base.apk")
    assert len(observed["package_set"].split_apks) == 1
