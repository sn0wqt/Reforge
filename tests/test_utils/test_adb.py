"""Unit tests for hardened ADB utilities in reforge.utils.adb."""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path

import pytest

from reforge.utils.adb import (
    ADB_DIRECTORY_BATCH_SCRIPT,
    AdbClient,
    AdbDirectoryEntry,
    AdbOutputError,
    AdbPackagePathEntry,
    AdbTargetError,
    build_adb_args,
    build_adb_shell_args,
    build_directory_listing_args,
    display_device_path,
    parse_adb_devices_output,
    parse_adb_directory_listing,
    parse_dumpsys_package_output,
    parse_getprop_output,
    parse_package_change_output,
    parse_package_list_output,
    parse_pm_path_output,
    pull_split_apks,
    query_package_details,
    quote_shell_operand,
    reserve_package_destinations,
    validate_adb_host_file_name,
)

# -----------------------------------------------------------------------------
# 1. Shell Quoting & Argument Construction
# -----------------------------------------------------------------------------


def test_quote_shell_operand_safe_strings() -> None:
    safe_samples = [
        "foo",
        "com.example.app",
        "file_123.txt",
        "/data/local/tmp",
        "key=value",
        "a:b@c+d,-",
        "A1B2C3",
    ]
    for sample in safe_samples:
        assert quote_shell_operand(sample) == sample


def test_quote_shell_operand_metacharacters() -> None:
    assert quote_shell_operand("") == "''"
    assert quote_shell_operand("hello world") == "'hello world'"
    assert quote_shell_operand("don't") == r"'don'\''t'"
    assert quote_shell_operand("a'b'c") == r"'a'\''b'\''c'"
    assert quote_shell_operand("; rm -rf /") == "'; rm -rf /'"
    assert quote_shell_operand("$PATH") == "'$PATH'"
    assert quote_shell_operand("`id`") == "'`id`'"
    assert quote_shell_operand("line1\nline2") == "'line1\nline2'"
    assert quote_shell_operand("file*.txt") == "'file*.txt'"
    assert quote_shell_operand("a|b&c") == "'a|b&c'"


def test_build_adb_args_with_and_without_serial() -> None:
    args1 = build_adb_args(["devices", "-l"])
    assert args1 == ["adb", "devices", "-l"]

    args2 = build_adb_args(["devices", "-l"], serial="emulator-5554", adb_bin="/opt/bin/adb")
    assert args2 == ["/opt/bin/adb", "-s", "emulator-5554", "devices", "-l"]

    args3 = build_adb_args(["shell", "pm", "path", "com.example; rm -rf /"])
    assert args3 == ["adb", "shell", "pm", "path", "'com.example; rm -rf /'"]


def test_build_adb_shell_args() -> None:
    args = build_adb_shell_args(["getprop", "ro.build.version.sdk"], serial="127.0.0.1:5555")
    assert args == ["adb", "-s", "127.0.0.1:5555", "shell", "getprop", "ro.build.version.sdk"]


# -----------------------------------------------------------------------------
# 2. Host File Name Validation & Display
# -----------------------------------------------------------------------------


def test_validate_adb_host_file_name_valid() -> None:
    valid_paths = [
        ("/data/local/tmp/notes.txt", "notes.txt"),
        ("/data/data/com.example/databases/app.db", "app.db"),
        ("/sdcard/My Notes.txt", "My Notes.txt"),
        ("/system/etc/hosts", "hosts"),
        ("/data/local/tmp/split_config.arm64_v8a.apk", "split_config.arm64_v8a.apk"),
        ("/data/local/tmp/résumé.xml", "résumé.xml"),
        ("/data/local/tmp/a-b_c.d", "a-b_c.d"),
    ]
    for dev_path, expected_name in valid_paths:
        res = validate_adb_host_file_name(dev_path)
        assert res.ok is True
        assert res.file_name == expected_name


def test_validate_adb_host_file_name_universal_rejections() -> None:
    assert validate_adb_host_file_name("").reason == "empty_file_name"
    assert validate_adb_host_file_name("/").reason == "empty_file_name"
    assert validate_adb_host_file_name("/data/local/tmp/").reason == "empty_file_name"
    assert validate_adb_host_file_name("data/local/tmp/file").reason == "not_absolute_path"
    assert validate_adb_host_file_name("/data/local/tmp/.").reason == "dot_segment"
    assert validate_adb_host_file_name("/data/local/tmp/..").reason == "dot_segment"
    assert validate_adb_host_file_name("/data\x00/local/tmp/file").reason == "unsupported_character"
    assert validate_adb_host_file_name("/data/local/tmp/a\x00b").reason == "unsupported_character"


def test_validate_adb_host_file_name_windows_rules() -> None:
    assert validate_adb_host_file_name(r"/data/local/tmp/a\b", platform="win32").reason == "unsupported_character"
    assert (
        validate_adb_host_file_name("/data/local/tmp/report:2024", platform="win32").reason == "unsupported_character"
    )
    assert validate_adb_host_file_name("/data/local/tmp/a*b.txt", platform="win32").reason == "unsupported_character"
    assert validate_adb_host_file_name("/data/local/tmp/a?b.txt", platform="win32").reason == "unsupported_character"
    assert validate_adb_host_file_name("/data/local/tmp/ta\tb", platform="win32").reason == "unsupported_character"

    assert validate_adb_host_file_name("/data/local/tmp/CON", platform="win32").reason == "reserved_name"
    assert validate_adb_host_file_name("/data/local/tmp/nul.txt", platform="win32").reason == "reserved_name"
    assert validate_adb_host_file_name("/data/local/tmp/com1", platform="win32").reason == "reserved_name"
    assert validate_adb_host_file_name("/data/local/tmp/LPT9", platform="win32").reason == "reserved_name"
    assert validate_adb_host_file_name("/data/local/tmp/COM¹.txt", platform="win32").reason == "reserved_name"
    assert validate_adb_host_file_name("/data/local/tmp/lpt³", platform="win32").reason == "reserved_name"

    assert validate_adb_host_file_name("/data/local/tmp/report.", platform="win32").reason == "trailing_dot_or_space"
    assert validate_adb_host_file_name("/data/local/tmp/report ", platform="win32").reason == "trailing_dot_or_space"

    # Non-Windows allows colon and backslash in POSIX filenames
    assert validate_adb_host_file_name("/data/local/tmp/report:2024", platform="linux").ok is True
    assert validate_adb_host_file_name(r"/data/local/tmp/a\b", platform="linux").ok is True

    # Windows allows high non-control characters
    assert validate_adb_host_file_name("/data/local/tmp/name\u007f.txt", platform="win32").ok is True
    assert validate_adb_host_file_name("/data/local/tmp/name\u0085.txt", platform="win32").ok is True


def test_display_device_path() -> None:
    assert display_device_path("/data/app/base.apk") == '"/data/app/base.apk"'
    assert display_device_path('/data/"app"/test') == '"/data/\\"app\\"/test"'
    assert "\\u{7}" in display_device_path("/data/\x07/bell")

    long_path = "/" + "a" * 200
    formatted = display_device_path(long_path)
    assert formatted.endswith("(excerpt)")
    assert len(formatted) < 220


# -----------------------------------------------------------------------------
# 3. NUL-Delimited Directory Listing
# -----------------------------------------------------------------------------


def test_directory_batch_script_constant() -> None:
    assert "stat -c '%A|%U|%G|%s|%y'" in ADB_DIRECTORY_BATCH_SCRIPT
    assert "readlink -n" in ADB_DIRECTORY_BATCH_SCRIPT


def test_build_directory_listing_args() -> None:
    args = build_directory_listing_args("/data/data/com.example/files", serial="device-1")
    assert args[0] == "adb"
    assert args[1:3] == ["-s", "device-1"]
    assert args[3] == "shell"
    assert args[4] == "sh"
    assert args[5] == "-c"
    assert "find . -mindepth 1 -maxdepth 1" in args[6]
    assert args[7] == "rea-list-directory"
    assert args[8] == "/data/data/com.example/files"


def test_parse_adb_directory_listing_records() -> None:
    date = "2026-01-02 11:00:00.000000000 +0000"
    raw = (
        f"-rw-rw----|u0_a1|u0_a1|4096|{date}\0app.db\0\0"
        f"drwxr-xr-x|system|system|4096|{date}\0cache\0\0"
        f"lrwxrwxrwx|root|root|25|{date}\0lib\0/apex/com.android.art/lib\0"
        f"-rw-r--r--|u0_a1|u0_a1|120|{date}\0 spaces and -> arrows \0\0"
    ).encode()

    entries, unparsed = parse_adb_directory_listing(raw)
    assert unparsed == []
    assert len(entries) == 4

    assert entries[0] == AdbDirectoryEntry(
        name="app.db",
        kind="file",
        permissions="-rw-rw----",
        owner="u0_a1",
        group="u0_a1",
        bytes=4096,
        date=date,
        link_target=None,
    )
    assert entries[1].kind == "directory"
    assert entries[1].name == "cache"

    assert entries[2] == AdbDirectoryEntry(
        name="lib",
        kind="symlink",
        permissions="lrwxrwxrwx",
        owner="root",
        group="root",
        bytes=25,
        date=date,
        link_target="/apex/com.android.art/lib",
    )
    assert entries[3].name == " spaces and -> arrows "
    assert entries[3].kind == "file"


def test_parse_adb_directory_listing_unparsed_and_errors() -> None:
    date = "2026-01-02 11:00:00.000000000 +0000"
    # Symlink with empty link target (illegal)
    bad_symlink = f"lrwxrwxrwx|root|root|0|{date}\0broken\0\0".encode()
    entries, unparsed = parse_adb_directory_listing(bad_symlink)
    assert entries == []
    assert len(unparsed) == 1

    # Non-symlink with non-empty link target (illegal)
    bad_file = f"-rw-rw----|u0_a1|u0_a1|10|{date}\0file.txt\0target\0".encode()
    entries, unparsed = parse_adb_directory_listing(bad_file)
    assert entries == []
    assert len(unparsed) == 1

    # Truncated record at stream end
    truncated = f"-rw-rw----|u0_a1|u0_a1|10|{date}\0incomplete".encode()
    entries, unparsed = parse_adb_directory_listing(truncated)
    assert entries == []
    assert len(unparsed) == 1
    assert "incomplete" in unparsed[0]

    # Invalid UTF-8 bytes
    invalid_utf8 = b"-rw-rw----|u0|u0|10|date\x00\xff\xfe\x00\x00"
    entries, unparsed = parse_adb_directory_listing(invalid_utf8)
    assert entries == []
    assert any("Invalid UTF-8 directory record" in line for line in unparsed)


# -----------------------------------------------------------------------------
# 4. Package Path Parsing & Split APK Puller
# -----------------------------------------------------------------------------


def test_parse_pm_path_output_classification() -> None:
    output = (
        "package:/data/app/~~a==/com.example.app-b==/base.apk\n"
        "package:/data/app/~~a==/com.example.app-b==/split_config.arm64_v8a.apk\n"
        "package:/data/app/~~a==/com.example.app-b==/split_config.en.apk\n"
        "package:/system/app/Legacy/custom.apk\n"
    )
    paths, rejected, unparsed = parse_pm_path_output(output)
    assert rejected == []
    assert unparsed == []
    assert len(paths) == 4

    assert paths[0] == AdbPackagePathEntry(
        device_path="/data/app/~~a==/com.example.app-b==/base.apk",
        file_name="base.apk",
        role="base",
    )
    assert paths[1].role == "split"
    assert paths[1].file_name == "split_config.arm64_v8a.apk"
    assert paths[2].role == "split"
    assert paths[2].file_name == "split_config.en.apk"
    assert paths[3].role == "unknown"
    assert paths[3].file_name == "custom.apk"


def test_parse_pm_path_output_rejections_and_unparsed() -> None:
    output = (
        "package:/data/app/pkg/base.apk/\n"  # trailing slash -> empty_file_name
        " package:/data/app/pkg/base.apk \n"  # leading space -> unparsed line
        "random output error\n"
    )
    paths, rejected, unparsed = parse_pm_path_output(output)
    assert paths == []
    assert len(rejected) == 1
    assert rejected[0]["reason"] == "empty_file_name"
    assert len(unparsed) == 2


def test_reserve_package_destinations_success_and_collision() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        package_dir = Path(temp_dir) / "com.example"
        package_dir.mkdir()

        # Success case: distinct filenames
        reserve_package_destinations(package_dir, ["base.apk", "split_config.apk"], "com.example")
        # Ensure temporary directories were released
        assert not (package_dir / "base.apk").exists()
        assert not (package_dir / "split_config.apk").exists()

        # Existing file conflict
        (package_dir / "base.apk").write_bytes(b"content")
        with pytest.raises(AdbOutputError, match="cannot be written to a unique local destination"):
            reserve_package_destinations(package_dir, ["base.apk"], "com.example")


class MockAdbClient(AdbClient):
    """Mock ADB client for testing high-level pull and query flows."""

    def __init__(self, responses: dict[str, tuple[int, bytes, bytes]]) -> None:
        super().__init__(serial="emulator-5554")
        self.responses = responses
        self.calls: list[list[str]] = []

    def run_cmd_bytes(
        self,
        full_args: list[str] | Sequence[str],
        *,
        timeout_s: float = 30.0,
        max_output_bytes: int = 32 * 1024 * 1024,
    ) -> tuple[int, bytes, bytes]:
        call = [str(x) for x in full_args]
        self.calls.append(call)
        key = " ".join(call)
        for pattern, resp in self.responses.items():
            if pattern in key:
                # If command is adb pull, write a fake file
                if "pull" in call:
                    dest = Path(call[-1])
                    dest.write_bytes(b"PK\x03\x04fake-apk-content")
                return resp
        return 1, b"", b"unknown command"


def test_pull_split_apks_flow() -> None:
    pm_output = b"package:/data/app/com.example/base.apk\npackage:/data/app/com.example/split_config.arm64_v8a.apk\n"

    mock = MockAdbClient(
        {
            "pm path com.example": (0, pm_output, b""),
            "pull /data/app/com.example/base.apk": (0, b"100%", b""),
            "pull /data/app/com.example/split_config.arm64_v8a.apk": (0, b"100%", b""),
        }
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        result = pull_split_apks("com.example", temp_dir, client=mock)
        assert result.package_name == "com.example"
        assert result.coverage == "complete"
        assert len(result.artifacts) == 2

        base = result.base_apk
        assert base is not None
        assert base.name == "base.apk"
        assert len(result.split_apks) == 1
        assert result.split_apks[0].name == "split_config.arm64_v8a.apk"

        # Check hash and size
        assert result.artifacts[0].bytes == len(b"PK\x03\x04fake-apk-content")
        assert len(result.artifacts[0].sha256) == 64

        package_set = result.to_package_set()
        assert package_set is not None
        assert package_set.base_apk == base
        assert package_set.split_apks == (result.split_apks[0],)


def test_pull_split_apks_uninstalled_package() -> None:
    mock = MockAdbClient(
        {
            "pm path com.absent": (0, b"", b""),
        }
    )
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        pytest.raises(AdbTargetError, match="Package Manager reported no APK paths"),
    ):
        pull_split_apks("com.absent", temp_dir, client=mock)


def test_pull_split_apks_duplicate_local_destination() -> None:
    pm_output = b"package:/data/app/dir1/base.apk\npackage:/data/app/dir2/base.apk\n"
    mock = MockAdbClient(
        {
            "pm path com.dup": (0, pm_output, b""),
        }
    )
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        pytest.raises(AdbOutputError, match="multiple APK paths with the same local file name"),
    ):
        pull_split_apks("com.dup", temp_dir, client=mock)


def test_pull_split_apks_unsafe_device_path() -> None:
    pm_output = b"package:/data/app/pkg/base.apk/\n"
    mock = MockAdbClient(
        {
            "pm path com.unsafe": (0, pm_output, b""),
        }
    )
    with (
        tempfile.TemporaryDirectory() as temp_dir,
        pytest.raises(AdbOutputError, match="cannot be written as a file on this host"),
    ):
        pull_split_apks("com.unsafe", temp_dir, client=mock)


# -----------------------------------------------------------------------------
# 5. Package Details Parser (dumpsys package)
# -----------------------------------------------------------------------------


def test_parse_dumpsys_package_output_standard() -> None:
    output = """
Packages:
  Package [com.example.app] (abcdef):
    userId=10234
    versionName=1.2.3
    versionCode=45 minSdk=24 targetSdk=34
    firstInstallTime=2026-01-02 03:04:05
    lastUpdateTime=2026-02-03 04:05:06
    installerPackageName=com.android.vending
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
    install permissions:
      android.permission.INTERNET: granted=true
"""
    details = parse_dumpsys_package_output(output)
    assert details.version_name == "1.2.3"
    assert details.version_code == 45
    assert details.first_install_time == "2026-01-02 03:04:05"
    assert details.last_update_time == "2026-02-03 04:05:06"
    assert details.installer_package_name == "com.android.vending"
    assert details.user_id == 10234
    assert details.pkg_flags == "[ HAS_CODE ALLOW_CLEAR_USER_DATA ]"
    assert details.requested_permissions_count == 2


def test_parse_dumpsys_package_output_restricted_permissions() -> None:
    output = """
  Package [com.example] (123):
    versionName=2.0
    versionCode=100
    requested permissions:
      android.permission.INTERNET
      android.permission.WRITE_EXTERNAL_STORAGE: restricted=true
      android.permission.RECORD_AUDIO
    signatures:PackageSignatures{...}
"""
    details = parse_dumpsys_package_output(output)
    assert details.version_name == "2.0"
    assert details.version_code == 100
    assert details.requested_permissions_count == 3


def test_query_package_details_not_found() -> None:
    mock = MockAdbClient(
        {
            "dumpsys package com.missing": (0, b"Unable to find package: com.missing\n", b""),
        }
    )
    with pytest.raises(AdbTargetError, match="Package Manager did not report details"):
        query_package_details("com.missing", client=mock)


# -----------------------------------------------------------------------------
# 6. Device, Property, & Package List Parsers
# -----------------------------------------------------------------------------


def test_parse_adb_devices_output() -> None:
    stdout = """List of devices attached
emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64xa transport_id:1
07ef9c2a              device usb:1-1 product:raven model:Pixel_6_Pro device:raven transport_id:2
192.168.1.42:5555     device product:mock model:mock transport_id:3
emulator-5556          offline transport_id:4
HT84L0240512           unauthorized usb:1-2 transport_id:5
HT84L0240599           no permissions usb:1-3 transport_id:6
"""
    devices, unparsed, daemon = parse_adb_devices_output(stdout)
    assert unparsed == []
    assert daemon is False
    assert len(devices) == 6

    assert devices[0].serial == "emulator-5554"
    assert devices[0].kind == "emulator"
    assert devices[0].transport == "tcp"

    assert devices[1].serial == "07ef9c2a"
    assert devices[1].kind == "physical"
    assert devices[1].transport == "usb"

    assert devices[2].serial == "192.168.1.42:5555"
    assert devices[2].kind == "unknown"
    assert devices[2].transport == "tcp"

    assert devices[3].state == "offline"
    assert devices[4].state == "unauthorized"
    assert devices[5].state == "no permissions"


def test_parse_adb_devices_daemon_notice() -> None:
    stdout = """* daemon not running; starting now at tcp:5037
* daemon started successfully
List of devices attached
emulator-5554          device transport_id:1
"""
    devices, unparsed, daemon = parse_adb_devices_output(stdout)
    assert daemon is True
    assert len(devices) == 1
    assert unparsed == []


def test_parse_getprop_output() -> None:
    stdout = """
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.kernel.qemu]: [1]
[ro.product.model]: [Pixel 8]
[unwanted.custom.property]: [ignored]
"""
    props, qemu = parse_getprop_output(stdout)
    assert qemu is True
    prop_dict = {p.name: p.value for p in props}
    assert prop_dict["ro.build.version.release"] == "14"
    assert prop_dict["ro.build.version.sdk"] == "34"
    assert prop_dict["ro.product.model"] == "Pixel 8"
    assert "unwanted.custom.property" not in prop_dict


def test_parse_package_list_output() -> None:
    stdout = """
package:/data/app/~~a==/com.example.app-1/base.apk=com.example.app
package:/system/app/Calculator/Calculator.apk=com.android.calculator2
invalid-line
"""
    packages, unparsed = parse_package_list_output(stdout)
    assert len(packages) == 2
    assert packages[0].package_name == "com.example.app"
    assert packages[0].base_apk_device_path == "/data/app/~~a==/com.example.app-1/base.apk"
    assert packages[1].package_name == "com.android.calculator2"
    assert unparsed == ["invalid-line"]


def test_parse_package_change_output() -> None:
    assert parse_package_change_output("Success\n") == ("success", None)
    assert parse_package_change_output("Failure [INSTALL_FAILED_ALREADY_EXISTS]\n") == (
        "failure",
        "INSTALL_FAILED_ALREADY_EXISTS",
    )
    status, reason = parse_package_change_output("error: device offline")
    assert status == "failure"
    assert reason is not None and "device offline" in reason


def test_adb_client_methods_with_mock() -> None:
    client = MockAdbClient(
        {
            "devices -l": (0, b"List of devices attached\nemulator-5554 device transport_id:1\n", b""),
            "pm list packages -f -3": (0, b"package:/data/app/app.apk=com.example\n", b""),
            "getprop": (0, b"[ro.build.version.sdk]: [34]\n", b""),
        }
    )
    devices, _, _ = client.list_devices()
    assert len(devices) == 1
    assert devices[0].serial == "emulator-5554"

    packages, _ = client.list_packages(scope="third_party")
    assert len(packages) == 1
    assert packages[0].package_name == "com.example"

    props, _ = client.get_properties()
    assert props[0].name == "ro.build.version.sdk"
    assert props[0].value == "34"
