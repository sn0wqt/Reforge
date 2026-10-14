"""Hardened ADB automation utilities ported from REA.

Provides shell operand quoting, safe NUL-delimited directory listing,
hardened split-APK acquisition, and dumpsys package metadata extraction.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from reforge.packaging.split_apks import AndroidPackageSet

# -----------------------------------------------------------------------------
# Shell Quoting & Argument Construction
# -----------------------------------------------------------------------------

_SAFE_SHELL_OPERAND = re.compile(r"^[A-Za-z0-9_./:=@+,-]+$")


def quote_shell_operand(value: str) -> str:
    """Quote an operand for the remote POSIX adb shell boundary.

    adb joins shell operands into a single string separated by spaces and sends
    them to the device-side /system/bin/sh. Arguments containing shell metacharacters,
    spaces, globs, or quotes are single-quoted with embedded quotes escaped as '\\''.
    """
    if _SAFE_SHELL_OPERAND.fullmatch(value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def build_adb_args(
    operands: Sequence[str],
    *,
    serial: str | None = None,
    adb_bin: str = "adb",
) -> list[str]:
    """Construct an argument vector for calling the adb binary.

    If the first operand is 'shell', any subsequent shell operands are escaped
    via `quote_shell_operand` to prevent device-side command injection.
    """
    if not operands:
        base: list[str] = []
    elif operands[0] == "shell":
        base = ["shell", *(quote_shell_operand(arg) for arg in operands[1:])]
    else:
        base = list(operands)

    if serial is not None:
        return [adb_bin, "-s", serial, *base]
    return [adb_bin, *base]


def build_adb_shell_args(
    shell_operands: Sequence[str],
    *,
    serial: str | None = None,
    adb_bin: str = "adb",
) -> list[str]:
    """Construct an argument vector for an 'adb shell' invocation."""
    return build_adb_args(["shell", *shell_operands], serial=serial, adb_bin=adb_bin)


# -----------------------------------------------------------------------------
# Host File Name Validation & Display
# -----------------------------------------------------------------------------

AdbHostFileNameReason = Literal[
    "empty_file_name",
    "not_absolute_path",
    "dot_segment",
    "unsupported_character",
    "reserved_name",
    "trailing_dot_or_space",
]

_WINDOWS_RESERVED_BASENAME_RE = re.compile(r"^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)", re.IGNORECASE)
_WINDOWS_DISALLOWED_CHARS_RE = re.compile(r'[\\:*?"<>|]')


@dataclass(frozen=True)
class HostFileNameResult:
    """Result of host file name validation from an Android device path."""

    ok: bool
    file_name: str | None = None
    reason: AdbHostFileNameReason | None = None


def validate_adb_host_file_name(
    device_path: str,
    platform: str | None = None,
) -> HostFileNameResult:
    """Validate that the basename of a device POSIX path is safe on the host OS.

    Prevents directory traversal, reserved DOS names on Windows, control characters,
    and trailing dots/spaces that would collide or corrupt filesystems.
    """
    target_platform = sys.platform if platform is None else platform

    if not device_path or device_path.endswith("/"):
        return HostFileNameResult(ok=False, reason="empty_file_name")
    if "\x00" in device_path:
        return HostFileNameResult(ok=False, reason="unsupported_character")
    if not device_path.startswith("/"):
        return HostFileNameResult(ok=False, reason="not_absolute_path")

    file_name = device_path[device_path.rfind("/") + 1 :]
    if file_name in (".", ".."):
        return HostFileNameResult(ok=False, reason="dot_segment")

    if target_platform == "win32":
        if _WINDOWS_DISALLOWED_CHARS_RE.search(file_name) or any(0 < ord(c) < 0x20 for c in file_name):
            return HostFileNameResult(ok=False, reason="unsupported_character")
        if _WINDOWS_RESERVED_BASENAME_RE.search(file_name):
            return HostFileNameResult(ok=False, reason="reserved_name")
        if file_name.endswith((".", " ")):
            return HostFileNameResult(ok=False, reason="trailing_dot_or_space")

    return HostFileNameResult(ok=True, file_name=file_name)


def display_device_path(device_path: str) -> str:
    """Quote a device path safely for logs/messages without unescaped control/bidi characters."""
    excerpt = device_path[:160]
    out: list[str] = []
    for ch in excerpt:
        if ch == " ":
            out.append(" ")
        elif ch in ("\\", '"'):
            out.append(f"\\{ch}")
        elif ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch).startswith(("C", "Z")) or ch == "\u2800":
            out.append(f"\\u{{{ord(ch):X}}}")
        else:
            out.append(ch)
    quoted = '"' + "".join(out) + '"'
    return quoted if len(excerpt) == len(device_path) else f"{quoted} (excerpt)"


# -----------------------------------------------------------------------------
# NUL-Delimited Directory Listing
# -----------------------------------------------------------------------------

ADB_DIRECTORY_BATCH_SCRIPT = r"""metadata=$(stat -c '%A|%U|%G|%s|%y' "$@") || exit
printf '%s\n' "$metadata" | {
  while IFS= read -r metadata; do
    [ "$#" -gt 0 ] || exit 1
    path=$1
    shift
    printf '%s\000%s\000' "$metadata" "${path##*/}"
    case "$metadata" in
      l*) readlink -n "$path" || exit 1 ;;
    esac
    printf '\000'
  done
  [ "$#" -eq 0 ]
}"""

_DIRECTORY_METADATA_RE = re.compile(r"^([bcdlps-][rwxstST-]{9})\|([^|\n]+)\|([^|\n]+)\|(\d+)\|([^|\n]+)$")


@dataclass(frozen=True)
class AdbDirectoryEntry:
    """One directory entry safely read via batched NUL framing."""

    name: str
    kind: Literal["directory", "file", "symlink", "other"]
    permissions: str
    owner: str
    group: str
    bytes: int
    date: str
    link_target: str | None = None


def _parse_entry(
    metadata: str,
    name: str,
    link_target: str,
) -> AdbDirectoryEntry | None:
    match = _DIRECTORY_METADATA_RE.match(metadata)
    if match is None or name == "" or "/" in name:
        return None
    permissions = match.group(1)
    try:
        size_bytes = int(match.group(4))
    except ValueError:
        return None
    if size_bytes < 0:
        return None

    is_symlink = permissions.startswith("l")
    if is_symlink and not link_target:
        return None
    if not is_symlink and link_target:
        return None

    if permissions.startswith("d"):
        kind: Literal["directory", "file", "symlink", "other"] = "directory"
    elif is_symlink:
        kind = "symlink"
    elif permissions.startswith("-"):
        kind = "file"
    else:
        kind = "other"

    return AdbDirectoryEntry(
        name=name,
        kind=kind,
        permissions=permissions,
        owner=match.group(2),
        group=match.group(3),
        bytes=size_bytes,
        date=match.group(5),
        link_target=link_target if is_symlink else None,
    )


def parse_adb_directory_listing(
    stdout_bytes: bytes,
) -> tuple[list[AdbDirectoryEntry], list[str]]:
    """Parse NUL-delimited triple records (metadata\\0name\\0linkTarget\\0) from ADB_DIRECTORY_BATCH_SCRIPT."""
    entries: list[AdbDirectoryEntry] = []
    unparsed_lines: list[str] = []
    offset = 0
    total = len(stdout_bytes)

    while offset < total:
        metadata_end = stdout_bytes.find(b"\x00", offset)
        name_end = -1 if metadata_end < 0 else stdout_bytes.find(b"\x00", metadata_end + 1)
        target_end = -1 if name_end < 0 else stdout_bytes.find(b"\x00", name_end + 1)

        if target_end < 0:
            remaining = stdout_bytes[offset:]
            try:
                unparsed_lines.append(remaining.decode("utf-8"))
            except UnicodeDecodeError:
                unparsed_lines.append(f"Invalid UTF-8 directory record (hex): {remaining.hex()}")
            break

        raw_record = stdout_bytes[offset : target_end + 1]
        try:
            metadata_str = stdout_bytes[offset:metadata_end].decode("utf-8")
            name_str = stdout_bytes[metadata_end + 1 : name_end].decode("utf-8")
            target_str = stdout_bytes[name_end + 1 : target_end].decode("utf-8")
        except UnicodeDecodeError:
            unparsed_lines.append(f"Invalid UTF-8 directory record (hex): {raw_record.hex()}")
            offset = target_end + 1
            continue

        entry = _parse_entry(metadata_str, name_str, target_str)
        if entry is None:
            unparsed_lines.append(raw_record.decode("utf-8", errors="replace"))
        else:
            entries.append(entry)

        offset = target_end + 1

    return entries, unparsed_lines


def build_directory_listing_args(
    device_path: str,
    *,
    serial: str | None = None,
    adb_bin: str = "adb",
) -> list[str]:
    """Construct arguments for running the NUL-delimited directory listing script safely."""
    shell_operands = [
        "sh",
        "-c",
        'cd "$1" || exit\nexec find . -mindepth 1 -maxdepth 1 -exec sh -c "$2" rea-list-directory {} +',
        "rea-list-directory",
        device_path,
        ADB_DIRECTORY_BATCH_SCRIPT,
    ]
    return build_adb_shell_args(shell_operands, serial=serial, adb_bin=adb_bin)


# -----------------------------------------------------------------------------
# Package Path Parsing & Split APK Puller
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AdbPackagePathEntry:
    """One APK path belonging to an installed package."""

    device_path: str
    file_name: str
    role: Literal["base", "split", "unknown"]


def parse_pm_path_output(
    stdout: str,
    platform: str | None = None,
) -> tuple[list[AdbPackagePathEntry], list[dict[str, str]], list[str]]:
    """Parse output from `pm path <package>`.

    Categorizes entries into base.apk, split_*.apk, and unknown APK roles while
    validating destination filenames against host path safety rules.
    """
    paths: list[AdbPackagePathEntry] = []
    rejected_paths: list[dict[str, str]] = []
    unparsed_lines: list[str] = []

    for raw_line in stdout.splitlines():
        if not raw_line:
            continue
        match = re.match(r"^package:(.*)$", raw_line)
        if match is None:
            unparsed_lines.append(raw_line)
            continue
        device_path = match.group(1)
        validated = validate_adb_host_file_name(device_path, platform=platform)
        if not validated.ok or validated.file_name is None:
            rejected_paths.append(
                {
                    "device_path": device_path,
                    "reason": validated.reason or "unknown_error",
                }
            )
            continue

        file_name = validated.file_name
        if file_name == "base.apk":
            role: Literal["base", "split", "unknown"] = "base"
        elif file_name.startswith("split_") and file_name.endswith(".apk"):
            role = "split"
        else:
            role = "unknown"

        paths.append(
            AdbPackagePathEntry(
                device_path=device_path,
                file_name=file_name,
                role=role,
            )
        )

    return paths, rejected_paths, unparsed_lines


def reserve_package_destinations(
    package_dir: Path,
    entries: Sequence[AdbPackagePathEntry | str],
    package_name: str = "",
) -> None:
    """Temporarily reserve local destination paths to detect case/alias collisions before transfer."""
    reservations: list[Path] = []
    try:
        for item in entries:
            file_name = item.file_name if isinstance(item, AdbPackagePathEntry) else item
            device_path = item.device_path if isinstance(item, AdbPackagePathEntry) else file_name
            target = package_dir / file_name
            try:
                target.mkdir()
                if not target.is_dir() or target.is_symlink():
                    raise OSError(f"Could not reserve local destination {file_name}")
                reservations.append(target)
            except OSError as exc:
                raise AdbOutputError(
                    f"pm path for {package_name} reported {display_device_path(device_path)}, "
                    f"whose file name {display_device_path(file_name)} cannot be written to a unique "
                    f"local destination ({exc}). No APK was pulled."
                ) from exc
    finally:
        for res in reservations:
            try:
                res.rmdir()
            except OSError as exc:
                raise AdbOutputError(f"Could not release the local filename reservation for {res.name}: {exc}") from exc


@dataclass(frozen=True)
class AdbPulledArtifact:
    """Metadata and digest for a pulled device file."""

    device_path: str
    file_name: str
    local_path: Path
    bytes: int
    sha256: str
    role: Literal["base", "split", "unknown"]
    role_basis: str = "file_name"


@dataclass(frozen=True)
class AdbPullFailure:
    """Details of a failed pull operation."""

    device_path: str | None
    stage: Literal["resolve_paths", "pull", "digest"]
    message: str


@dataclass(frozen=True)
class AdbPackagePullResult:
    """Result of pulling all APKs (base + splits) for a package."""

    package_name: str
    output_directory: Path
    artifacts: list[AdbPulledArtifact]
    failures: list[AdbPullFailure]
    coverage: Literal["complete", "partial"]

    @property
    def base_apk(self) -> Path | None:
        """Return the local path to the base APK if present."""
        for art in self.artifacts:
            if art.role == "base":
                return art.local_path
        return None

    @property
    def split_apks(self) -> tuple[Path, ...]:
        """Return all pulled split APK paths in order."""
        return tuple(art.local_path for art in self.artifacts if art.role == "split")

    def to_package_set(self) -> AndroidPackageSet | None:
        """Convert into an AndroidPackageSet if a base APK was pulled and packaging is available."""
        try:
            from reforge.packaging.split_apks import AndroidPackageSet
        except ImportError:
            return None

        base = self.base_apk
        if base is None:
            return None
        return AndroidPackageSet(
            source=self.output_directory,
            base_apk=base,
            split_apks=self.split_apks,
            source_kind="adb",
        )


# -----------------------------------------------------------------------------
# Package Details Parser (dumpsys package)
# -----------------------------------------------------------------------------

_RESTRICTED_PERM_RE = re.compile(r"^\s{2,}[A-Za-z0-9._]+(?:: restricted=true)?$")
_DETAIL_LINE_RE = re.compile(r"^\s+([A-Za-z][A-Za-z0-9_]*)=(.*)$")


@dataclass(frozen=True)
class AdbPackageDetails:
    """Extracted package metadata from `dumpsys package PACKAGE`."""

    version_name: str | None
    version_code: int | None
    first_install_time: str | None
    last_update_time: str | None
    installer_package_name: str | None
    user_id: int | None
    pkg_flags: str | None
    requested_permissions_count: int


def parse_dumpsys_package_output(stdout: str) -> AdbPackageDetails:
    """Parse `dumpsys package PACKAGE` output, extracting whitelisted properties."""
    version_name: str | None = None
    version_code: int | None = None
    first_install_time: str | None = None
    last_update_time: str | None = None
    installer_package_name: str | None = None
    user_id: int | None = None
    pkg_flags: str | None = None
    requested_permissions = 0
    in_permissions = False

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if stripped.startswith("requested permissions:"):
            in_permissions = True
            continue

        if in_permissions and _RESTRICTED_PERM_RE.match(line):
            requested_permissions += 1
            continue

        in_permissions = False
        match = _DETAIL_LINE_RE.match(line)
        if match is None:
            continue

        key = match.group(1)
        value = match.group(2).strip()

        if key == "versionName" and version_name is None:
            version_name = value if value else None
        elif key == "versionCode" and version_code is None:
            code_match = re.match(r"^(\d+)", value)
            if code_match:
                version_code = int(code_match.group(1))
        elif key == "firstInstallTime" and first_install_time is None:
            first_install_time = value if value else None
        elif key == "lastUpdateTime" and last_update_time is None:
            last_update_time = value if value else None
        elif key == "installerPackageName" and installer_package_name is None:
            installer_package_name = value if value else None
        elif key == "userId" and user_id is None:
            uid_match = re.match(r"^(\d+)", value)
            if uid_match:
                user_id = int(uid_match.group(1))
        elif key == "pkgFlags" and pkg_flags is None:
            pkg_flags = value if value else None

    return AdbPackageDetails(
        version_name=version_name,
        version_code=version_code,
        first_install_time=first_install_time,
        last_update_time=last_update_time,
        installer_package_name=installer_package_name,
        user_id=user_id,
        pkg_flags=pkg_flags,
        requested_permissions_count=requested_permissions,
    )


# -----------------------------------------------------------------------------
# Device & Package Listing
# -----------------------------------------------------------------------------

ADB_DEVICE_STATES = (
    "no permissions",
    "unauthorized",
    "authorizing",
    "offline",
    "recovery",
    "sideload",
    "connecting",
    "bootloader",
    "device",
    "unknown",
    "host",
    "rescue",
    "detached",
)


@dataclass(frozen=True)
class AdbDeviceEntry:
    """One device exactly as `adb devices -l` reports it."""

    serial: str
    state: str
    transport: Literal["usb", "tcp", "unknown"]
    product: str | None
    model: str | None
    device: str | None
    transport_id: int | None
    kind: Literal["emulator", "physical", "unknown"]
    kind_basis: Literal["emulator_serial_prefix", "usb_transport", "none"]


_DEVICE_LINE_RE = re.compile(r"^(\S+)\s+(.*)$")


def _metadata_value(remainder: str, key: str) -> str | None:
    match = re.search(rf"(?:^|\s){re.escape(key)}:(\S+)", remainder)
    return match.group(1) if match else None


def parse_adb_devices_output(
    stdout: str,
    stderr: str = "",
) -> tuple[list[AdbDeviceEntry], list[str], bool]:
    """Parse `adb devices -l` output, preserving unparsed lines and daemon startup notices."""
    devices: list[AdbDeviceEntry] = []
    unparsed_lines: list[str] = []
    daemon_started = False

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if line in ("* daemon started successfully", "* daemon started successfully *"):
            daemon_started = True
            continue
        if not line or line.startswith("List of devices attached") or line.startswith("* daemon"):
            continue

        match = _DEVICE_LINE_RE.match(line)
        state: str | None = None
        if match:
            remainder = match.group(2)
            for candidate in ADB_DEVICE_STATES:
                if remainder.startswith(candidate):
                    next_char = remainder[len(candidate) : len(candidate) + 1]
                    if not next_char or next_char.isspace():
                        state = candidate
                        break

        if match is None or state is None:
            if raw_line.strip():
                unparsed_lines.append(raw_line)
            continue

        serial = match.group(1)
        remainder = match.group(2)[len(state) :]
        usb = _metadata_value(remainder, "usb")
        transport_id_str = _metadata_value(remainder, "transport_id")
        transport_id = int(transport_id_str) if transport_id_str and transport_id_str.isdigit() else None
        is_emulator = bool(re.match(r"^emulator-\d+$", serial))

        if is_emulator:
            kind: Literal["emulator", "physical", "unknown"] = "emulator"
            kind_basis: Literal["emulator_serial_prefix", "usb_transport", "none"] = "emulator_serial_prefix"
        elif usb is not None:
            kind = "physical"
            kind_basis = "usb_transport"
        else:
            kind = "unknown"
            kind_basis = "none"

        if usb is not None:
            transport: Literal["usb", "tcp", "unknown"] = "usb"
        elif is_emulator or ":" in serial:
            transport = "tcp"
        else:
            transport = "unknown"

        devices.append(
            AdbDeviceEntry(
                serial=serial,
                state=state,
                transport=transport,
                product=_metadata_value(remainder, "product"),
                model=_metadata_value(remainder, "model"),
                device=_metadata_value(remainder, "device"),
                transport_id=transport_id,
                kind=kind,
                kind_basis=kind_basis,
            )
        )

    if not daemon_started and stderr:
        for raw_line in stderr.splitlines():
            line = raw_line.rstrip()
            if line in ("* daemon started successfully", "* daemon started successfully *"):
                daemon_started = True
                break

    return devices, unparsed_lines, daemon_started


DEVICE_PROPERTY_WHITELIST = (
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.build.characteristics",
    "ro.debuggable",
    "ro.kernel.qemu",
    "ro.product.brand",
    "ro.product.device",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.cpu.abilist",
)


@dataclass(frozen=True)
class AdbDeviceProperty:
    """One projected device property."""

    name: str
    value: str


def parse_getprop_output(stdout: str) -> tuple[list[AdbDeviceProperty], bool | None]:
    """Parse `getprop` output for whitelisted properties and qemu detection."""
    values: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        match = re.match(r"^\[([^\]]+)\]:\s*\[(.*)\]$", raw_line.strip())
        if match:
            values[match.group(1)] = match.group(2)
    properties: list[AdbDeviceProperty] = []
    for name in DEVICE_PROPERTY_WHITELIST:
        val = values.get(name)
        if val:
            properties.append(AdbDeviceProperty(name=name, value=val))
    qemu = values.get("ro.kernel.qemu")
    emulator_observed = None if qemu is None else (qemu == "1")
    return properties, emulator_observed


@dataclass(frozen=True)
class AdbPackageEntry:
    """One installed package as `pm list packages -f` reports it."""

    package_name: str
    base_apk_device_path: str


def parse_package_list_output(stdout: str) -> tuple[list[AdbPackageEntry], list[str]]:
    """Parse `pm list packages -f` output lines."""
    packages: list[AdbPackageEntry] = []
    unparsed_lines: list[str] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^package:(.+)=([^\s=]+)$", line)
        if match is None:
            unparsed_lines.append(raw_line)
            continue
        packages.append(
            AdbPackageEntry(
                package_name=match.group(2),
                base_apk_device_path=match.group(1),
            )
        )
    return packages, unparsed_lines


def parse_package_change_output(
    stdout: str,
) -> tuple[Literal["success", "failure"], str | None]:
    """Parse `adb install` / `adb uninstall` output text for success/failure."""
    text = stdout.strip()
    if re.search(r"^Success$", text, re.MULTILINE):
        return "success", None
    failure_match = re.search(r"Failure \[([^\]]+)\]", text)
    if failure_match:
        return "failure", failure_match.group(1)
    return "failure", (None if not text else text[:512])


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class AdbError(Exception):
    """Base exception for all ADB operations."""


class AdbCommandError(AdbError):
    """Raised when an ADB command fails or returns unexpected output."""


class AdbTargetError(AdbError):
    """Raised when the target device or package is unavailable, offline, or missing."""


class AdbTargetUnauthorizedError(AdbTargetError):
    """Raised when the target device is unauthorized."""


class AdbOutputError(AdbError):
    """Raised when output destination paths are unsafe or conflicting."""


class AdbTimeoutError(AdbError):
    """Raised when an ADB command exceeds its execution timeout."""


# -----------------------------------------------------------------------------
# ADB Client Runner
# -----------------------------------------------------------------------------


class AdbClient:
    """Robust ADB automation client executing hardened device commands."""

    def __init__(self, serial: str | None = None, adb_bin: str = "adb") -> None:
        self.serial = serial
        self.adb_bin = adb_bin

    def build_args(self, operands: Sequence[str]) -> list[str]:
        """Construct full arguments list including adb binary and optional serial."""
        return build_adb_args(operands, serial=self.serial, adb_bin=self.adb_bin)

    def run_cmd_bytes(
        self,
        full_args: Sequence[str],
        *,
        timeout_s: float = 30.0,
        max_output_bytes: int = 32 * 1024 * 1024,
    ) -> tuple[int, bytes, bytes]:
        """Run an ADB command synchronously, capturing stdout and stderr bytes."""
        try:
            proc = subprocess.run(
                list(full_args),
                capture_output=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdbTimeoutError(f"ADB command timed out after {timeout_s}s: {full_args}") from exc
        except FileNotFoundError as exc:
            raise AdbCommandError(f"ADB binary not found at '{self.adb_bin}': {exc}") from exc
        except OSError as exc:
            raise AdbCommandError(f"Failed to execute ADB command {full_args}: {exc}") from exc

        stdout = proc.stdout[:max_output_bytes]
        stderr = proc.stderr[:max_output_bytes]
        return proc.returncode, stdout, stderr

    def run_cmd(
        self,
        operands: Sequence[str],
        *,
        timeout_s: float = 30.0,
        max_output_bytes: int = 32 * 1024 * 1024,
    ) -> tuple[int, str, str]:
        """Run an ADB command with operands, returning (returncode, stdout, stderr)."""
        full_args = self.build_args(operands)
        code, out_b, err_b = self.run_cmd_bytes(full_args, timeout_s=timeout_s, max_output_bytes=max_output_bytes)
        return code, out_b.decode("utf-8", errors="replace"), err_b.decode("utf-8", errors="replace")

    def run_shell(
        self,
        shell_operands: Sequence[str],
        *,
        timeout_s: float = 30.0,
        max_output_bytes: int = 32 * 1024 * 1024,
    ) -> tuple[int, str, str]:
        """Run an 'adb shell' command with safely quoted shell operands."""
        full_args = build_adb_shell_args(shell_operands, serial=self.serial, adb_bin=self.adb_bin)
        code, out_b, err_b = self.run_cmd_bytes(full_args, timeout_s=timeout_s, max_output_bytes=max_output_bytes)
        return code, out_b.decode("utf-8", errors="replace"), err_b.decode("utf-8", errors="replace")

    def list_devices(self, timeout_s: float = 20.0) -> tuple[list[AdbDeviceEntry], list[str], bool]:
        """List attached devices via `adb devices -l`."""
        code, out, err = self.run_cmd(["devices", "-l"], timeout_s=timeout_s)
        if code != 0:
            raise AdbCommandError(f"`adb devices -l` failed with exit code {code}: {err}")
        return parse_adb_devices_output(out, err)

    def list_packages(
        self, scope: Literal["all", "third_party", "system"] = "all", timeout_s: float = 60.0
    ) -> tuple[list[AdbPackageEntry], list[str]]:
        """List packages via `pm list packages -f`."""
        cmd = ["pm", "list", "packages", "-f"]
        if scope == "third_party":
            cmd.append("-3")
        elif scope == "system":
            cmd.append("-s")
        code, out, err = self.run_shell(cmd, timeout_s=timeout_s)
        if code != 0:
            raise AdbCommandError(f"`pm list packages` failed with exit code {code}: {err}")
        return parse_package_list_output(out)

    def get_properties(self, timeout_s: float = 30.0) -> tuple[list[AdbDeviceProperty], bool | None]:
        """Query device build properties via `getprop`."""
        code, out, err = self.run_shell(["getprop"], timeout_s=timeout_s)
        if code != 0:
            raise AdbCommandError(f"`getprop` failed with exit code {code}: {err}")
        return parse_getprop_output(out)

    def inspect_package(self, package_name: str, timeout_s: float = 60.0) -> AdbPackageDetails:
        """Query package metadata via `dumpsys package`."""
        return query_package_details(package_name, client=self, timeout_s=timeout_s)

    def list_directory(self, device_path: str, timeout_s: float = 30.0) -> tuple[list[AdbDirectoryEntry], list[str]]:
        """List directory contents safely using the batched NUL-framing script."""
        return list_device_directory(device_path, client=self, timeout_s=timeout_s)

    def pull_package(
        self,
        package_name: str,
        output_directory: Path | str,
        timeout_s: float = 600.0,
        platform: str | None = None,
    ) -> AdbPackagePullResult:
        """Pull all APKs (base + splits) for a package into a local directory."""
        return pull_split_apks(
            package_name,
            output_directory,
            client=self,
            timeout_s=timeout_s,
            platform=platform,
        )


# -----------------------------------------------------------------------------
# High-Level Operations
# -----------------------------------------------------------------------------


def list_device_directory(
    device_path: str,
    *,
    client: AdbClient | None = None,
    serial: str | None = None,
    adb_bin: str = "adb",
    timeout_s: float = 30.0,
) -> tuple[list[AdbDirectoryEntry], list[str]]:
    """List directory contents on device safely using NUL-delimited batched stat output."""
    client = client or AdbClient(serial=serial, adb_bin=adb_bin)
    full_args = build_directory_listing_args(device_path, serial=client.serial, adb_bin=client.adb_bin)
    code, stdout_bytes, stderr_bytes = client.run_cmd_bytes(full_args, timeout_s=timeout_s)
    if code != 0:
        err_msg = stderr_bytes.decode("utf-8", errors="replace").strip()
        if re.search(
            r"No such file or directory|Permission denied|read: Permission denied",
            err_msg,
            re.IGNORECASE,
        ):
            raise AdbTargetError(f"Cannot list directory {device_path}: {err_msg}")
        raise AdbCommandError(f"Directory listing failed for {device_path}: {err_msg}")
    return parse_adb_directory_listing(stdout_bytes)


def query_package_details(
    package_name: str,
    *,
    client: AdbClient | None = None,
    serial: str | None = None,
    adb_bin: str = "adb",
    timeout_s: float = 60.0,
) -> AdbPackageDetails:
    """Query package properties using `dumpsys package` without shell injection risks."""
    client = client or AdbClient(serial=serial, adb_bin=adb_bin)
    code, stdout, stderr = client.run_shell(["dumpsys", "package", package_name], timeout_s=timeout_s)
    if code != 0 or "Unable to find package:" in stdout or not stdout.strip():
        raise AdbTargetError(f"Package Manager did not report details for {package_name}; it may not be installed.")
    return parse_dumpsys_package_output(stdout)


def pull_split_apks(
    package_name: str,
    output_directory: Path | str,
    *,
    client: AdbClient | None = None,
    serial: str | None = None,
    adb_bin: str = "adb",
    timeout_s: float = 600.0,
    platform: str | None = None,
) -> AdbPackagePullResult:
    """Pull split APKs for an installed package safely into a local directory.

    1. Resolves device APK paths via `pm path`.
    2. Validates paths against host filename and path traversal rules.
    3. Checks for case/alias collisions on the host filesystem before pulling.
    4. Downloads each APK via `adb pull` and calculates SHA-256 digests.
    """
    client = client or AdbClient(serial=serial, adb_bin=adb_bin)
    code, stdout, stderr = client.run_shell(["pm", "path", package_name], timeout_s=30.0)
    if code != 0 or not stdout.strip():
        raise AdbTargetError(f"Package Manager reported no APK paths for {package_name}; it may not be installed.")

    paths, rejected_paths, unparsed_lines = parse_pm_path_output(stdout, platform=platform)

    if rejected_paths:
        first = rejected_paths[0]
        raise AdbOutputError(
            f"pm path for {package_name} reported an APK path that cannot be written as a file on this host: "
            f"{display_device_path(first['device_path'])} ({first['reason']}). No APK was pulled."
        )

    if not paths and not unparsed_lines:
        raise AdbTargetError(f"Package Manager reported no APK paths for {package_name}; it may not be installed.")

    if unparsed_lines:
        raise AdbCommandError(f"pm path reported an unrecognized line: {unparsed_lines[0]}")

    destination_names: set[str] = set()
    for entry in paths:
        if entry.file_name in destination_names:
            raise AdbOutputError(
                f"pm path for {package_name} reported multiple APK paths with the same local file name "
                f"{display_device_path(entry.file_name)}; no APK was pulled."
            )
        destination_names.add(entry.file_name)

    base_dir = Path(output_directory).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    package_directory = base_dir / package_name
    package_directory.mkdir(parents=True, exist_ok=True)

    reserve_package_destinations(package_directory, paths, package_name=package_name)

    artifacts: list[AdbPulledArtifact] = []
    failures: list[AdbPullFailure] = []

    for entry in paths:
        local_path = package_directory / entry.file_name
        pull_code, pull_out, pull_err = client.run_cmd(
            ["pull", entry.device_path, str(local_path)], timeout_s=timeout_s
        )
        if pull_code != 0:
            failures.append(
                AdbPullFailure(
                    device_path=entry.device_path,
                    stage="pull",
                    message=pull_err.strip() or pull_out.strip() or f"adb pull exited with code {pull_code}",
                )
            )
            continue

        try:
            h = hashlib.sha256()
            size = 0
            with open(local_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
                    size += len(chunk)
            artifacts.append(
                AdbPulledArtifact(
                    device_path=entry.device_path,
                    file_name=entry.file_name,
                    local_path=local_path,
                    bytes=size,
                    sha256=h.hexdigest(),
                    role=entry.role,
                )
            )
        except OSError as exc:
            failures.append(
                AdbPullFailure(
                    device_path=entry.device_path,
                    stage="digest",
                    message=f"The pulled file could not be read back after pulling: {local_path} ({exc})",
                )
            )

    if not artifacts and failures:
        raise AdbCommandError(
            f"Every APK pull failed for {package_name} on {client.serial or 'device'}: {failures[0].message}"
        )

    coverage: Literal["complete", "partial"] = "complete" if not failures else "partial"
    return AdbPackagePullResult(
        package_name=package_name,
        output_directory=package_directory,
        artifacts=artifacts,
        failures=failures,
        coverage=coverage,
    )
