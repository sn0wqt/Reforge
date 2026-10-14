"""Pure-Python Apple Info.plist and IPA Application Scanner.

Inspects iOS (.ipa, .app) and macOS application bundles and Mach-O entitlements:
- Parses binary (bplist00) and XML Info.plist files via built-in plistlib.
- Extracts bundle identity: CFBundleIdentifier, CFBundleName, CFBundleExecutable,
  CFBundleShortVersionString, MinimumOSVersion, URL schemes.
- Discovers privacy/permission usage declarations (NSCameraUsageDescription, etc.).
- Inspects embedded.mobileprovision profiles and extracts signing entitlements:
  get-task-allow (debuggable), application-identifier, keychain-access-groups.
- Inspects .ipa archives directly without external extraction tools.
"""

from __future__ import annotations

import plistlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AppleAppInfo:
    """Extracted Apple application package and metadata report."""

    bundle_id: str | None = None
    bundle_name: str | None = None
    version: str | None = None
    executable_name: str | None = None
    minimum_os_version: str | None = None
    url_schemes: tuple[str, ...] = field(default_factory=tuple)
    permissions: dict[str, str] = field(default_factory=dict)
    entitlements: dict[str, object] = field(default_factory=dict)
    debuggable: bool = False
    team_name: str | None = None
    architectures: tuple[str, ...] = field(default_factory=tuple)
    raw_plist: dict[str, object] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def is_debuggable(self) -> bool:
        return self.debuggable or bool(self.entitlements.get("get-task-allow"))


class PlistScanner:
    """Pure-Python scanner for Apple Info.plist and IPA packages."""

    @classmethod
    def scan_plist_bytes(cls, data: bytes) -> AppleAppInfo | None:
        """Parse Info.plist bytes (XML or binary bplist00)."""
        try:
            parsed = plistlib.loads(data)
            if not isinstance(parsed, dict):
                return None
            return cls._from_dict(parsed)
        except Exception:
            return None

    @classmethod
    def scan_file(cls, path: str | Path) -> AppleAppInfo | None:
        """Scan an Info.plist file, .app directory, or .ipa archive."""
        target = Path(path)
        if not target.exists():
            return None

        # 1. IPA Archive (.ipa or zip)
        if target.is_file() and target.suffix.casefold() in (".ipa", ".zip"):
            return cls.scan_ipa_file(target)

        # 2. Direct Info.plist file
        if target.is_file():
            try:
                data = target.read_bytes()
                return cls.scan_plist_bytes(data)
            except OSError:
                return None

        # 3. App bundle directory (*.app)
        if target.is_dir():
            plist_file = target / "Info.plist"
            if plist_file.is_file():
                try:
                    data = plist_file.read_bytes()
                    info = cls.scan_plist_bytes(data)
                    if info:
                        # Check mobileprovision
                        prov = target / "embedded.mobileprovision"
                        if prov.is_file():
                            ent, team = cls._parse_mobileprovision(prov.read_bytes())
                            return cls._merge_provision(info, ent, team)
                        return info
                except OSError:
                    pass
        return None

    @classmethod
    def scan_ipa_file(cls, path: str | Path, max_bytes: int = 64 * 1024 * 1024) -> AppleAppInfo | None:
        """Inspect an .ipa archive directly."""
        target = Path(path)
        if not target.is_file():
            return None

        try:
            with zipfile.ZipFile(target, "r") as zf:
                # Find Payload/<Name>.app/Info.plist
                plist_names = [
                    name for name in zf.namelist() if name.startswith("Payload/") and name.endswith(".app/Info.plist")
                ]
                if not plist_names:
                    # Fallback to any Info.plist
                    plist_names = [n for n in zf.namelist() if n.endswith("Info.plist")]
                if not plist_names:
                    return None

                plist_bytes = zf.read(plist_names[0])
                info = cls.scan_plist_bytes(plist_bytes)
                if not info:
                    return None

                # Find embedded.mobileprovision
                prov_names = [
                    name
                    for name in zf.namelist()
                    if name.startswith("Payload/") and name.endswith(".app/embedded.mobileprovision")
                ]
                if prov_names:
                    try:
                        prov_bytes = zf.read(prov_names[0])
                        ent, team = cls._parse_mobileprovision(prov_bytes)
                        info = cls._merge_provision(info, ent, team)
                    except Exception:
                        pass

                return info
        except (zipfile.BadZipFile, OSError):
            return None

    @classmethod
    def _from_dict(cls, data: dict[str, object]) -> AppleAppInfo:
        """Map raw plist dictionary to AppleAppInfo."""
        bundle_id = str(data.get("CFBundleIdentifier", "")) or None
        bundle_name = str(data.get("CFBundleDisplayName") or data.get("CFBundleName", "")) or None
        version = str(data.get("CFBundleShortVersionString") or data.get("CFBundleVersion", "")) or None
        executable = str(data.get("CFBundleExecutable", "")) or None
        min_os = str(data.get("MinimumOSVersion", "")) or None

        # URL schemes
        url_schemes: list[str] = []
        raw_types = data.get("CFBundleURLTypes")
        if isinstance(raw_types, list):
            for item in raw_types:
                if isinstance(item, dict):
                    schemes = item.get("CFBundleURLSchemes")
                    if isinstance(schemes, list):
                        for s in schemes:
                            if isinstance(s, str) and s:
                                url_schemes.append(s)

        # Privacy / Permission declarations
        permissions: dict[str, str] = {}
        for k, v in data.items():
            if k.startswith("NS") and k.endswith("UsageDescription") and isinstance(v, str):
                perm_key = k[2:-16] or k
                permissions[perm_key] = v

        notes: list[str] = []
        if bundle_id:
            notes.append(f"Bundle ID: {bundle_id}")
        if bundle_name:
            notes.append(f"App Name: {bundle_name}")
        if version:
            notes.append(f"Version: {version}")
        if min_os:
            notes.append(f"Min OS: {min_os}")
        if url_schemes:
            notes.append(f"URL Schemes: {', '.join(sorted(set(url_schemes)))}")
        if permissions:
            notes.append(f"Permissions: {', '.join(sorted(permissions.keys()))}")

        return AppleAppInfo(
            bundle_id=bundle_id,
            bundle_name=bundle_name,
            version=version,
            executable_name=executable,
            minimum_os_version=min_os,
            url_schemes=tuple(sorted(set(url_schemes))),
            permissions=permissions,
            entitlements={},
            debuggable=False,
            raw_plist=data,
            notes=notes,
        )

    @classmethod
    def _parse_mobileprovision(cls, data: bytes) -> tuple[dict[str, object], str | None]:
        """Extract embedded plist from PKCS#7 signed embedded.mobileprovision."""
        try:
            start = data.find(b"<?xml")
            if start == -1:
                start = data.find(b"<plist")
            end = data.find(b"</plist>")
            if start != -1 and end != -1:
                xml_data = data[start : end + len(b"</plist>")]
                parsed = plistlib.loads(xml_data)
                if isinstance(parsed, dict):
                    ent = parsed.get("Entitlements")
                    team = str(parsed.get("TeamName", "")) or None
                    return (ent if isinstance(ent, dict) else {}), team
        except Exception:
            pass
        return {}, None

    @classmethod
    def _merge_provision(
        cls,
        info: AppleAppInfo,
        entitlements: dict[str, object],
        team_name: str | None,
    ) -> AppleAppInfo:
        """Combine base app info with provision profile data."""
        debuggable = bool(entitlements.get("get-task-allow", False))
        notes = list(info.notes)
        if team_name:
            notes.append(f"Team: {team_name}")
        if debuggable:
            notes.append("Debuggable: YES (get-task-allow)")
        app_id = str(entitlements.get("application-identifier", ""))
        if app_id:
            notes.append(f"AppID: {app_id}")

        return AppleAppInfo(
            bundle_id=info.bundle_id,
            bundle_name=info.bundle_name,
            version=info.version,
            executable_name=info.executable_name,
            minimum_os_version=info.minimum_os_version,
            url_schemes=info.url_schemes,
            permissions=info.permissions,
            entitlements=entitlements,
            debuggable=debuggable,
            team_name=team_name,
            architectures=info.architectures,
            raw_plist=info.raw_plist,
            notes=notes,
        )
