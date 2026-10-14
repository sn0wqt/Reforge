# Platform Guide

Reforge supports binary analysis, candidate ranking, and hook generation across multiple operating systems, architectures, and packaging formats.

## Platform Profiles

Initialize projects with the profile matching your target platform:

```bash
# Portable C++ default
reforge init --profile generic-cpp

# iOS ARM64 binaries (Mach-O)
reforge init --profile ios-arm64

# Android ARM64 shared libraries (.so / ELF)
reforge init --profile android-arm64

# Windows x64 executables and DLLs (PE)
reforge init --profile windows-x64

# Linux x64 executables and shared objects (ELF)
reforge init --profile linux-x64
```

### Profile Specifications

| Profile | Binary Format | Calling Convention / ABI | Common Toolchain |
|---|---|---|---|
| `ios-arm64` | Mach-O (ARM64 / ARM64e) | AAPCS64 / Apple ARM64 (`X0`-`X7`, `X8` indirect) | Xcode (`xcrun clang++`) |
| `android-arm64` | ELF Shared Objects (`.so`) | AAPCS64 (Android NDK) | Android NDK (`aarch64-linux-android-clang++`) |
| `windows-x64` | PE / PE32+ (`.exe`, `.dll`) | Microsoft x64 (`RCX`, `RDX`, `R8`, `R9`) | MSVC (`cl.exe`) or Clang (`clang-cl`) |
| `linux-x64` | ELF (64-bit LSB executable / `.so`) | System V AMD64 (`RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`) | GCC / Clang |

## Pipeline Pathways

Reforge automatically detects target binary types:

| ID | Detection Signature | Pathway | Primary Output |
|---|---|---|---|
| 1 | `index.android.bundle` in archive | React Native Hermes (Android) | `Hook_Frida.js` |
| 2 | `main.jsbundle` or `index.ios.bundle` | React Native Hermes (iOS) | `Hook_Frida.js` |
| 3 | `libil2cpp.so` or metadata in APK | Unity IL2CPP (Android) | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 4 | `UnityFramework` or metadata in IPA | Unity IL2CPP (iOS) | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 5 | `GameAssembly.dll` | Unity IL2CPP (Windows) | `Hook_Goal.cpp` |
| 6 | `assets/public/index.html` or DEX | Android WebView / DEX Bytecode | `Hook_Web.js` or `Hook_Frida.js` |
| 7 | ELF / PE binary with C++, Unreal, Flutter | Native | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 8 | Mach-O binary with Swift / Obj-C symbols | Native iOS | `Hook_Frida.js` |

## Unity IL2CPP Analysis

For Unity packages with `libil2cpp.so` and `global-metadata.dat`:

```bash
reforge pipeline --binary game.apk --il2cpp-dumper /path/to/Il2CppDumper \
  --goal "find player balance" --no-repack
```

If analyzing an existing dumper directory:

```bash
reforge pipeline --metadata-dir /path/to/Dump --platform android \
  --goal "find player balance" --no-repack
```

Supported `--platform` values for metadata-only dumps: `ios`, `ios-arm64`, `android`, `android-arm64`, `windows`, `windows-x64`.

## Packaged Web / Capacitor Applications

APK files containing deployed HTML/JS entries (such as Capacitor or Cordova apps) are analyzed at the web layer:

1. Deployed JavaScript and source maps (when `sourcesContent` is present) are inspected.
2. `--patch-bundle` modifies the entry point and generates `Hook_Web.js`.
3. `--repack-apk` rebuilds and re-signs the APK with the modified entry point. Does not require root or Frida Gadget.

## Split APKs and XAPK Packages

Reforge accepts directories or ZIP/XAPK/APKS archives containing `base.apk` plus split APKs:

```powershell
reforge pipeline `
  --binary "C:\path\app.xapk" `
  --goal "find player coins" `
  --repack-apk
```

Outputs:
- `modded_split_apks/`: Modified base APK and all re-signed splits.
- `modded_split_apks.zip`: Portable zip of the modified set.
- `INSTALL_SPLIT_APKS.txt`: Instructions for ADB and Shizuku installation.

Install on device via Shizuku (InstallWithOptions) or ADB:

```powershell
adb install-multiple modded_split_apks\base.apk modded_split_apks\split_config.arm64_v8a.apk ...
```

## Android Non-Root Frida Gadget Workflow

To instrument apps without root, Reforge can embed Frida Gadget into the target APK:

```powershell
# 1. Run setup script to download pinned tools
powershell -ExecutionPolicy Bypass -File .\scripts\setup_android_tools.ps1

# 2. Verify readiness
reforge doctor

# 3. Build signed APK with embedded Gadget
reforge pipeline --binary app.apk --goal "trace player balance" `
  --embed-frida-gadget --frida-gadget-on-load resume
```

Connect and trace:

```powershell
adb install .\modded_app-aligned-signed.apk
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l .\Hook_Frida.js
```

Packaging requirements:
- Single-asset JavaScript replacement requires Java and `uber-apk-signer`.
- Structural changes (Frida Gadget injection, manifest edits, smali, native libraries) require `apktool`.
- Pinned tool versions: Frida 17.16.4, uber-apk-signer 1.3.0, platform-tools 37.0.1.

## Hook Activation Rules

Reforge separates raw evidence from active hooks:
- **Active Java/DEX Hooks**: Emitted active only when exact class, method, descriptor, and primitive return type are verified.
- **Active IL2CPP Hooks**: Emitted active for `bool` or integer return values with an exact nonzero method RVA.
- **Review-Only Blocks**: Structs, floating-point returns, arguments, and native offsets are generated as commented blocks for manual validation.
