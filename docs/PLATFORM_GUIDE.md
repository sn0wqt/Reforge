# Platform-Agnostic Profile Guide for Reforge

`Reforge` supports evidence collection, candidate ranking, and hook
scaffolding across multiple operating systems, architectures, and binary
formats. Generated hooks remain candidates until their ABI, offset, build, and
runtime behavior have been validated.

---

### Built-in Platform Profiles

When initializing a new reverse-engineering project, select the profile matching your target platform:

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

---

### Profile Specifications

#### 1. iOS ARM64 (`ios-arm64`)
- **Binary Format**: Mach-O (ARM64 / ARM64e)
- **Calling Convention**: AAPCS64 / Apple ARM64 ABI (`X0`-`X7` argument registers, `X8` indirect result)
- **Source Extensions**: `.cpp`, `.mm`, `.m`, `.h`, `.hpp`
- **Validation**: Integrates with Xcode command line tools (`xcrun clang++ -arch arm64`).

#### 2. Android ARM64 (`android-arm64`)
- **Binary Format**: ELF Shared Objects (`.so`)
- **Calling Convention**: AAPCS64 (ARM64 Android NDK)
- **Source Extensions**: `.cpp`, `.cc`, `.cxx`, `.c`, `.h`, `.hpp`
- **Validation**: Integrates with Android NDK toolchain (`aarch64-linux-android-clang++`).

#### 3. Windows x64 (`windows-x64`)
- **Binary Format**: PE / PE32+ (`.exe`, `.dll`)
- **Calling Convention**: Microsoft x64 Calling Convention (`RCX`, `RDX`, `R8`, `R9`)
- **Source Extensions**: `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`
- **Validation**: Integrates with MSVC (`cl.exe`) or MinGW (`clang-cl`).

#### 4. Linux x64 (`linux-x64`)
- **Binary Format**: ELF (`.so`, ELF 64-bit LSB executable)
- **Calling Convention**: System V AMD64 ABI (`RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`)
- **Source Extensions**: `.cpp`, `.cc`, `.cxx`, `.c`, `.h`, `.hpp`
- **Validation**: Integrates with standard GCC / Clang toolchains.

---

### Universal Pipeline Pathways

| ID | Detection evidence | Pathway | Primary output |
|---:|---|---|---|
| 1 | Android package with `index.android.bundle` | React Native Hermes Android | `Hook_Frida.js` |
| 2 | iOS package with `main.jsbundle` or `index.ios.bundle` | React Native Hermes iOS | `Hook_Frida.js` |
| 3 | Android package with `libil2cpp.so` or IL2CPP metadata | Unity IL2CPP Android | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 4 | iOS package with `UnityFramework` or IL2CPP metadata | Unity IL2CPP iOS | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 5 | Windows `GameAssembly.dll` | Unity IL2CPP Windows | `Hook_Goal.cpp` |
| 6 | Android WebView/Capacitor package with a deployed HTML/JS entry, or executable DEX bytecode | Android WebView JavaScript or Java/Kotlin | `Hook_Web.js` and an optional textual bundle patch, or `Hook_Frida.js` |
| 7 | ELF/PE or Android native package using C++, Unreal, or Flutter | Native | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 8 | IPA or Mach-O with Swift/Objective-C evidence | Native iOS | `Hook_Frida.js` |

The detector can route all eight package shapes, but routing is not itself
evidence recovery. Hermes textual/decompiled property discovery, supplied
IL2CPP dumper metadata, and DEX name recovery are implemented locally. Native
ELF/PE/Mach-O, Unity packages without supplied dumper output, and incomplete
DEX ABI data fail with `INSUFFICIENT_EVIDENCE` instead of fabricating targets.

### Packaged WebView / Capacitor Applications

An APK that contains `assets/public/index.html` or `assets/www/index.html` plus
a locally deployed JavaScript entry is analyzed as a web application before
its Android shell DEX. When packaged `.js.map` files contain `sourcesContent`,
the pipeline recovers the original application sources, grounds candidate JSON
paths in those sources, and associates a response mutation only with an API
endpoint sharing a non-generic entity identity. It does not rank the shell's
Capacitor classes or bundled Android dependencies as application behavior.

`--patch-bundle` prepends the selected response transformer to the deployed
textual entry and validates the result as an ES module when Node.js is
available. `--repack-apk` can then place that exact modified member back into a
rebuilt and signed APK. This route does not require Frida Gadget or root.
`Hook_Web.js` is also emitted for inspection. A client-side response mutation
can change UI/client state, but it cannot override independent server-side
authorization, purchase validation, Play Integrity, or anti-tamper checks.

For a Unity package containing both the native IL2CPP binary and
`global-metadata.dat`, an explicitly selected local dumper can generate the
sidecars used by candidate discovery:

```bash
reforge pipeline --binary game.apk --il2cpp-dumper /trusted/Il2CppDumper \
  --goal "find the player balance" --no-repack
```

Loose `libil2cpp.so` or `GameAssembly.dll` inputs also require
`--metadata /path/to/global-metadata.dat`. Dumper execution is never downloaded
or enabled implicitly; the path is a user trust decision.

An Il2CppDumper output directory is detected from root-level artifacts such as
`script.json`, `dump.cs`, and `il2cpp.h`. Generated `DummyDll/*.dll` files and
the optional Visual Studio `cpp_project` are analysis artifacts and are never
treated as evidence that the game targets Windows. When a platform-specific
Unity image in `dump.cs` establishes the target, the pipeline reports that
evidence. If the metadata remains ambiguous, select the known target explicitly:

```bash
reforge pipeline --metadata-dir /path/to/Dump0 --platform ios \
  --goal "find the player balance" --no-repack
```

Accepted metadata-only platform values are `ios`, `ios-arm64`, `android`,
`android-arm64`, `windows`, and `windows-x64`. An unresolved metadata-only run
stops before generating a platform-specific hook instead of guessing.

Every pathway uses the same candidate policy:

- Up to five candidates with confidence greater than or equal to 85% are
  displayed as the report's high-confidence targets. Selection is goal-aware:
  only the highest-ranked candidate for each explicitly requested entity is
  primary (for example, one coins target and one keys target). Singular and
  plural forms are treated as the same entity.
- Every remaining candidate is retained with its exact score in the expanded
  summary.
- Hook files contain only candidates with complete activation evidence in the
  active group. They include at most the 20 highest-ranked remaining
  candidates as commented review blocks; the complete inventory belongs in
  `patch_diff_summary.txt`, not in compilable hook source.
- Per-class C++ offset-inventory headers are bounded to the 50 most relevant
  classes to avoid thousands of redundant filesystem artifacts.
- Behavior-changing C++ installs remain review-only until the method signature,
  calling convention, address, and lifecycle hook are grounded. The narrow
  Java/DEX primitive return-override path can activate only when the exact
  declared executable method, descriptor, static/instance state, and return
  type were recovered. Frida may also activate an IL2CPP `bool` or integer
  return override when metadata supplies an exact nonzero method RVA, the
  primitive return type, and a type-compatible replacement. Floating-point,
  object, struct, argument, field, and unresolved native mutations remain
  review-only because they require additional ABI or lifecycle information.
- `patch_diff_summary.txt` records the complete candidate list, detected
  pathway, bundle resolution, and static-patch outcome.

### Hermes Bundle Handling

- Android resolves and extracts `index.android.bundle`.
- iOS resolves `main.jsbundle` first or `index.ios.bundle` when present.
- Plain JavaScript bundles can receive bounded property-value replacements with
  `--patch-bundle`.
- Hermes bytecode is decompiled for analysis only. Decompiler pseudo-JavaScript
  is never passed to `hermesc` or presented as a deployable bundle.
- Name-only properties recovered from compiled bytecode are capped below the
  active confidence threshold because they have no stable source location or
  runtime binding. `Hermes_Candidate_Evidence.txt` records bounded source lines,
  nearest decompiler-function labels, and context for separating app state from
  framework or library export tables.
- Raw Hermes bytecode is not treated as a generic string table. Hermes formats
  are versioned, and changing an identifier string does not safely rewrite the
  bytecode instruction or constant that supplies a gameplay value. A binary
  patch requires a format-version-aware assembler/rewriter plus validation for
  that exact bundle; otherwise runtime Frida review scaffolding remains the
  output and is not described as an installed behavior-changing hook.

### Typed Runtime Evidence

- `dump.cs` field offsets and method RVAs remain separate evidence types.
  Only an explicitly parsed `RVA:` method header may become
  `module.base + method_rva`; a field offset is never used as an executable
  address. A verified IL2CPP `bool` or integer getter RVA can receive a Frida
  `onLeave` return replacement. Other generated RVA interceptors log calls
  only, while return/argument changes remain disabled pending ABI review.
- The built-in DEX parser resolves class definitions, executable `class_data`
  methods, `proto_idx` entries, exact descriptors, static/instance state, and
  Frida overload type names. A primitive return override is emitted active only
  when all those facts are present; otherwise the script leaves the candidate
  commented and review-only.

### Packaging Choices

Interactive terminal runs offer packaging or hook/report-only output at the end
of supported Android and Windows pathways. Automation should use exactly one of:

```bash
reforge pipeline --binary app.apk --goal "grant unlimited diamonds" --repack-apk
reforge pipeline --binary app.apk --goal "grant unlimited diamonds" --no-repack
```

Split-delivered applications may be supplied as a directory or an outer
ZIP/XAPK/APKS archive containing `base.apk` and its configuration splits:

```powershell
reforge pipeline --binary app.xapk --goal "authorized test goal" `
  --repack-apk --installer-package com.example.installer
```

The base is patched and every APK is re-signed together. The output contains
`modded_split_apks/`, `modded_split_apks.zip`, and
`INSTALL_SPLIT_APKS.txt`. Select every emitted APK in InstallWithOptions'
split-install mode after starting Shizuku, or use the emitted
`adb install-multiple` command. Installer metadata is informational: it does
not recreate store licensing or integrity state, and Android 14+ retains shell
origin information. Executable dynamic-feature splits and split-package Gadget
embedding are rejected until they can be analyzed and injected end to end.

A verified textual asset replacement requires Java and a trusted signer, but
does not decode the manifest or resources and therefore does not require
`apktool`. Structural changes—including Frida Gadget, manifest, smali,
resources, or native libraries—also require `apktool`. The Windows setup script
installs the signer in the managed tool directory; alternatively,
`REFORGE_APK_SIGNER_JAR` (or legacy `RE_AGENT_APK_SIGNER_JAR`) can select one explicitly.
`REFORGE_APKTOOL` (or legacy `RE_AGENT_APKTOOL`) can pin a specific apktool launcher;
otherwise PATH and managed installs are checked.
Without runtime injection, repackaging is refused unless a real textual bundle
patch was produced. A zero exit status is returned only when the requested
artifact exists, its signature/alignment verify, and the expected modified
member survives signing byte-for-byte.

For an explicitly authorized non-root Android test workflow, the pipeline can
embed Frida Gadget from the managed tool installation:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_android_tools.ps1
reforge doctor
reforge pipeline --binary app.apk --goal "trace the player balance" `
  --embed-frida-gadget --frida-gadget-on-load resume
```

Runtime embedding remains deliberately opt-in. The pipeline never downloads
Gadget during an analysis run; the separate setup script performs pinned,
hash-verified installation. `REFORGE_FRIDA_GADGET_DIR` and
`REFORGE_FRIDA_GADGET_VERSION` (or legacy `RE_AGENT_FRIDA_GADGET_*`) select the managed input automatically.
`--frida-gadget-path` and `--frida-gadget-version` remain explicit overrides.
A single `.so` or `.so.xz` may be supplied for a single-ABI APK; a directory
must contain one matching ELF Gadget for every ABI shipped by a multi-ABI APK.
A single input can additionally be pinned with `--frida-gadget-sha256`.

The packager verifies ELF type and architecture, rejects unsupported or
missing ABI coverage and split manifests, installs a non-exported startup
provider, writes Gadget's listen configuration, and verifies payload hashes
plus the loader class in the signed APK. `FRIDA_GADGET_NOTES.txt` records the
exact ADB forwarding and Frida connection command.

Typical deployment after a successful pipeline run:

```powershell
adb install .\modded_app-aligned-signed.apk
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l .\Hook_Frida.js
```

Embedding does not make every APK compatible. Re-signing changes the signing
certificate, and signature pinning, anti-tamper logic, Play Integrity, split
delivery, or application-specific startup behavior can still reject the
rebuilt package. The declared Gadget version is compared with a locally
installed `frida --version` when available, but a version declaration is not a
cryptographic identity; use the SHA-256 option when provenance must be pinned.

Every run also writes `pipeline_manifest.json`. Pipeline success means the
declared analysis and artifact stages completed; it does not claim that a
runtime hook was installed or that the requested behavior was observed.

Windows packaging collects the binary, hook sources, report, and signing notes.
Authenticode signing requires the user's certificate and is not performed
implicitly.

iOS signing is not attempted on Windows. The pipeline writes
`IOS_DEPLOYMENT_NOTES.txt`, `Hook_Frida.js`, and a modified textual bundle when
one can be safely produced. Deployment requires a suitable Frida test device;
IPA signing requires macOS, `codesign`, a provisioning profile, and an Apple
Developer certificate.

### Shared Objects on Android

A `.so` is an ELF shared object, not a Unity-specific format. Unity commonly
ships `libil2cpp.so`, while Unreal, Flutter, C/C++, Rust, Go, Cocos2d, and JNI
libraries also use `.so` files. Standard Java and Kotlin application code is
packaged as DEX bytecode; it reaches native `.so` code through JNI.
