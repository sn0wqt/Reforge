# Platform-Agnostic Profile Guide for auto-re-agent

`auto-re-agent` supports evidence collection, candidate ranking, and hook
scaffolding across multiple operating systems, architectures, and binary
formats. Generated hooks remain candidates until their ABI, offset, build, and
runtime behavior have been validated.

---

### Built-in Platform Profiles

When initializing a new reverse-engineering project, select the profile matching your target platform:

```bash
# Portable C++ default
re-agent init --profile generic-cpp

# iOS ARM64 binaries (Mach-O)
re-agent init --profile ios-arm64

# Android ARM64 shared libraries (.so / ELF)
re-agent init --profile android-arm64

# Windows x64 executables and DLLs (PE)
re-agent init --profile windows-x64

# Linux x64 executables and shared objects (ELF)
re-agent init --profile linux-x64
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
| 6 | Android package or file containing DEX bytecode | Android Java/Kotlin | `Hook_Frida.js` |
| 7 | ELF/PE or Android native package using C++, Unreal, or Flutter | Native | `Hook_Goal.cpp`, `Hook_Frida.js` |
| 8 | IPA or Mach-O with Swift/Objective-C evidence | Native iOS | `Hook_Frida.js` |

The detector can route all eight package shapes, but routing is not itself
evidence recovery. Hermes textual/decompiled property discovery, supplied
IL2CPP dumper metadata, and DEX name recovery are implemented locally. Native
ELF/PE/Mach-O, Unity packages without supplied dumper output, and incomplete
DEX ABI data fail with `INSUFFICIENT_EVIDENCE` instead of fabricating targets.

For a Unity package containing both the native IL2CPP binary and
`global-metadata.dat`, an explicitly selected local dumper can generate the
sidecars used by candidate discovery:

```bash
re-agent pipeline --binary game.apk --il2cpp-dumper /trusted/Il2CppDumper \
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
re-agent pipeline --metadata-dir /path/to/Dump0 --platform ios \
  --goal "find the player balance" --no-repack
```

Accepted metadata-only platform values are `ios`, `ios-arm64`, `android`,
`android-arm64`, `windows`, and `windows-x64`. An unresolved metadata-only run
stops before generating a platform-specific hook instead of guessing.

Every pathway uses the same candidate policy:

- Up to five candidates with confidence greater than or equal to 85% are
  displayed as the report's high-confidence targets.
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
  type were recovered.
- `patch_diff_summary.txt` records the complete candidate list, detected
  pathway, bundle resolution, and static-patch outcome.

### Hermes Bundle Handling

- Android resolves and extracts `index.android.bundle`.
- iOS resolves `main.jsbundle` first or `index.ios.bundle` when present.
- Plain JavaScript bundles can receive bounded property-value replacements with
  `--patch-bundle`.
- Hermes bytecode is decompiled for analysis only. Decompiler pseudo-JavaScript
  is never passed to `hermesc` or presented as a deployable bundle.
- Raw Hermes bytecode is not treated as a generic string table. Hermes formats
  are versioned, and changing an identifier string does not safely rewrite the
  bytecode instruction or constant that supplies a gameplay value. A binary
  patch requires a format-version-aware assembler/rewriter plus validation for
  that exact bundle; otherwise runtime Frida scaffolding remains the output.

### Typed Runtime Evidence

- `dump.cs` field offsets and method RVAs remain separate evidence types.
  Only an explicitly parsed `RVA:` method header may become
  `module.base + method_rva`; a field offset is never used as an executable
  address. Generated RVA interceptors log calls only, while return/argument
  changes remain disabled pending ABI review.
- The built-in DEX parser resolves class definitions, executable `class_data`
  methods, `proto_idx` entries, exact descriptors, static/instance state, and
  Frida overload type names. A primitive return override is emitted active only
  when all those facts are present; otherwise the script leaves the candidate
  commented and review-only.

### Packaging Choices

Interactive terminal runs offer packaging or hook/report-only output at the end
of supported Android and Windows pathways. Automation should use exactly one of:

```bash
re-agent pipeline --binary app.apk --goal "grant unlimited diamonds" --repack-apk
re-agent pipeline --binary app.apk --goal "grant unlimited diamonds" --no-repack
```

Android repackaging requires `apktool`, Java, and a trusted signer. The Windows
setup script installs the signer in the managed tool directory; alternatively,
`RE_AGENT_APK_SIGNER_JAR` can select one explicitly. `RE_AGENT_APKTOOL` can pin
a specific apktool executable; otherwise the PATH copy is used. Without runtime
injection, repackaging is refused unless a real textual bundle patch was
produced. The APK is decoded, the valid modification is injected, and the
result is rebuilt, signed, and verified. A zero exit status is returned only
when the requested artifact exists and the expected modified members survive
signing.

For an explicitly authorized non-root Android test workflow, the pipeline can
embed Frida Gadget from the managed tool installation:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_android_tools.ps1
re-agent doctor
re-agent pipeline --binary app.apk --goal "trace the player balance" `
  --embed-frida-gadget --frida-gadget-on-load resume
```

Runtime embedding remains deliberately opt-in. The pipeline never downloads
Gadget during an analysis run; the separate setup script performs pinned,
hash-verified installation. `RE_AGENT_FRIDA_GADGET_DIR` and
`RE_AGENT_FRIDA_GADGET_VERSION` select the managed input automatically.
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
