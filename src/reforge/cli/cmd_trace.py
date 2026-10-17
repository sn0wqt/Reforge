"""CLI command for generating Frida TypeScript/JS live runtime tracing scripts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Literal

from reforge.utils.address import format_address
from reforge.utils.paths import safe_filename


def generate_frida_trace_script(
    symbol: str | None = None,
    class_name: str | None = None,
    address: str | None = None,
    assembly: str = "Assembly-CSharp",
    module: str | None = None,
) -> str:
    """Generate a clean Frida TypeScript/JS tracing script."""
    if class_name:
        class_literal = json.dumps(class_name)
        assembly_literal = json.dumps(assembly)
        module_guard = ""
        if module:
            module_literal = json.dumps(module)
            module_guard = f"""const runtimeModule = Process.findModuleByName({module_literal});
if (runtimeModule === null) throw new Error("runtime module unresolved: " + {module_literal});
"""
        if symbol:
            symbol_literal = json.dumps(symbol)
            return f"""// Auto-generated Frida IL2CPP Method Tracing Script
// Requires frida-il2cpp-bridge (https://github.com/vfsfitvnm/frida-il2cpp-bridge)

{module_guard}Il2Cpp.perform(() => {{
    const targetClass = Il2Cpp.domain.assembly({assembly_literal}).image.class({class_literal});
    const targetMethod = targetClass.method({symbol_literal});
    if (targetMethod.virtualAddress.isNull()) throw new Error("method address unresolved");
    console.log("[+] Attached to " + targetClass.name + "::" + targetMethod.name);
    Interceptor.attach(targetMethod.virtualAddress, {{
        onEnter(args) {{
            console.log("[+] Enter " + targetClass.name + "::" + targetMethod.name);
        }},
        onLeave(retval) {{
            console.log("[+] Leave " + targetClass.name + "::" + targetMethod.name
                + " -> " + retval);
        }}
    }});
}});
"""
        return f"""// Auto-generated Frida IL2CPP Class Tracing Script
// Requires frida-il2cpp-bridge (https://github.com/vfsfitvnm/frida-il2cpp-bridge)

{module_guard}Il2Cpp.perform(() => {{
    const targetClass = Il2Cpp.domain.assembly({assembly_literal}).image.class({class_literal});
    console.log("[+] Attached to IL2CPP Class: " + targetClass.name);

    targetClass.methods.forEach((method) => {{
        if (method.virtualAddress.isNull()) return;
        Interceptor.attach(method.virtualAddress, {{
            onEnter(args) {{
                console.log("[+] Calling " + targetClass.name + "::" + method.name);
            }}
        }});
    }});
}});
"""

    if symbol:
        symbol_literal = json.dumps(symbol)
        resolver = (
            f"Process.getModuleByName({json.dumps(module)}).findExportByName({symbol_literal})"
            if module
            else f"Module.findGlobalExportByName({symbol_literal})"
        )
        return f"""// Auto-generated Frida Native Export Tracing Script
const targetAddress = {resolver};
if (targetAddress === null || targetAddress.isNull()) {{
    throw new Error("native export unresolved: " + {symbol_literal});
}}
console.log("[+] Intercepting export " + {symbol_literal} + " at " + targetAddress);
Interceptor.attach(targetAddress, {{
        onEnter(args) {{
            console.log("[+] " + {symbol_literal} + " onEnter - self: " + args[0] + ", arg1: " + args[1]);
        }},
        onLeave(retval) {{
            console.log("[+] " + {symbol_literal} + " onLeave - return value: " + retval);
        }}
}});
"""

    if address is None:
        raise ValueError("Trace generation requires --class, --symbol, or --address")
    addr_val = format_address(address)
    mod_str = json.dumps(module) if module else "null"
    return f"""// Auto-generated Frida ASLR-Aware Address Interceptor Script
const modName = {mod_str};
const mod = modName
    ? Process.findModuleByName(modName)
    : (Process.findModuleByName("libil2cpp.so")
       || Process.findModuleByName("GameAssembly.dll")
       || Process.findModuleByName("UnityFramework")
       || Process.findModuleByName("GameAssembly.so")
       || Process.enumerateModules()[0]);
if (!mod) throw new Error("Could not resolve module for address tracing");
const targetAddress = mod.base.add(ptr({json.dumps(addr_val)}));

console.log(
    "[+] Intercepting address "
    + {json.dumps(addr_val)}
    + " (Module: "
    + mod.name
    + " @ "
    + mod.base
    + " -> "
    + targetAddress
    + ")"
);

try {{
    Interceptor.attach(targetAddress, {{
        onEnter(args) {{
            console.log("[+] Enter " + {json.dumps(addr_val)} + " - arg0: " + args[0] + ", arg1: " + args[1]);
        }},
        onLeave(retval) {{
            console.log("[+] Leave " + {json.dumps(addr_val)} + " -> " + retval);
        }}
    }});
}} catch (err) {{
    console.log("[-] Interceptor failed at " + targetAddress + ": " + err.message);
}}
"""


def cmd_trace(args: argparse.Namespace) -> int:
    """Execute Frida trace script generation and optional live execution."""
    symbol = args.symbol
    class_name = getattr(args, "class_name", None)
    address = args.address
    if not symbol and not class_name and not address:
        print("Error: trace requires --class, --symbol, or --address", file=sys.stderr)
        return 2
    if address and (symbol or class_name):
        print("Error: --address cannot be combined with --class or --symbol", file=sys.stderr)
        return 2

    attach_target = getattr(args, "attach", None)
    spawn_target = getattr(args, "spawn", None)
    use_usb = getattr(args, "usb", False)
    remote_host = getattr(args, "host", None)
    if (use_usb or remote_host) and not (attach_target or spawn_target):
        print("Error: --usb/--host requires --attach or --spawn", file=sys.stderr)
        return 2

    target_name = symbol or class_name or address or "trace"
    print(f"[*] Generating Frida runtime trace script for {target_name}...")

    script = generate_frida_trace_script(
        symbol=symbol,
        class_name=class_name,
        address=address,
        assembly=getattr(args, "assembly", "Assembly-CSharp"),
        module=getattr(args, "module", None),
    )
    out_path = Path(args.output or safe_filename(f"trace_{target_name}", suffix=".ts"))
    out_path.write_text(script, encoding="utf-8")
    print(f"[+] Successfully generated Frida trace script: {out_path}")

    if attach_target or spawn_target:
        print("[*] Initiating live Frida tracing session...")
        from reforge.dynamic.frida_runner import (
            FridaSessionConfig,
            is_frida_available,
            run_frida_session,
        )

        timeout = getattr(args, "timeout", None)
        timeout_sec = float(timeout) if timeout is not None else None

        if is_frida_available():
            target_str = spawn_target or attach_target or ""
            target_val: int | str = int(target_str) if target_str.isdigit() else target_str
            mode_val: Literal["spawn", "attach"] = "spawn" if spawn_target else "attach"
            device_val: Literal["local", "usb", "remote"] = "usb" if use_usb else ("remote" if remote_host else "local")
            cfg = FridaSessionConfig(
                target=target_val,
                mode=mode_val,
                device_type=device_val,
                remote_address=remote_host,
            )
            try:
                res = run_frida_session(
                    cfg,
                    script,
                    duration=timeout_sec,
                    stream_to_stdout=True,
                )
                if res.error:
                    print(f"[!] Live tracing error: {res.error}", file=sys.stderr)
                    return 1
                return 0
            except KeyboardInterrupt:
                print("\n[*] Live tracing interrupted by user.", file=sys.stderr)
                return 130
            except Exception as exc:
                print(f"[!] Live tracing runner error: {exc}", file=sys.stderr)
                return 1

        cmd = ["frida"]
        if use_usb:
            cmd.append("-U")
        elif remote_host:
            cmd.extend(["-H", remote_host])

        if spawn_target:
            cmd.extend(["-f", spawn_target])
        elif attach_target:
            if str(attach_target).isdigit():
                cmd.extend(["-p", str(attach_target)])
            else:
                cmd.extend(["-n", attach_target])

        cmd.extend(["-l", str(out_path)])
        try:
            print(f"[*] Running CLI command: {' '.join(cmd)}")
            if timeout is not None:
                subprocess.run(cmd, check=True, timeout=timeout)
            else:
                subprocess.run(cmd, check=True)
        except subprocess.TimeoutExpired:
            print(f"[*] Live tracing session completed ({timeout}s limit reached).", file=sys.stderr)
            return 0
        except FileNotFoundError:
            print("[!] Neither Python 'frida' module nor 'frida' CLI was found on PATH.", file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as exc:
            print(f"[!] Live tracing session ended: {exc}", file=sys.stderr)
            return exc.returncode or 1
        except KeyboardInterrupt:
            print("\n[*] Live tracing interrupted by user.", file=sys.stderr)
            return 130

    return 0
