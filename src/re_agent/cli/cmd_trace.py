"""CLI command for generating Frida TypeScript/JS live runtime tracing scripts."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from re_agent.utils.address import format_address
from re_agent.utils.paths import safe_filename


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
        if symbol:
            symbol_literal = json.dumps(symbol)
            return f"""// Auto-generated Frida IL2CPP Method Tracing Script
// Requires frida-il2cpp-bridge (https://github.com/vfsfitvnm/frida-il2cpp-bridge)

Il2Cpp.perform(() => {{
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

Il2Cpp.perform(() => {{
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
    return f"""// Auto-generated Frida Absolute Address Interceptor Script
const targetAddress = ptr({json.dumps(addr_val)});

console.log("[+] Intercepting raw address at: " + targetAddress);

Interceptor.attach(targetAddress, {{
    onEnter(args) {{
        console.log("[+] Intercepted address {addr_val} - arg0: " + args[0]);
    }},
    onLeave(retval) {{
        console.log("[+] Address {addr_val} returned: " + retval);
    }}
}});
"""


def cmd_trace(args: argparse.Namespace) -> int:
    """Execute Frida trace script generation."""
    symbol = args.symbol
    class_name = getattr(args, "class_name", None)
    address = args.address
    if not symbol and not class_name and not address:
        print("Error: trace requires --class, --symbol, or --address", file=sys.stderr)
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

    print(f"[✓] Successfully generated Frida trace script: {out_path}")
    return 0
