"""Data model for LLM-analyzed hook targets."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AnalyzedTarget:
    """A single hook target identified by the LLM from IL2CPP metadata.

    Attributes:
        class_name: The IL2CPP class to target (e.g. ``"WalletModel"``).
        target: Method or field name (e.g. ``"GetCurrency"``, ``"Coins"``).
        offset: Byte offset from ``this`` for fields (e.g. ``0x30``).
            Method addresses are stored separately so field offsets can never
            be mistaken for executable addresses.
        method_rva: Relative virtual address for a method, when the metadata
            explicitly labels it as an RVA.
        parameter_types: Exact Java/Frida parameter type names recovered from
            a DEX prototype. Empty when the signature is unavailable.
        method_descriptor: Original DEX method descriptor, when available.
        hook_type: One of ``"return_override"``, ``"memory_patch"``,
            ``"multi_memory_patch"``,
            ``"skip_call"``, ``"esp_overlay"``, ``"speed_modify"``,
            ``"nop"``.
        return_value: The value to return/set (e.g. ``"999999999"``,
            ``"true"``, ``"0"``).  ``None`` for esp_overlay / nop.
        return_type: C++ return type (e.g. ``"int32_t"``, ``"bool"``,
            ``"float"``, ``"void"``).
        confidence: LLM confidence score 0-100.
        reason: Human-readable explanation of why this target matters.
        signature_verified: Whether a parser recovered a complete callable
            signature, including static/instance and parameter/return ABI.
        address_verified: Whether the runtime module/address/selector identity
            is unambiguous and evidence-backed.
        implementation_ready: Whether the generated scaffold for this hook
            type actually installs and performs the requested behavior.
    """

    class_name: str
    target: str
    offset: int | None = None
    hook_type: str = "return_override"
    return_value: str | None = "999999999"
    return_type: str = "int32_t"
    confidence: int = 50
    reason: str = ""
    method_rva: int | None = None
    parameter_types: tuple[str, ...] = ()
    method_descriptor: str | None = None
    signature_verified: bool = False
    address_verified: bool = False
    implementation_ready: bool = False

    def __post_init__(self) -> None:
        # Normalize LLM aliases to canonical hook types
        alias_map = {
            "patch": "memory_patch",
            "memory": "memory_patch",
            "override": "return_override",
            "skip": "skip_call",
            "speed": "speed_modify",
            "esp": "esp_overlay",
            "js_property": "js_property_patch",
            "js_patch": "js_property_patch",
        }
        if self.hook_type in alias_map:
            self.hook_type = alias_map[self.hook_type]

        valid_types = {
            "return_override",
            "memory_patch",
            "multi_memory_patch",
            "skip_call",
            "esp_overlay",
            "speed_modify",
            "nop",
            "js_property_patch",
        }
        if self.hook_type not in valid_types:
            raise ValueError(f"Invalid hook_type {self.hook_type!r}. Must be one of: {', '.join(sorted(valid_types))}")
        if self.offset is not None and self.hook_type not in {
            "memory_patch",
            "multi_memory_patch",
        }:
            raise ValueError("offset is reserved for field memory-patch targets")
        if self.method_rva is not None and (
            not isinstance(self.method_rva, int)
            or isinstance(self.method_rva, bool)
            or not 0 <= self.method_rva <= 0x7FFF_FFFF_FFFF_FFFF
        ):
            raise ValueError("method_rva must be a non-negative integer")
        if any(
            not isinstance(value, bool)
            for value in (
                self.signature_verified,
                self.address_verified,
                self.implementation_ready,
            )
        ):
            raise ValueError("hook readiness fields must be booleans")
        self.parameter_types = tuple(self.parameter_types)
        if any(
            not isinstance(parameter, str) or not parameter or any(character in parameter for character in "\r\n\x00")
            for parameter in self.parameter_types
        ):
            raise ValueError("parameter_types must contain safe non-empty strings")
