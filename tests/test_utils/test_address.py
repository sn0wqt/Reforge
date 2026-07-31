"""Strict address parsing tests."""

from __future__ import annotations

import pytest

from re_agent.utils.address import normalize_address


@pytest.mark.parametrize("value", ["../secret", "..\\secret", "-1", "0xGG", "1" * 17])
def test_address_rejects_non_hex_or_unbounded_values(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_address(value)
