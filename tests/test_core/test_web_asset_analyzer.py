"""Packaged WebView source-map discovery and patch tests."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from reforge.core.candidates import split_candidates
from reforge.core.web_asset_analyzer import (
    discover_web_asset_candidates,
    patch_web_entry_bundle,
    render_web_response_interceptor,
)


def _write_web_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "web.apk"
    sources = [
        "../../src/features/spark/hooks/useGetSparkBalance/getSparkBalance.options.ts",
        "../../src/features/spark/hooks/useGetSparkBalance/useInvalidateSparkBalance.ts",
        "../../src/features/profile/hooks/useGetMyProfile/getMyProfile.options.ts",
        "../../src/features/subscription/utils/isPremium.ts",
    ]
    contents = [
        "const getSparkWalletUrl = 'spark/wallet';\nconst queryFn = () => PrivateApi.get(getSparkWalletUrl).json();",
        "function set(newBalance: number) {\n  client.setQueryData(key, { wallet: { balance: newBalance } });\n}\n",
        "const getMyProfileUrl = 'profiles/@me';\nconst queryFn = () => PrivateApi.get(getMyProfileUrl).json();",
        "export function isPremium(profile) {\n  return profile?.isPremium ?? false;\n}\n",
    ]
    source_map = json.dumps(
        {
            "version": 3,
            "file": "app.js",
            "sources": sources,
            "sourcesContent": contents,
            "names": [],
            "mappings": "",
        }
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(
            "assets/public/index.html",
            '<script type="module" src="./assets/app.js"></script>',
        )
        archive.writestr("assets/public/assets/app.js", "export const app = true;\n")
        archive.writestr("assets/public/assets/app.js.map", source_map)
        archive.writestr("classes.dex", b"dex")
    return apk


def test_web_source_maps_recover_unknown_currency_response_path(tmp_path: Path) -> None:
    apk = _write_web_apk(tmp_path)

    targets, evidence, source_count = discover_web_asset_candidates(
        apk,
        "grant unlimited sparks",
        tmp_path,
    )
    primary = split_candidates(targets, goal_prompt="grant unlimited sparks").primary

    assert source_count == 4
    assert primary
    assert primary[0].target == "wallet.balance"
    assert primary[0].endpoint_pattern == "spark/wallet"
    assert primary[0].return_value == "9007199254740991"
    assert primary[0].implementation_ready
    assert "useGetSparkBalance" in evidence.read_text(encoding="utf-8")


def test_web_source_maps_recover_subscription_predicate(tmp_path: Path) -> None:
    apk = _write_web_apk(tmp_path)

    targets, _evidence, _source_count = discover_web_asset_candidates(
        apk,
        "unlock ace subscription",
        tmp_path,
    )
    primary = split_candidates(targets, goal_prompt="unlock ace subscription").primary

    assert primary
    assert primary[0].target == "profile.isPremium"
    assert primary[0].endpoint_pattern == "profiles/@me"
    assert primary[0].return_value == "true"


def test_web_entry_patch_contains_only_selected_verified_rules(tmp_path: Path) -> None:
    apk = _write_web_apk(tmp_path)
    targets, _evidence, _source_count = discover_web_asset_candidates(
        apk,
        "grant unlimited sparks",
        tmp_path,
    )
    primary = list(split_candidates(targets, goal_prompt="grant unlimited sparks").primary)
    entry = tmp_path / "app.js"
    entry.write_text("export const app = true;\n", encoding="utf-8")

    modified, notes = patch_web_entry_bundle(entry, primary, tmp_path)

    assert modified is not None
    patched = modified.read_text(encoding="utf-8")
    assert '"endpoint":"spark/wallet"' in patched
    assert '"path":["wallet","balance"]' in patched
    assert "originalFetch" in patched
    assert "export const app = true" in patched
    assert any("server-side authorization" in note for note in notes)
    assert render_web_response_interceptor(primary) in patched


def test_web_endpoint_matching_splits_camel_case_response_roots(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "web-endpoints.apk"
    source_map = json.dumps(
        {
            "version": 3,
            "file": "app.js",
            "sources": [
                "../../src/features/spark/api.ts",
                "../../src/features/subscription/dialog.tsx",
            ],
            "sourcesContent": [
                "const sparkUrl = 'spark/wallet';\nPrivateApi.get(sparkUrl).json();",
                "const duoUrl = 'duo/balance';\n"
                "PrivateApi.get(duoUrl).json();\n"
                "const shown = sparkWallet.wallet.balance;",
            ],
            "names": [],
            "mappings": "",
        }
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/public/assets/app.js.map", source_map)

    targets, _evidence, _source_count = discover_web_asset_candidates(
        apk,
        "grant unlimited sparks",
        tmp_path,
    )

    wallet_targets = [target for target in targets if target.json_path == "wallet.balance"]
    assert wallet_targets
    assert all(target.endpoint_pattern == "spark/wallet" for target in wallet_targets)
    assert not any(target.endpoint_pattern == "duo/balance" and target.implementation_ready for target in targets)
