"""Unit tests for re-agent batch CLI command."""
from __future__ import annotations

from pathlib import Path

from re_agent.cli.main import main


def test_cmd_batch_auto_discover(tmp_path: Path) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text(f"""
project_profile:
  name: "ios-arm64"
  language_standard: "C++20"
  source_root: "{tmp_path.as_posix()}/src"
""")

    out_dir = (tmp_path / "src").as_posix()
    args = ["--config", config_file.as_posix(), "batch", "--auto-discover", "--output-dir", out_dir]
    out = main(args)
    assert out == 3
    assert not (tmp_path / "src" / "ReconstructedModule.h").exists()
    assert not (tmp_path / "src" / "ReconstructedModule.cpp").exists()


def test_cmd_batch_symbol(tmp_path: Path) -> None:
    config_file = tmp_path / "re-agent.yaml"
    config_file.write_text(f"""
project_profile:
  name: "generic-cpp"
  source_root: "{tmp_path.as_posix()}/src"
""")

    out_dir = (tmp_path / "src").as_posix()
    args = [
        "--config",
        config_file.as_posix(),
        "batch",
        "--symbol",
        "GetLevel",
        "--class",
        "Player",
        "--output-dir",
        out_dir,
    ]
    out = main(args)
    assert out == 3
    assert not (tmp_path / "src" / "Player.h").exists()


def test_resolve_goal_keywords_clean() -> None:
    from re_agent.cli.cmd_batch import _match_keyword, resolve_goal_keywords

    keywords = resolve_goal_keywords("avoid hitting obstacles")
    assert "obstacles" in keywords or "hitting" in keywords
    assert resolve_goal_keywords("grant unlimited") == []
    assert _match_keyword("pro", "ProcessManager") is False
    assert _match_keyword("key", "KeyboardController") is False
    assert _match_keyword("currency", "PlayerCurrencyManager") is True


def test_known_domain_goal_does_not_spend_an_llm_call() -> None:
    from re_agent.cli.cmd_batch import resolve_goal_keywords

    class FailIfCalled:
        def send(self, _messages, **_kwargs):
            raise AssertionError("known domain expansion must remain local")

    keywords = resolve_goal_keywords(
        "grant unlimited diamonds",
        provider=FailIfCalled(),
    )

    assert "diamonds" in keywords
    assert "wallet" in keywords


def test_rank_classes_by_relevance_wrapper_penalty() -> None:
    from re_agent.cli.cmd_batch import rank_classes_by_relevance

    candidates = [
        ("ThemeEffectCollision", [{"name": "OnHit"}], []),
        ("CharacterCollision", [{"name": "OnHit"}], []),
    ]
    keywords = ["collision", "character"]
    ranked = rank_classes_by_relevance(candidates, keywords)

    # CharacterCollision should rank higher than ThemeEffectCollision due to wrapper penalty on Theme/Effect
    top_class = ranked[0][0]
    assert top_class == "CharacterCollision"


def test_only_exact_executable_dex_override_is_activation_ready() -> None:
    from re_agent.cli.cmd_batch import _method_activation_facts

    evidence = {
        "descriptor": "()I",
        "return_type": "int",
        "is_declared": True,
        "is_executable": True,
        "is_constructor": False,
        "is_static": False,
    }

    assert _method_activation_facts(
        "android-java-dex",
        evidence,
        "return_override",
    ) == {
        "signature_verified": True,
        "address_verified": True,
        "implementation_ready": True,
    }
    evidence["is_executable"] = False
    assert not any(
        _method_activation_facts(
            "android-java-dex",
            evidence,
            "return_override",
        ).values()
    )
