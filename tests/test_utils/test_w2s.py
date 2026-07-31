"""Unit tests for World-to-Screen (W2S) matrix projection utility."""

from __future__ import annotations

from re_agent.utils.w2s import Matrix4x4, Vector3, generate_w2s_cpp_helper, world_to_screen


def test_world_to_screen_center() -> None:
    # Identity view matrix
    identity_matrix = Matrix4x4(
        (
            (1.0, 0.0, 0.0, 0.0),
            (0.0, 1.0, 0.0, 0.0),
            (0.0, 0.0, 1.0, 0.0),
            (0.0, 0.0, 0.0, 1.0),
        )
    )

    # Point at origin (0, 0, 0) clip_w = 1.0, NDC = (0, 0)
    screen_pos = world_to_screen(
        world_pos=Vector3(0.0, 0.0, 0.0),
        view_matrix=identity_matrix,
        screen_width=1920.0,
        screen_height=1080.0,
    )
    assert screen_pos is not None
    assert screen_pos.x == 960.0
    assert screen_pos.y == 540.0


def test_world_to_screen_behind_camera() -> None:
    identity_matrix = Matrix4x4(
        (
            (1.0, 0.0, 0.0, 0.0),
            (0.0, 1.0, 0.0, 0.0),
            (0.0, 0.0, 1.0, 0.0),
            (0.0, 0.0, 0.0, -1.0),  # clip_w < 0
        )
    )

    screen_pos = world_to_screen(
        world_pos=Vector3(0.0, 0.0, 0.0),
        view_matrix=identity_matrix,
        screen_width=1920.0,
        screen_height=1080.0,
    )
    assert screen_pos is None


def test_generate_w2s_cpp_helper() -> None:
    cpp = generate_w2s_cpp_helper()
    assert "WorldToScreen" in cpp
    assert "Matrix4x4" in cpp
