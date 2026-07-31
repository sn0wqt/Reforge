"""World-to-Screen (W2S) 3D-to-2D matrix projection utility for game engines (Unity, Unreal, RenderWare, Source)."""
from __future__ import annotations

from typing import NamedTuple


class Vector2(NamedTuple):
    x: float
    y: float


class Vector3(NamedTuple):
    x: float
    y: float
    z: float


class Matrix4x4(NamedTuple):
    m: tuple[tuple[float, float, float, float], ...]


def world_to_screen(
    world_pos: Vector3,
    view_matrix: Matrix4x4,
    screen_width: float,
    screen_height: float,
) -> Vector2 | None:
    """Translate 3D world coordinates (X, Y, Z) to 2D viewport screen coordinates (X, Y)."""
    m = view_matrix.m

    # Calculate clip space coordinates via matrix multiplication
    clip_x = world_pos.x * m[0][0] + world_pos.y * m[0][1] + world_pos.z * m[0][2] + m[0][3]
    clip_y = world_pos.x * m[1][0] + world_pos.y * m[1][1] + world_pos.z * m[1][2] + m[1][3]
    clip_w = world_pos.x * m[3][0] + world_pos.y * m[3][1] + world_pos.z * m[3][2] + m[3][3]

    # Point is behind camera
    if clip_w < 0.001:
        return None

    # Normalized Device Coordinates (NDC) [-1, 1]
    ndc_x = clip_x / clip_w
    ndc_y = clip_y / clip_w

    # Screen coordinates transformation
    screen_x = (screen_width / 2.0) * (ndc_x + 1.0)
    screen_y = (screen_height / 2.0) * (1.0 - ndc_y)

    return Vector2(screen_x, screen_y)


def generate_w2s_cpp_helper() -> str:
    """Generate reusable C++ WorldToScreen implementation snippet."""
    return """// Auto-generated WorldToScreen C++ Helper for Game Engine Camera Projection
#include <cstdint>

struct Vector2 { float x, y; };
struct Vector3 { float x, y, z; };
struct Matrix4x4 { float m[4][4]; };

bool WorldToScreen(
    const Vector3& world,
    const Matrix4x4& viewMatrix,
    float screenWidth,
    float screenHeight,
    Vector2& outScreen
) {
    float clipX = world.x * viewMatrix.m[0][0] + world.y * viewMatrix.m[0][1]
                + world.z * viewMatrix.m[0][2] + viewMatrix.m[0][3];
    float clipY = world.x * viewMatrix.m[1][0] + world.y * viewMatrix.m[1][1]
                + world.z * viewMatrix.m[1][2] + viewMatrix.m[1][3];
    float clipW = world.x * viewMatrix.m[3][0] + world.y * viewMatrix.m[3][1]
                + world.z * viewMatrix.m[3][2] + viewMatrix.m[3][3];

    if (clipW < 0.001f) {
        return false; // Point behind camera
    }

    float ndcX = clipX / clipW;
    float ndcY = clipY / clipW;

    outScreen.x = (screenWidth / 2.0f) * (ndcX + 1.0f);
    outScreen.y = (screenHeight / 2.0f) * (1.0f - ndcY);

    return true;
}
"""
