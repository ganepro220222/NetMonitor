from __future__ import annotations
"""
icon_generator.py
-----------------
Generates the application icon on first launch if it doesn't already exist.
Uses Pillow (bundled with Anaconda). Falls back gracefully if unavailable.

Design: dark navy circle with a teal network-pulse graphic.
"""
import os
import math


import sys as _sys
# 打包后 sys.executable 指向 .exe 本身；开发时用 main.py 目录
_BASE = (os.path.dirname(_sys.executable) if getattr(_sys, 'frozen', False)
         else os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ICON_PATH = os.path.join(_BASE, "assets", "icon.png")
ICO_PATH  = os.path.join(_BASE, "assets", "icon.ico")


def ensure_icon() -> str | None:
    """
    Generate the icon files if they don't exist yet.
    Returns the path to icon.png (for CTk's iconphoto), or None on failure.
    """
    if os.path.exists(ICON_PATH):
        # PNG exists — make sure ICO is also present and multi-size.
        # (Older builds only wrote a 16x16 ICO; regenerate if needed.)
        # Regenerate ICO if missing OR suspiciously small.
        # A 16×16-only ICO is a few hundred bytes; a proper multi-size
        # ICO (256,128,64,48,32,16) is typically 50–200 KB.
        # Threshold: anything under 10 KB is certainly incomplete.
        _ico_missing = not os.path.exists(ICO_PATH)
        _ico_tiny    = (not _ico_missing) and os.path.getsize(ICO_PATH) < 10_000
        if _ico_missing or _ico_tiny:
            try:
                from PIL import Image as _Img
                _img = _Img.open(ICON_PATH).convert("RGBA")
                _icon_sizes = [256, 128, 64, 48, 32, 16]
                _frames = [_img.resize((s,s), _Img.LANCZOS).convert("RGBA")
                           for s in _icon_sizes]
                _frames[0].save(ICO_PATH, format="ICO",
                                append_images=_frames[1:])
            except Exception:
                pass
        return ICON_PATH
    try:
        _generate()
        return ICON_PATH
    except Exception as e:
        print(f"[Icon] Could not generate icon: {e}")
        return None


def _generate():
    """Draw the icon with Pillow."""
    from PIL import Image, ImageDraw

    SIZE = 256
    MARGIN = 12
    BG    = (26, 29, 36, 255)       # dark navy
    DOT   = (77, 208, 225, 255)     # teal
    NODE  = (46, 204, 113, 255)     # green
    LINE  = (77, 180, 200, 160)     # semi-transparent teal

    img  = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle
    draw.ellipse([MARGIN, MARGIN, SIZE - MARGIN, SIZE - MARGIN], fill=BG)

    # Outer decorative ring (teal, slightly transparent)
    ring_col = (77, 208, 225, 180)
    draw.arc([MARGIN + 8, MARGIN + 8, SIZE - MARGIN - 8, SIZE - MARGIN - 8],
             0, 360, fill=ring_col, width=6)

    # Center hub dot
    cx, cy = SIZE // 2, SIZE // 2 + 10
    r_hub = 18
    draw.ellipse([cx - r_hub, cy - r_hub, cx + r_hub, cy + r_hub], fill=DOT)

    # Three satellite nodes at 120° intervals
    angles = [270, 30, 150]   # top, bottom-right, bottom-left
    dist   = 72

    for angle in angles:
        rad = math.radians(angle)
        nx  = int(cx + math.cos(rad) * dist)
        ny  = int(cy + math.sin(rad) * dist)
        # Connection line
        draw.line([cx, cy, nx, ny], fill=LINE, width=3)
        # Satellite node
        r_node = 12
        draw.ellipse([nx - r_node, ny - r_node, nx + r_node, ny + r_node], fill=NODE)

    # Small pulse rings around center (network activity suggestion)
    for radius, alpha in [(32, 60), (46, 30)]:
        pulse = (77, 208, 225, alpha)
        draw.arc([cx - radius, cy - radius, cx + radius, cy + radius],
                 0, 360, fill=pulse, width=2)

    # Save PNG
    os.makedirs(os.path.dirname(ICON_PATH), exist_ok=True)
    img.save(ICON_PATH)

    # Also save ICO (multi-size) for Windows taskbar
    # Build ICO without the `sizes` parameter (known PIL compatibility issue)
    # Instead: manually create correctly-sized images and append them.
    try:
        icon_sizes = [256, 128, 64, 48, 32, 16]
        frames = [img.resize((s, s), Image.LANCZOS).convert("RGBA")
                  for s in icon_sizes]
        # Save largest-first; PIL appends the rest as additional ICO entries
        frames[0].save(ICO_PATH, format="ICO", append_images=frames[1:])
    except Exception:
        pass   # ICO save can fail on some PIL versions; PNG alone is fine
