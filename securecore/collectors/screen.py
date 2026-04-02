"""Screen collector adapters for HID visual signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

try:
    import mss  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    mss = None


DEFAULT_ARC_PALETTE = [
    (0, 0, 0),       # 0 = black
    (0, 116, 217),   # 1 = blue
    (255, 65, 54),   # 2 = red
    (46, 204, 64),   # 3 = green
    (255, 220, 0),   # 4 = yellow
    (170, 170, 170), # 5 = grey
    (240, 18, 190),  # 6 = magenta
    (255, 133, 27),  # 7 = orange
    (127, 219, 255), # 8 = cyan
    (135, 12, 37),   # 9 = dark red
]


@dataclass
class ScreenCaptureSample:
    frame_id: int
    grid: list[list[int]]
    capture_region: str = ""
    operator: str = "local"
    cell_id: str = ""


def _nearest_palette_index(pixel: Sequence[int], palette: Sequence[tuple[int, int, int]]) -> int:
    return min(
        range(len(palette)),
        key=lambda idx: sum((int(pixel[channel]) - int(palette[idx][channel])) ** 2 for channel in range(3)),
    )


def _normalize_pixels(frame_pixels: object) -> list[list[tuple[int, int, int]]]:
    if hasattr(frame_pixels, "tolist"):
        frame_pixels = frame_pixels.tolist()

    rows = []
    for row in frame_pixels or []:
        normalized_row = []
        for pixel in row:
            normalized_row.append((int(pixel[0]), int(pixel[1]), int(pixel[2])))
        if normalized_row:
            rows.append(normalized_row)
    return rows


def quantize_frame(
    frame_pixels: object,
    grid_size: int = 32,
    palette: Sequence[tuple[int, int, int]] | None = None,
) -> list[list[int]]:
    """Resize RGB pixels to a grid and quantize them to ARC palette indices."""
    palette = palette or DEFAULT_ARC_PALETTE
    grid_size = max(1, int(grid_size))
    pixels = _normalize_pixels(frame_pixels)
    if not pixels:
        return [[0] * grid_size for _ in range(grid_size)]

    src_h = len(pixels)
    src_w = len(pixels[0]) if pixels[0] else 0
    if src_w == 0:
        return [[0] * grid_size for _ in range(grid_size)]

    grid: list[list[int]] = []
    for y in range(grid_size):
        src_y = min(src_h - 1, (y * src_h) // grid_size)
        row: list[int] = []
        for x in range(grid_size):
            src_x = min(src_w - 1, (x * src_w) // grid_size)
            pixel = pixels[src_y][src_x]
            row.append(_nearest_palette_index(pixel, palette))
        grid.append(row)
    return grid


class ScreenCollector:
    """Adapter that turns screen frames into HID screen_capture records."""

    def __init__(self, hid_writer, grid_size: int = 32, palette: Sequence[tuple[int, int, int]] | None = None):
        self._hid_writer = hid_writer
        self._grid_size = max(1, int(grid_size))
        self._palette = list(palette or DEFAULT_ARC_PALETTE)
        self._frame_id = 0

    @property
    def is_capture_available(self) -> bool:
        return mss is not None

    def quantize(self, frame_pixels: object) -> list[list[int]]:
        return quantize_frame(frame_pixels, grid_size=self._grid_size, palette=self._palette)

    def build_sample(
        self,
        frame_pixels: object,
        capture_region: str = "",
        operator: str = "local",
        cell_id: str = "",
    ) -> ScreenCaptureSample:
        grid = self.quantize(frame_pixels)
        sample = ScreenCaptureSample(
            frame_id=self._frame_id,
            grid=grid,
            capture_region=capture_region,
            operator=operator,
            cell_id=cell_id,
        )
        self._frame_id += 1
        return sample

    def emit_sample(self, sample: ScreenCaptureSample):
        return self._hid_writer.record_screen_capture(
            grid=sample.grid,
            frame_id=sample.frame_id,
            capture_region=sample.capture_region,
            screen_changed=False,
            change_ratio=0.0,
            operator=sample.operator,
            cell_id=sample.cell_id,
        )

    def emit_frame(
        self,
        frame_pixels: object,
        capture_region: str = "",
        operator: str = "local",
        cell_id: str = "",
    ):
        sample = self.build_sample(
            frame_pixels,
            capture_region=capture_region,
            operator=operator,
            cell_id=cell_id,
        )
        return self.emit_sample(sample)

    def capture_pixels(self, region: tuple[int, int, int, int] | None = None) -> list[list[tuple[int, int, int]]] | None:
        if mss is None:  # pragma: no cover - optional dependency path
            return None

        monitor = {"top": 0, "left": 0, "width": 1920, "height": 1080}
        if region:
            monitor = {
                "left": int(region[0]),
                "top": int(region[1]),
                "width": int(region[2]),
                "height": int(region[3]),
            }

        with mss.mss() as sct:  # pragma: no cover - requires local capture backend
            shot = sct.grab(monitor)
        return [
            [(pixel[2], pixel[1], pixel[0]) for pixel in row]
            for row in shot
        ]

    def capture_and_emit(
        self,
        region: tuple[int, int, int, int] | None = None,
        operator: str = "local",
        cell_id: str = "",
    ):
        pixels = self.capture_pixels(region=region)
        if pixels is None:
            return None
        capture_region = str(region) if region else "full"
        return self.emit_frame(
            pixels,
            capture_region=capture_region,
            operator=operator,
            cell_id=cell_id,
        )
