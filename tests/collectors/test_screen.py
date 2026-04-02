import unittest

from securecore.collectors.screen import ScreenCollector, quantize_frame


class _FakeHIDWriter:
    def __init__(self):
        self.calls = []

    def record_screen_capture(self, **kwargs):
        self.calls.append(kwargs)
        return {"kind": "screen", "payload": kwargs}


class ScreenCollectorTests(unittest.TestCase):
    def test_quantize_frame_maps_pixels_to_palette_indices(self):
        pixels = [
            [(0, 0, 0), (255, 65, 54)],
            [(46, 204, 64), (255, 220, 0)],
        ]

        grid = quantize_frame(pixels, grid_size=2)

        self.assertEqual(grid, [[0, 2], [3, 4]])

    def test_emit_frame_writes_screen_capture_record(self):
        writer = _FakeHIDWriter()
        collector = ScreenCollector(writer, grid_size=2)
        pixels = [
            [(0, 0, 0), (255, 65, 54)],
            [(46, 204, 64), (255, 220, 0)],
        ]

        result = collector.emit_frame(pixels, capture_region="full")

        self.assertEqual(result["kind"], "screen")
        self.assertEqual(writer.calls[0]["frame_id"], 0)
        self.assertEqual(writer.calls[0]["grid"], [[0, 2], [3, 4]])
        self.assertEqual(writer.calls[0]["capture_region"], "full")
        self.assertFalse(writer.calls[0]["screen_changed"])
        self.assertEqual(writer.calls[0]["change_ratio"], 0.0)

    def test_emit_frame_advances_frame_ids_without_change_inference(self):
        writer = _FakeHIDWriter()
        collector = ScreenCollector(writer, grid_size=2)
        first = [
            [(0, 0, 0), (0, 0, 0)],
            [(0, 0, 0), (0, 0, 0)],
        ]
        second = [
            [(0, 0, 0), (255, 65, 54)],
            [(0, 0, 0), (0, 0, 0)],
        ]

        collector.emit_frame(first, capture_region="full")
        collector.emit_frame(second, capture_region="full")

        self.assertEqual(writer.calls[1]["frame_id"], 1)
        self.assertFalse(writer.calls[1]["screen_changed"])
        self.assertEqual(writer.calls[1]["change_ratio"], 0.0)

    def test_capture_availability_is_false_without_backend(self):
        writer = _FakeHIDWriter()
        collector = ScreenCollector(writer, grid_size=2)
        self.assertIsInstance(collector.is_capture_available, bool)


if __name__ == "__main__":
    unittest.main()
