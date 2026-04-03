import unittest

from securecore.chat.projection import get_block, project_blocks


class ChatProjectionTests(unittest.TestCase):
    def test_project_blocks_splits_paragraphs_and_keeps_code_fences(self):
        content = "First paragraph.\n\nSecond paragraph.\n\n```python\nprint('hi')\n```"
        blocks = project_blocks(content)

        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[0].block_id, "b0")
        self.assertEqual(blocks[1].content, "Second paragraph.")
        self.assertEqual(blocks[2].block_type, "code")
        self.assertEqual(blocks[2].language, "python")

    def test_get_block_returns_none_for_unknown_block(self):
        self.assertIsNone(get_block("Only one paragraph.", "b9"))


if __name__ == "__main__":
    unittest.main()
