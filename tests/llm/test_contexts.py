"""Tests for typed LLM context bundles and help-context assembly."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from securecore.llm.contexts.help_context import build_help_context
from securecore.llm.contexts.types import ContextBlock, ContextBundle


class _FakeCorpus:
    def search(self, query: str):
        return [{"help_id": "reaper"}] if "reaper" in query else []

    def get(self, help_id: str):
        if help_id == "reaper":
            return {"label": "Reaper", "tier1": {"what": "The Reaper acts."}}
        return None


class _FakeCodeIndex:
    def __init__(self, mirror_path: str):
        self._mirror_path = mirror_path

    def search(self, query: str, limit: int = 5):
        if "reaper" not in query:
            return []
        return [
            {
                "relative_path": "securecore/control/reaper.py",
                "mirror_path": self._mirror_path,
                "symbols": [{"name": "Reaper"}],
            }
        ]


class TestContextBundles(unittest.TestCase):
    def test_bundle_hash_is_canonical_across_input_order(self):
        block_a = ContextBlock.build("code_index", "a.py", 1, "CODE")
        block_b = ContextBlock.build("help_corpus", "help.json", 0, "HELP")

        bundle_one = ContextBundle.build([block_a, block_b])
        bundle_two = ContextBundle.build([block_b, block_a])

        self.assertEqual(bundle_one.bundle_hash, bundle_two.bundle_hash)
        self.assertEqual([b.source_label for b in bundle_one.blocks], ["help_corpus", "code_index"])

    def test_help_context_hydrates_mirrored_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mirror_path = os.path.join(tmpdir, "reaper.py")
            with open(mirror_path, "w", encoding="utf-8") as handle:
                handle.write("class Reaper:\n    pass\n")

            bundle, metadata = build_help_context(
                question="how does reaper work",
                corpus=_FakeCorpus(),
                code_index=_FakeCodeIndex(mirror_path),
                include_runtime=False,
                max_context_chars=4000,
            )

            self.assertEqual(metadata["corpus_hits"], 1)
            self.assertEqual(metadata["code_hits"], 1)
            self.assertFalse(metadata["runtime_included"])
            self.assertEqual([b.source_label for b in bundle.blocks], ["help_corpus", "code_index"])
            code_block = bundle.blocks[1]
            self.assertIn("class Reaper", code_block.content)
