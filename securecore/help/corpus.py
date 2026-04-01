"""Manual help corpus for SecureCore."""

from __future__ import annotations

import json
from typing import Any

from securecore.help.config import load_help_config


class HelpCorpus:
    def __init__(self):
        self._config = load_help_config()
        self._entries = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        path = self._config["content_path"]
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def get(self, help_id: str) -> dict[str, Any] | None:
        return self._entries.get(help_id)

    def list_ids(self) -> list[dict[str, str]]:
        return [
            {
                "help_id": help_id,
                "label": entry.get("label", ""),
                "category": entry.get("category", ""),
            }
            for help_id, entry in sorted(self._entries.items())
        ]

    def search(self, query: str) -> list[dict[str, Any]]:
        q = query.lower().strip()
        if not q:
            return []
        results = []
        for help_id, entry in self._entries.items():
            searchable = " ".join([
                help_id,
                entry.get("label", ""),
                entry.get("category", ""),
                json.dumps(entry.get("tier1", {}), sort_keys=True),
                json.dumps(entry.get("tier2", {}), sort_keys=True),
                json.dumps(entry.get("tier3", {}), sort_keys=True),
            ]).lower()
            if q in searchable:
                results.append({
                    "source": "corpus",
                    "help_id": help_id,
                    "label": entry.get("label", ""),
                    "category": entry.get("category", ""),
                    "snippet": entry.get("tier1", {}).get("what", "")[:120],
                })
        return results

    def stats(self) -> dict[str, Any]:
        categories: dict[str, int] = {}
        for entry in self._entries.values():
            category = entry.get("category", "Uncategorized")
            categories[category] = categories.get(category, 0) + 1
        return {
            "total_ids": len(self._entries),
            "categories": categories,
        }
