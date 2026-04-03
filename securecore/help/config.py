"""Configuration for the SecureCore help subsystem."""

from __future__ import annotations

import os
from pathlib import Path


def load_help_config() -> dict:
    repo_root = Path(__file__).resolve().parent.parent.parent
    securecore_root = repo_root / "securecore"
    help_root = Path(os.getenv("SECURECORE_HELP_DIR", securecore_root / "data" / "help"))
    local_model = (
        os.getenv("SECURECORE_LOCAL_MODEL")
        or os.getenv("SECURECORE_OLLAMA_MODEL")
        or os.getenv("SECURECORE_HELP_MODEL")
        or "auto"
    )

    return {
        "repo_root": repo_root,
        "securecore_root": securecore_root,
        "help_root": help_root,
        "mirror_dir": help_root / "mirror",
        "index_path": help_root / "code_index.json",
        "manifest_path": help_root / "mirror_manifest.jsonl",
        "content_path": Path(os.getenv("SECURECORE_HELP_CONTENT", Path(__file__).resolve().parent / "content" / "help_content.json")),
        "system_prompt_path": Path(os.getenv("SECURECORE_HELP_PROMPT", repo_root / "docs" / "operations" / "SecureCore Help Bot System Prompt.md")),
        "include_roots": [
            securecore_root,
            repo_root / "tests",
            repo_root / "README.md",
        ],
        "exclude_dirs": {
            ".git",
            ".pytest_cache",
            "__pycache__",
            "node_modules",
            "venv",
            ".venv",
            "instance",
            "data",
            "logs",
            "docs",
        },
        "exclude_suffixes": {
            ".pyc",
            ".pyo",
            ".db",
            ".sqlite",
            ".sqlite3",
            ".jsonl",
        },
        "exclude_names": {
            ".env",
        },
        "mirror_extensions": {
            ".py",
            ".md",
            ".txt",
            ".json",
            ".html",
            ".js",
            ".css",
            ".toml",
            ".yaml",
            ".yml",
        },
        "local_model": local_model,
        "ollama_host": os.getenv("SECURECORE_OLLAMA_HOST", "http://127.0.0.1:11434"),
        "max_context_chars": int(os.getenv("SECURECORE_HELP_MAX_CONTEXT_CHARS", "24000")),
        "default_tier": int(os.getenv("SECURECORE_HELP_DEFAULT_TIER", "1")),
        "search_limit": int(os.getenv("SECURECORE_HELP_SEARCH_LIMIT", "12")),
    }
