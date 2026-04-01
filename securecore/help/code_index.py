"""Detached code mirror and index for SecureCore help/dev support."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, UTC
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

from securecore.help.config import load_help_config


@dataclass(slots=True)
class IndexedSymbol:
    name: str
    kind: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "line": self.line}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _should_include(path: Path, config: dict) -> bool:
    if path.name in config["exclude_names"]:
        return False
    if path.suffix.lower() in config["exclude_suffixes"]:
        return False
    if path.suffix.lower() not in config["mirror_extensions"]:
        return False
    for parent in path.parents:
        if parent.name in config["exclude_dirs"]:
            return False
    return True


class _SymbolVisitor(ast.NodeVisitor):
    def __init__(self):
        self.symbols: list[IndexedSymbol] = []
        self._class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = ".".join([*self._class_stack, node.name]) if self._class_stack else node.name
        self.symbols.append(IndexedSymbol(name=qualified, kind="class", line=node.lineno))
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, "async_function")

    def _visit_function(self, node, kind: str) -> None:
        qualified = ".".join([*self._class_stack, node.name]) if self._class_stack else node.name
        symbol_kind = "method" if self._class_stack else kind
        self.symbols.append(IndexedSymbol(name=qualified, kind=symbol_kind, line=node.lineno))
        self.generic_visit(node)


class CodeMirrorIndex:
    def __init__(self):
        self.config = load_help_config()
        self.repo_root: Path = self.config["repo_root"]
        self.mirror_dir: Path = self.config["mirror_dir"]
        self.index_path: Path = self.config["index_path"]
        self.manifest_path: Path = self.config["manifest_path"]

    def sync(self, force: bool = False) -> dict[str, Any]:
        self.mirror_dir.mkdir(parents=True, exist_ok=True)
        files: list[dict[str, Any]] = []
        mirrored_paths: set[Path] = set()

        for root in self.config["include_roots"]:
            root_path = Path(root)
            if not root_path.exists():
                continue
            if root_path.is_file():
                result = self._mirror_file(root_path)
                if result:
                    files.append(result)
                    mirrored_paths.add(self.mirror_dir / result["relative_path"])
                continue

            for path in root_path.rglob("*"):
                if not path.is_file():
                    continue
                if not _should_include(path, self.config):
                    continue
                result = self._mirror_file(path)
                if result:
                    files.append(result)
                    mirrored_paths.add(self.mirror_dir / result["relative_path"])

        existing_mirror_files = {path for path in self.mirror_dir.rglob("*") if path.is_file()}
        removed = 0
        for stale in existing_mirror_files - mirrored_paths:
            stale.unlink()
            removed += 1

        now = datetime.now(UTC)
        index = {
            "generated_at": now.isoformat(),
            "generated_epoch": now.timestamp(),
            "repo_root": str(self.repo_root),
            "mirror_dir": str(self.mirror_dir),
            "total_files": len(files),
            "total_symbols": sum(len(entry.get("symbols", [])) for entry in files),
            "files": files,
        }
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")

        with open(self.manifest_path, "w", encoding="utf-8") as handle:
            for entry in files:
                handle.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

        return {
            "files": len(files),
            "symbols": index["total_symbols"],
            "removed": removed,
            "index_path": str(self.index_path),
            "mirror_dir": str(self.mirror_dir),
        }

    def _mirror_file(self, path: Path) -> dict[str, Any] | None:
        relative_path = _safe_relative(path, self.repo_root)
        mirror_path = self.mirror_dir / relative_path
        mirror_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, mirror_path)

        entry = {
            "relative_path": relative_path,
            "source_path": str(path),
            "mirror_path": str(mirror_path),
            "sha256": _sha256(path),
            "size": path.stat().st_size,
            "kind": path.suffix.lower().lstrip(".") or "text",
            "symbols": [],
        }
        if path.suffix.lower() == ".py":
            entry["symbols"] = [symbol.to_dict() for symbol in self._extract_python_symbols(path)]
        return entry

    def _extract_python_symbols(self, path: Path) -> list[IndexedSymbol]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        visitor = _SymbolVisitor()
        visitor.visit(tree)
        return visitor.symbols

    def load(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"files": [], "total_files": 0, "total_symbols": 0}
        with open(self.index_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def ensure_current(self) -> dict[str, Any]:
        index = self.load()
        if self._is_stale(index):
            return self.sync()
        return {
            "files": index.get("total_files", 0),
            "symbols": index.get("total_symbols", 0),
            "removed": 0,
            "index_path": str(self.index_path),
            "mirror_dir": str(self.mirror_dir),
            "fresh": True,
        }

    def _is_stale(self, index: dict[str, Any]) -> bool:
        generated_epoch = float(index.get("generated_epoch", 0))
        if not generated_epoch:
            return True
        for root in self.config["include_roots"]:
            root_path = Path(root)
            if not root_path.exists():
                continue
            if root_path.is_file():
                if root_path.stat().st_mtime > generated_epoch:
                    return True
                continue
            for path in root_path.rglob("*"):
                if not path.is_file():
                    continue
                if not _should_include(path, self.config):
                    continue
                if path.stat().st_mtime > generated_epoch:
                    return True
        return False

    def search(self, query: str, limit: int | None = None) -> list[dict[str, Any]]:
        index = self.load()
        q = query.lower().strip()
        if not q:
            return []
        limit = limit or self.config["search_limit"]
        results: list[dict[str, Any]] = []
        for entry in index.get("files", []):
            path_text = entry["relative_path"].lower()
            symbol_names = " ".join(symbol["name"] for symbol in entry.get("symbols", [])).lower()
            if q in path_text or q in symbol_names:
                results.append({
                    "source": "code",
                    "relative_path": entry["relative_path"],
                    "mirror_path": entry["mirror_path"],
                    "symbols": entry.get("symbols", []),
                })
        return results[:limit]

    def resolve(self, query: str, limit: int | None = None) -> list[dict[str, Any]]:
        index = self.load()
        q = query.strip().lower()
        limit = limit or self.config["search_limit"]
        exact: list[dict[str, Any]] = []
        fuzzy: list[dict[str, Any]] = []

        for entry in index.get("files", []):
            relative_path = entry["relative_path"]
            path_lower = relative_path.lower()
            matched_symbols = [symbol for symbol in entry.get("symbols", []) if q == symbol["name"].lower()]
            if q == path_lower or matched_symbols:
                exact.append({
                    "relative_path": relative_path,
                    "mirror_path": entry["mirror_path"],
                    "symbols": matched_symbols or entry.get("symbols", []),
                })
            else:
                fuzzy_symbols = [symbol for symbol in entry.get("symbols", []) if q in symbol["name"].lower()]
                if q in path_lower or fuzzy_symbols:
                    fuzzy.append({
                        "relative_path": relative_path,
                        "mirror_path": entry["mirror_path"],
                        "symbols": fuzzy_symbols or entry.get("symbols", []),
                    })

        return (exact + fuzzy)[:limit]
