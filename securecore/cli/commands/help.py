"""Help command — reference help over corpus and code index.

Usage:
    securecore help                         top-level nav
    securecore help search <query>          search corpus + code index
    securecore help show <help_id>          show help entry (default tier 1)
    securecore help show <help_id> --tier 3 explicit tier
    securecore help where <symbol>          code/file mapping
    securecore help doctor                  check for stale index / missing content
    securecore help sync                    rebuild code mirror index
"""

from __future__ import annotations

import sys


def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    codes = {
        "green": "\033[92m", "yellow": "\033[93m", "red": "\033[91m",
        "cyan": "\033[96m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
    }
    return f"{codes.get(color, '')}{text}{codes.get('reset', '')}"


def run(action: str, query: str, tier: int) -> None:
    if action == "search" and query:
        _search(query)
    elif action == "show" and query:
        _show(query, tier)
    elif action == "where" and query:
        _where(query)
    elif action == "doctor":
        _doctor()
    elif action == "sync":
        _sync()
    else:
        _nav()


def _nav() -> None:
    from securecore.help.corpus import HelpCorpus
    corpus = HelpCorpus()
    entries = corpus.list_ids()

    print()
    print(_colorize("  SECURECORE HELP", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()
    print("  Commands:")
    print(f"    {'help search <query>':35s}  search help + code")
    print(f"    {'help show <id> [--tier N]':35s}  show help entry at tier 1/2/3")
    print(f"    {'help where <symbol>':35s}  find code location")
    print(f"    {'help doctor':35s}  check index health")
    print(f"    {'help sync':35s}  rebuild code mirror")
    print()

    if entries:
        print(_colorize("  HELP TOPICS", "cyan"))
        for e in entries:
            print(f"    {_colorize(e['help_id'], 'bold'):30s}  {e.get('category', ''):15s}  {e.get('label', '')}")
    else:
        print(f"  {_colorize('No help content found.', 'yellow')}")
    print()


def _search(query: str) -> None:
    from securecore.help.corpus import HelpCorpus
    from securecore.help.code_index import CodeMirrorIndex

    corpus = HelpCorpus()
    code_index = CodeMirrorIndex()

    corpus_hits = corpus.search(query)
    code_hits = code_index.search(query)

    print()
    print(_colorize(f"  SEARCH: {query}", "bold"))
    print()

    if corpus_hits:
        print(_colorize("  HELP CORPUS", "cyan"))
        for hit in corpus_hits[:10]:
            print(f"    {_colorize(hit['help_id'], 'bold'):25s}  {hit.get('label', '')}  {hit.get('snippet', '')[:60]}")
        print()

    if code_hits:
        print(_colorize("  CODE INDEX", "cyan"))
        for hit in code_hits[:10]:
            symbols = ", ".join(s["name"] for s in hit.get("symbols", [])[:5])
            print(f"    {hit['relative_path']:40s}  {symbols}")
        print()

    if not corpus_hits and not code_hits:
        print(f"  {_colorize('No results found.', 'yellow')}")
        print()


def _show(help_id: str, tier: int) -> None:
    from securecore.help.corpus import HelpCorpus
    corpus = HelpCorpus()
    entry = corpus.get(help_id)

    if not entry:
        print(f"\n  {_colorize(f'Unknown help ID: {help_id}', 'yellow')}")
        print(f"  Try: securecore help search {help_id}\n")
        return

    print()
    print(_colorize(f"  {entry.get('label', help_id)}", "bold"))
    print(_colorize(f"  Category: {entry.get('category', '?')}", "dim"))
    print()

    if tier >= 1:
        t1 = entry.get("tier1", {})
        if t1:
            print(_colorize("  TIER 1 — Quick", "cyan"))
            if t1.get("what"):
                print(f"    What: {t1['what']}")
            if t1.get("when"):
                print(f"    When: {t1['when']}")
            print()

    if tier >= 2:
        t2 = entry.get("tier2", {})
        if t2:
            print(_colorize("  TIER 2 — Concept", "cyan"))
            if t2.get("concept"):
                print(f"    {t2['concept']}")
            if t2.get("misunderstanding"):
                print(f"\n    Common misunderstanding: {t2['misunderstanding']}")
            print()

    if tier >= 3:
        t3 = entry.get("tier3", {})
        if t3:
            print(_colorize("  TIER 3 — Details", "cyan"))
            if t3.get("how"):
                print(f"    How: {t3['how']}")
            if t3.get("files"):
                print(f"    Files: {', '.join(t3['files'])}")
            if t3.get("commands"):
                print(f"    Commands: {', '.join(t3['commands'])}")
            if t3.get("env_vars"):
                print(f"    Env: {', '.join(t3['env_vars'])}")
            if t3.get("failure_modes"):
                print(f"    Failure: {t3['failure_modes']}")
            print()


def _where(query: str) -> None:
    from securecore.help.code_index import CodeMirrorIndex
    code_index = CodeMirrorIndex()
    results = code_index.resolve(query)

    print()
    print(_colorize(f"  WHERE: {query}", "bold"))
    print()

    if not results:
        print(f"  {_colorize('Not found in code index.', 'yellow')}")
        print(f"  Try: securecore help sync  (to rebuild the index)")
        print()
        return

    for result in results[:10]:
        print(f"    {_colorize(result['relative_path'], 'cyan')}")
        for sym in result.get("symbols", [])[:10]:
            print(f"      {sym['kind']:10s}  {sym['name']}  line {sym['line']}")
    print()


def _doctor() -> None:
    from securecore.help.corpus import HelpCorpus
    from securecore.help.code_index import CodeMirrorIndex

    corpus = HelpCorpus()
    code_index = CodeMirrorIndex()
    index = code_index.load()
    warnings = []

    print()
    print(_colorize("  HELP DOCTOR — GROUNDING AUDIT", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    # 1. Corpus health
    stats = corpus.stats()
    print(_colorize("  CORPUS", "cyan"))
    print(f"    entries:    {stats['total_ids']}")
    for cat, count in stats.get("categories", {}).items():
        print(f"      {cat:20s}  {count}")
    print()

    # 2. Code index health
    total_files = index.get("total_files", 0)
    total_symbols = index.get("total_symbols", 0)
    generated = index.get("generated_at", "never")
    stale = code_index._is_stale(index)

    print(_colorize("  CODE INDEX", "cyan"))
    print(f"    files:      {total_files}")
    print(f"    symbols:    {total_symbols}")
    print(f"    generated:  {generated}")
    idx_status = _colorize("STALE", "yellow") if stale else _colorize("CURRENT", "green")
    print(f"    status:     {idx_status}")
    if stale:
        warnings.append("code index is stale — run `securecore help sync`")
    print()

    # 3. Verify command references in help content
    print(_colorize("  COMMAND REFS", "cyan"))
    # Get all known CLI commands from the parser
    from securecore.cli.main import _build_parser
    parser = _build_parser()
    known_commands = {}
    if hasattr(parser, "_subparsers"):
        for action in parser._subparsers._actions:
            if hasattr(action, "choices") and action.choices:
                for subcmd, subparser in action.choices.items():
                    known_commands[subcmd] = {
                        option
                        for sub_action in subparser._actions
                        for option in sub_action.option_strings
                    }

    command_issues = 0
    for help_id in [e["help_id"] for e in corpus.list_ids()]:
        entry = corpus.get(help_id)
        if not entry:
            continue
        t3 = entry.get("tier3", {})
        for cmd in t3.get("commands", []):
            # Extract the subcommand (e.g., "securecore reaper" -> "reaper")
            parts = cmd.strip().split()
            subcmd = parts[1] if len(parts) > 1 else ""
            if subcmd and subcmd not in known_commands and not subcmd.startswith("-"):
                print(f"    {_colorize('MISSING', 'red')}  {help_id} -> {cmd}")
                warnings.append(f"command ref '{cmd}' in {help_id} not found in CLI parser")
                command_issues += 1
                continue

            if subcmd in known_commands:
                known_flags = known_commands[subcmd]
                invalid_flags = [
                    token for token in parts[2:]
                    if token.startswith("-") and token not in known_flags
                ]
                for flag in invalid_flags:
                    print(f"    {_colorize('INVALID', 'red')}  {help_id} -> {cmd}  (unknown flag: {flag})")
                    warnings.append(f"command ref '{cmd}' in {help_id} uses unknown flag {flag}")
                    command_issues += 1
    if command_issues == 0:
        print(f"    {_colorize('all command refs valid', 'green')}")
    print()

    # 4. Verify file references exist in code index or on disk
    print(_colorize("  FILE REFS", "cyan"))
    indexed_paths = {f.get("relative_path", "") for f in index.get("files", [])}
    file_issues = 0
    for help_id in [e["help_id"] for e in corpus.list_ids()]:
        entry = corpus.get(help_id)
        if not entry:
            continue
        t3 = entry.get("tier3", {})
        for fpath in t3.get("files", []):
            if fpath not in indexed_paths:
                # Check disk as fallback
                from pathlib import Path
                from securecore.help.config import load_help_config
                cfg = load_help_config()
                full = Path(cfg["repo_root"]) / fpath
                if not full.exists():
                    print(f"    {_colorize('MISSING', 'red')}  {help_id} -> {fpath}")
                    warnings.append(f"file ref '{fpath}' in {help_id} not found")
                    file_issues += 1
    if file_issues == 0:
        print(f"    {_colorize('all file refs valid', 'green')}")
    print()

    # Summary
    if warnings:
        print(_colorize("  WARNINGS", "yellow"))
        for w in warnings:
            print(f"    - {w}")
    else:
        print(_colorize("  ALL CHECKS PASSED", "green"))
    print()


def _sync() -> None:
    from securecore.help.code_index import CodeMirrorIndex
    code_index = CodeMirrorIndex()
    result = code_index.sync()
    print()
    print(_colorize("  CODE MIRROR SYNCED", "bold"))
    print(f"    files:   {result['files']}")
    print(f"    symbols: {result['symbols']}")
    print(f"    removed: {result['removed']}")
    print(f"    index:   {result['index_path']}")
    print()
