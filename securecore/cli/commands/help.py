"""Help command — four-tier help system with grounded chat bot.

Usage:
    securecore help                         top-level nav
    securecore help search <query>          search corpus + code index
    securecore help show <help_id>          show help entry (default tier 1)
    securecore help show <help_id> --tier 3 explicit tier
    securecore help where <symbol>          code/file mapping
    securecore help chat "question"         grounded LLM chat (tier 4)
    securecore help doctor                  check for stale index / missing content
    securecore help sync                    rebuild code mirror index
"""

from __future__ import annotations

import json
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
    elif action == "chat" and query:
        _chat(query)
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
    print(f"    {'help chat \"question\"':35s}  ask the help bot (tier 4)")
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


def _chat(question: str) -> None:
    try:
        from securecore.help.config import load_help_config
        from securecore.llm.broker import LLMBroker
        from securecore.help.bot import HelpBot

        config = load_help_config()
        broker = LLMBroker(ollama_host=config["ollama_host"])
        from securecore.cli.common import request_live_command
        from securecore.help.bot import _load_system_prompt
        prompt = _load_system_prompt(config)
        snapshot = request_live_command("registry_snapshot") or {}
        callers = snapshot.get("registry", {}).get("callers", {})
        caller_entry = callers.get("llm:help")
        if not caller_entry:
            print(f"\n  {_colorize('Help bot unavailable: live llm:help caller not registered.', 'yellow')}")
            print(f"  Start SecureCore to use registry-backed help chat.\n")
            return
        broker.register_role(
            role_name="help",
            caller_entry=caller_entry,
            model=config["help_model"],
            system_prompt=prompt,
            max_context_chars=config["max_context_chars"],
        )
        bot = HelpBot(broker)
        print()
        print(_colorize("  HELP BOT (tier 4)", "bold"))
        print(_colorize("  " + "-" * 50, "dim"))
        print()

        result = bot.ask(question)

        # Render structured response
        print(f"  {result['answer']}")

        if result.get("basis"):
            print(f"\n  {_colorize('Basis:', 'cyan')} {', '.join(result['basis'])}")
        if result.get("file_refs"):
            print(f"  {_colorize('Files:', 'cyan')} {', '.join(result['file_refs'])}")
        if result.get("commands"):
            print(f"  {_colorize('Commands:', 'cyan')} {', '.join(result['commands'])}")
        if result.get("unknowns"):
            print(f"  {_colorize('Unknown:', 'yellow')} {', '.join(result['unknowns'])}")

        print()
        structured_tag = "structured" if result.get("structured") else "freeform"
        print(_colorize(f"  Sources: corpus={result['sources']['corpus_hits']} "
                        f"code={result['sources']['code_hits']} "
                        f"runtime={'yes' if result['sources']['runtime_included'] else 'no'} "
                        f"model={result['model']} format={structured_tag}", "dim"))
        print()
    except Exception as exc:
        print(f"\n  {_colorize(f'Help bot unavailable: {exc}', 'yellow')}")
        print(f"  Is ollama running? Try: ollama serve")
        print(f"  Is the model loaded? Try: ollama pull gpt-oss:20b\n")


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
    known_commands = set()
    if hasattr(parser, "_subparsers"):
        for action in parser._subparsers._actions:
            if hasattr(action, "_parser_class"):
                continue
            if hasattr(action, "choices") and action.choices:
                known_commands.update(action.choices.keys())

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

    # 5. Verify LLM roles align with registry
    print(_colorize("  LLM ROLES", "cyan"))
    from securecore.cli.common import request_live_command
    registry_result = request_live_command("registry_snapshot") or {}
    registry_callers = registry_result.get("registry", {}).get("callers", {})
    llm_roles = ["llm:help", "llm:draft", "llm:analyze"]
    for role_id in llm_roles:
        if role_id in registry_callers:
            entry = registry_callers[role_id]
            writes = entry.get("allowed_write", [])
            write_tag = _colorize("read-only", "green") if not writes else _colorize(f"writes={writes}", "red")
            print(f"    {role_id:15s}  {write_tag}")
        else:
            print(f"    {role_id:15s}  {_colorize('NOT IN REGISTRY', 'yellow')}  (start organism to verify)")
    print()

    # 6. Check model availability
    print(_colorize("  MODEL", "cyan"))
    try:
        from securecore.help.config import load_help_config
        cfg = load_help_config()
        from securecore.llm.adapters.ollama import OllamaAdapter
        adapter = OllamaAdapter(host=cfg["ollama_host"], model=cfg["help_model"])
        available = adapter.is_available()
        digest = adapter.model_digest()
        model_status = _colorize("AVAILABLE", "green") if available else _colorize("NOT AVAILABLE", "yellow")
        print(f"    model:      {cfg['help_model']}")
        print(f"    status:     {model_status}")
        if digest:
            print(f"    digest:     {digest[:16]}")
        if not available:
            warnings.append(f"model {cfg['help_model']} not available via ollama")
    except Exception as exc:
        print(f"    {_colorize(f'check failed: {exc}', 'yellow')}")
        warnings.append(f"model check failed: {exc}")
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
