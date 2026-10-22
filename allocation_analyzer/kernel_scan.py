from __future__ import annotations

from pathlib import Path
from typing import Any


SYSCALL_PREFIX = "__x64_sys_"
ALLOCATORS = {
    "__kmalloc": "slab",
    "kmalloc": "slab",
    "kzalloc": "slab",
    "kcalloc": "slab",
    "krealloc": "slab",
    "kmem_cache_alloc": "slab",
    "kmem_cache_zalloc": "slab",
    "vmalloc": "mapping",
    "vmalloc_node": "mapping",
    "vmalloc_user": "mapping",
    "vzalloc": "mapping",
    "vmap": "mapping",
}


class KernelScanError(ValueError):
    pass


def scan_kernel(binary: Path, *, analyzer_types: tuple[type, type, type], syscall_prefix: str = SYSCALL_PREFIX,
                max_entries: int = 500, analyze_entry: str | None = None,
                max_steps: int = 512, max_states: int = 256,
                timeout_seconds: int = 30) -> dict[str, Any]:
    """Index syscall-to-allocation callgraph candidates in one trusted x86-64 vmlinux."""
    import angr
    import networkx as nx

    binary = binary.resolve()
    if not binary.is_file() or binary.stat().st_size > 256 * 1024 * 1024:
        raise KernelScanError("binary must be a readable ELF file no larger than 256 MiB")
    with binary.open("rb") as stream:
        signature = stream.read(4)
    if signature != b"\x7fELF":
        raise KernelScanError("binary must be an ELF file")
    if not syscall_prefix or len(syscall_prefix) > 64:
        raise KernelScanError("syscall-prefix must contain 1 through 64 characters")

    project = angr.Project(str(binary), auto_load_libs=False)
    main_object = project.loader.main_object
    if main_object.arch.name != "AMD64":
        raise KernelScanError("only ELF x86-64 kernel images are supported")
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    functions = cfg.kb.functions
    graph = cfg.kb.callgraph

    entries: dict[str, int] = {}
    for symbol in main_object.symbols:
        if (symbol.name.startswith(syscall_prefix) and symbol.is_function and
                not symbol.is_import and symbol.rebased_addr in functions):
            entries.setdefault(symbol.name, symbol.rebased_addr)
    allocators: dict[str, tuple[int, str]] = {}
    for name, category in ALLOCATORS.items():
        symbol = main_object.get_symbol(name)
        if symbol is not None and symbol.is_function and not symbol.is_import:
            allocators[name] = (symbol.rebased_addr, category)

    selected = sorted(entries.items())[:max_entries]
    results = []
    for name, address in selected:
        candidates = []
        for allocator, (allocator_address, category) in allocators.items():
            try:
                path = nx.shortest_path(graph, address, allocator_address)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            candidates.append({
                "allocator": allocator,
                "category": category,
                "status": "syntactic_candidate",
                "call_chain": [functions[node].name if node in functions else f"sub_{node:x}" for node in path],
            })
        results.append({
            "entry": name,
            "status": "syntactic_candidate_observed" if candidates else "unknown_no_candidate_observed",
            "candidates": candidates,
            "symbolic_analysis": "not_run",
            "unknown": [] if candidates else ["cfg_callgraph_did_not_show_a_path"],
        })

    result: dict[str, Any] = {
        "schema_version": 1,
        "mode": "kernel_static_scan",
        "binary": str(binary),
        "architecture": "ELF x86-64",
        "cfg": "angr.CFGFast",
        "syscall_prefix": syscall_prefix,
        "symbols": {
            "syscall_entries_discovered": len(entries),
            "syscall_entries_scanned": len(selected),
            "syscall_entries_omitted_by_limit": max(0, len(entries) - len(selected)),
            "allocation_symbols_found": {name: category for name, (_, category) in sorted(allocators.items())},
            "allocation_symbols_missing": sorted(set(ALLOCATORS) - set(allocators)),
        },
        "entries": results,
        "interpretation": (
            "Callgraph paths are syntactic candidates only. No path found is not evidence of unreachability. "
            "Kernel boot state, syscall register frames, external state, and allocator side effects are not modeled."
        ),
    }
    if analyze_entry is not None:
        result["bounded_symbolic_analysis"] = _analyze_entry(
            binary, analyze_entry, allocators, max_steps, max_states, timeout_seconds, analyzer_types,
        )
    return result


def _analyze_entry(binary: Path, entry: str, allocators: dict[str, tuple[int, str]],
                   max_steps: int, max_states: int, timeout_seconds: int,
                   analyzer_types: tuple[type, type, type]) -> dict[str, Any]:
    Analyzer, Config, Input = analyzer_types

    import angr

    project = angr.Project(str(binary), auto_load_libs=False)
    symbol = project.loader.find_symbol(entry)
    if symbol is None or not symbol.is_function or symbol.is_import:
        return {"entry": entry, "status": "unknown_entry_symbol", "witnesses": [],
                "unknown": ["syscall_symbol_not_found"]}
    categories = {name: category for name, (_, category) in allocators.items()}
    config = Config(
        binary=binary,
        entry=entry,
        inputs=(Input("syscall_context", 64),),
        allocators=categories,
        max_steps=max_steps,
        max_states=max_states,
        timeout_seconds=timeout_seconds,
        seeds=(),
        random_seed=0,
        random_trials=0,
    )
    try:
        report = Analyzer(config).analyze()
    except Exception as exc:
        return {
            "entry": entry,
            "status": "unknown_execution_error",
            "unknown": [f"{type(exc).__name__}:{str(exc)[:240]}"],
            "witnesses": [],
            "kernel_state": "not_modeled",
        }
    analysis = report["analysis"]
    return {
        "entry": entry,
        "status": "exploratory_bounded_model",
        "kernel_state": "not_modeled",
        "syscall_context_input": "one symbolic 64-bit value; not a modeled pt_regs or user-memory frame",
        "claim_limit": "Witnesses describe this incomplete angr model only, not a reachable kernel behavior or exploit input.",
        "model_status": analysis["status"],
        "candidate_paths": analysis["candidate_paths"],
        "model_witnesses": [dict(witness, status="bounded_model_witness") for witness in analysis["witnesses"]],
        "unknown": analysis["unknown"],
        "metrics": analysis["metrics"],
    }
