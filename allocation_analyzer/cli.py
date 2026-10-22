from __future__ import annotations

import argparse
import heapq
import json
import random
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))


SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RETURN_ADDRESS = 0xF00DCAFE
CATEGORIES = {"slab", "mapping", "unknown"}


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Input:
    name: str
    bits: int


@dataclass(frozen=True)
class Config:
    binary: Path
    entry: str
    inputs: tuple[Input, ...]
    allocators: dict[str, str]
    max_steps: int
    max_states: int
    timeout_seconds: int
    seeds: tuple[tuple[int, ...], ...]
    random_seed: int
    random_trials: int


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise InputError(f"{name} must be an integer from {low} through {high}")
    return value


def _symbol(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SYMBOL.fullmatch(value):
        raise InputError(f"{name} must be a plain C symbol name")
    return value


def load_config(filename: Path) -> Config:
    try:
        raw = json.loads(filename.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot read JSON config: {exc}") from exc
    expected = {
        "binary", "entry", "inputs", "allocators", "max_steps", "max_states",
        "timeout_seconds", "seeds", "random_seed", "random_trials",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise InputError(f"config keys must be exactly: {', '.join(sorted(expected))}")
    if not isinstance(raw["binary"], str) or not raw["binary"].strip():
        raise InputError("binary must be a non-empty path")
    binary = (filename.parent / raw["binary"]).resolve()
    try:
        if not binary.is_file() or binary.stat().st_size > 256 * 1024 * 1024:
            raise InputError("binary must be a file no larger than 256 MiB")
        with binary.open("rb") as stream:
            signature = stream.read(4)
        if signature != b"\x7fELF":
            raise InputError("binary must be an ELF file")
    except OSError as exc:
        raise InputError(f"cannot read ELF binary: {exc}") from exc
    inputs_raw = raw["inputs"]
    if not isinstance(inputs_raw, list) or not 1 <= len(inputs_raw) <= 6:
        raise InputError("inputs must declare one through six integer arguments")
    inputs: list[Input] = []
    for index, item in enumerate(inputs_raw):
        if not isinstance(item, dict) or set(item) != {"name", "bits"}:
            raise InputError(f"inputs[{index}] must contain only name and bits")
        bits = _integer(item["bits"], f"inputs[{index}].bits", 8, 64)
        if bits not in {8, 16, 32, 64}:
            raise InputError(f"inputs[{index}].bits must be 8, 16, 32, or 64")
        inputs.append(Input(_symbol(item["name"], f"inputs[{index}].name"), bits))
    if len({item.name for item in inputs}) != len(inputs):
        raise InputError("input names must be unique")
    allocators_raw = raw["allocators"]
    if not isinstance(allocators_raw, dict) or not allocators_raw:
        raise InputError("allocators must map at least one symbol to a category")
    allocators: dict[str, str] = {}
    for name, category in allocators_raw.items():
        name = _symbol(name, "allocator name")
        if not isinstance(category, str) or category not in CATEGORIES:
            raise InputError(f"allocator {name} category must be slab, mapping, or unknown")
        allocators[name] = category
    seeds_raw = raw["seeds"]
    if not isinstance(seeds_raw, list) or len(seeds_raw) > 1000:
        raise InputError("seeds must be a list with at most 1000 entries")
    seeds: list[tuple[int, ...]] = []
    for row_index, row in enumerate(seeds_raw):
        if not isinstance(row, list) or len(row) != len(inputs):
            raise InputError(f"seeds[{row_index}] must contain one value per declared input")
        values = tuple(_integer(value, f"seeds[{row_index}][{column}]", 0, (1 << inputs[column].bits) - 1)
                       for column, value in enumerate(row))
        seeds.append(values)
    return Config(
        binary=binary,
        entry=_symbol(raw["entry"], "entry"),
        inputs=tuple(inputs),
        allocators=allocators,
        max_steps=_integer(raw["max_steps"], "max_steps", 1, 100_000),
        max_states=_integer(raw["max_states"], "max_states", 1, 10_000),
        timeout_seconds=_integer(raw["timeout_seconds"], "timeout_seconds", 1, 300),
        seeds=tuple(seeds),
        random_seed=_integer(raw["random_seed"], "random_seed", 0, 2**32 - 1),
        random_trials=_integer(raw["random_trials"], "random_trials", 0, 10_000),
    )


class Analyzer:
    def __init__(self, config: Config):
        import angr
        import networkx as nx

        self.angr = angr
        self.nx = nx
        self.config = config
        self.project = angr.Project(str(config.binary), auto_load_libs=False)
        if self.project.loader.main_object.arch.name != "AMD64":
            raise InputError("only ELF x86-64 binaries are supported")
        self.entry_symbol = self.project.loader.find_symbol(config.entry)
        if self.entry_symbol is None or self.entry_symbol.is_import:
            raise InputError(f"entry symbol not found in the ELF: {config.entry}")
        self.allocator_symbols = {}
        for name in config.allocators:
            symbol = self.project.loader.find_symbol(name)
            if symbol is None or symbol.is_import:
                raise InputError(f"allocator symbol not found in the ELF: {name}")
            self.allocator_symbols[name] = symbol.rebased_addr
        self.address_names = {address: name for name, address in self.allocator_symbols.items()}
        self.functions = {}
        self.cfg = None

    def build_cfg(self) -> None:
        self.cfg = self.project.analyses.CFGFast(normalize=True, data_references=True)
        self.functions = {address: function.name for address, function in self.cfg.kb.functions.items()}

    def candidates(self) -> list[dict[str, Any]]:
        graph = self.cfg.kb.callgraph
        result = []
        for name, address in self.allocator_symbols.items():
            if self.entry_symbol.rebased_addr not in graph or address not in graph:
                continue
            try:
                path = self.nx.shortest_path(graph, self.entry_symbol.rebased_addr, address)
            except self.nx.NetworkXNoPath:
                continue
            result.append({
                "allocator": name,
                "category": self.config.allocators[name],
                "status": "syntactic_candidate",
                "call_chain": [self.functions.get(node, f"sub_{node:x}") for node in path],
            })
        return result

    def _symbolic_run(self, budget: int, max_states: int, timeout: float,
                      prioritise: tuple[set[tuple[int, int]], set[int]] | None = None) -> dict[str, Any]:
        import claripy

        start = time.perf_counter()
        if budget <= 0 or timeout <= 0:
            return {
                "status": "incomplete",
                "steps": 0,
                "unique_blocks": 0,
                "states_created": 0,
                "concrete_inputs": 0,
                "solver_calls": 0,
                "visited_blocks": set(),
                "witnesses": [],
                "unknown": ["time_limit" if timeout <= 0 else "step_limit"],
                "elapsed_seconds": 0.0,
            }
        symbolic = [claripy.BVS(item.name, item.bits) for item in self.config.inputs]
        prototype = self.angr.types.SimTypeFunction(
            [self.angr.types.SimTypeNum(item.bits, signed=False) for item in self.config.inputs],
            self.angr.types.SimTypeInt(signed=True),
            arg_names=[item.name for item in self.config.inputs],
        )
        initial = self.project.factory.call_state(
            self.entry_symbol.rebased_addr,
            *symbolic,
            prototype=prototype,
            ret_addr=RETURN_ADDRESS,
            add_options={
                self.angr.options.LAZY_SOLVES,
                self.angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        initial.solver._solver.timeout = timeout * 1000
        frontier: list[tuple[int, int, Any]] = [(0, 0, initial)]
        serial = 1
        states_created = 1
        steps = 0
        solver_calls = 0
        visited: set[int] = set()
        witnesses: list[dict[str, Any]] = []
        unknown: set[str] = set()
        while frontier and steps < budget and time.perf_counter() - start < timeout:
            _, _, state = heapq.heappop(frontier)
            address = state.addr
            if address == RETURN_ADDRESS:
                continue
            if address in self.address_names:
                solver_calls += 1
                try:
                    if state.solver.satisfiable():
                        # SimSolver in angr 9.2.207 has no batch_eval method.
                        # Evaluate one concatenated bitvector so every returned
                        # argument comes from the same satisfying model.
                        packed_model = state.solver.eval(claripy.Concat(*symbolic))
                        arguments = {}
                        remaining_model = packed_model
                        for item in reversed(self.config.inputs):
                            arguments[item.name] = remaining_model & ((1 << item.bits) - 1)
                            remaining_model >>= item.bits
                        arguments = {item.name: arguments[item.name] for item in self.config.inputs}
                        name = self.address_names[address]
                        trace = self._call_trace(state, name)
                        witnesses.append({
                            "allocator": name,
                            "category": self.config.allocators[name],
                            "status": "feasible_witness",
                            "arguments": arguments,
                            "call_chain": trace["functions"],
                            "call_chain_complete": trace["complete"],
                            "block_trace": trace["blocks"],
                            "constraint_count": len(state.solver.constraints),
                            "constraints": [str(item) for item in state.solver.constraints[:64]],
                            "constraints_truncated": len(state.solver.constraints) > 64,
                        })
                except Exception as exc:
                    unknown.add(f"solver_error:{type(exc).__name__}")
                continue
            visited.add(address)
            steps += 1
            remaining = max(1, int((timeout - (time.perf_counter() - start)) * 1000))
            state.solver._solver.timeout = remaining
            try:
                successors = self.project.factory.successors(state)
            except Exception as exc:
                unknown.add(f"unsupported_execution:{type(exc).__name__}")
                continue
            if successors.unconstrained_successors:
                unknown.add("unconstrained_successor")
            for successor in successors.flat_successors:
                if states_created >= max_states:
                    unknown.add("state_limit")
                    break
                states_created += 1
                successor.solver._solver.timeout = remaining
                score = 0
                if prioritise is not None:
                    covered, target_reachable = prioritise
                    score = 0 if (address, successor.addr) not in covered and successor.addr in target_reachable else 1
                heapq.heappush(frontier, (score, serial, successor))
                serial += 1
        if frontier and steps >= budget:
            unknown.add("step_limit")
        if frontier and time.perf_counter() - start >= timeout:
            unknown.add("time_limit")
        if witnesses and unknown:
            status = "witnessed_with_incomplete_paths"
        elif witnesses:
            status = "witnessed"
        elif unknown:
            status = "incomplete"
        else:
            status = "no_witness_observed"
        return {
            "status": status,
            "steps": steps,
            "unique_blocks": len(visited),
            "states_created": states_created,
            "concrete_inputs": 0,
            "solver_calls": solver_calls,
            "visited_blocks": visited,
            "witnesses": witnesses,
            "unknown": sorted(unknown),
            "elapsed_seconds": round(time.perf_counter() - start, 6),
        }

    def _call_trace(self, state: Any, allocator: str) -> dict[str, Any]:
        # Derive the witness chain from blocks actually visited on this state.
        # A callgraph shortest path is suitable for a syntactic candidate, but
        # can select an infeasible route when another route reaches the target.
        blocks = list(state.history.bbl_addrs)
        if not blocks or blocks[-1] != state.addr:
            blocks.append(state.addr)
        functions = []
        complete = True
        for address in blocks:
            node = self.cfg.model.get_any_node(address, anyaddr=True)
            if node is None:
                complete = False
                continue
            name = self.functions.get(node.function_address)
            if name is None:
                complete = False
                continue
            if not functions or functions[-1] != name:
                functions.append(name)
        if not functions or functions[0] != self.config.entry:
            complete = False
        if not functions or functions[-1] != allocator:
            complete = False
        return {
            "functions": functions,
            "complete": complete,
            "blocks": [f"0x{address:x}" for address in blocks],
        }

    def _concrete_run(self, values: tuple[int, ...], budget: int, timeout: int) -> dict[str, Any]:
        import claripy

        prototype = self.angr.types.SimTypeFunction(
            [self.angr.types.SimTypeNum(item.bits, signed=False) for item in self.config.inputs],
            self.angr.types.SimTypeInt(signed=True),
            arg_names=[item.name for item in self.config.inputs],
        )
        arguments = [claripy.BVV(value, item.bits) for value, item in zip(values, self.config.inputs)]
        state = self.project.factory.call_state(
            self.entry_symbol.rebased_addr,
            *arguments,
            prototype=prototype,
            ret_addr=RETURN_ADDRESS,
            add_options={self.angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )
        start = time.perf_counter()
        visited = set()
        edges = set()
        steps = 0
        for _ in range(budget):
            if time.perf_counter() - start >= timeout:
                return {"steps": steps, "visited_blocks": visited, "edges": edges, "allocator": None, "unknown": "time_limit"}
            address = state.addr
            if address == RETURN_ADDRESS:
                return {"steps": steps, "visited_blocks": visited, "edges": edges, "allocator": None, "unknown": None}
            if address in self.address_names:
                return {"steps": steps, "visited_blocks": visited, "edges": edges,
                        "allocator": self.address_names[address], "unknown": None}
            visited.add(address)
            steps += 1
            try:
                successors = self.project.factory.successors(state)
            except Exception as exc:
                return {"steps": steps, "visited_blocks": visited, "edges": edges, "allocator": None,
                        "unknown": f"unsupported_execution:{type(exc).__name__}"}
            if successors.unconstrained_successors:
                return {"steps": steps, "visited_blocks": visited, "edges": edges, "allocator": None,
                        "unknown": "unsupported_or_unconstrained_successor"}
            if len(successors.flat_successors) != 1:
                return {"steps": steps, "visited_blocks": visited, "edges": edges, "allocator": None,
                        "unknown": "concrete_input_not_deterministic"}
            state = successors.flat_successors[0]
            edges.add((address, state.addr))
        return {"steps": steps, "visited_blocks": visited, "edges": edges, "allocator": None, "unknown": "step_limit"}

    def analyze(self) -> dict[str, Any]:
        started = time.monotonic()
        self.build_cfg()
        cfg_seconds = round(time.monotonic() - started, 6)
        symbolic = self._symbolic_run(
            self.config.max_steps,
            self.config.max_states,
            self.config.timeout_seconds,
        )
        return {
            "schema_version": 1,
            "angr_version": self.angr.__version__,
            "binary": str(self.config.binary),
            "architecture": "ELF x86-64",
            "entry": self.config.entry,
            "analysis": {
                "cfg_seconds": cfg_seconds,
                "candidate_paths": self.candidates(),
                "witnesses": symbolic["witnesses"],
                "status": symbolic["status"],
                "unknown": symbolic["unknown"],
                "bounds": {
                    "max_steps": self.config.max_steps,
                    "max_states": self.config.max_states,
                    "timeout_seconds": self.config.timeout_seconds,
                },
                "metrics": {key: symbolic[key] for key in
                            ("steps", "unique_blocks", "states_created", "solver_calls", "elapsed_seconds")},
                "solver_calls_scope": "Explicit allocator-state feasibility checks; angr internal branch-solver calls are not instrumented.",
            },
        }

    def explore(self) -> dict[str, Any]:
        self.build_cfg()
        target_reachable: set[int] = set()
        graph = self.cfg.graph._graph
        for node in graph.nodes:
            if node[0] in self.allocator_symbols.values():
                target_reachable.add(node[0])
                target_reachable.update(item[0] for item in self.nx.ancestors(graph, node))

        def concrete_inputs(values: list[tuple[int, ...]], budget: int) -> dict[str, Any]:
            started = time.perf_counter()
            remaining = budget
            blocks: set[int] = set()
            edges: set[tuple[int, int]] = set()
            witnesses = []
            unknown = set()
            steps = 0
            used = 0
            for row in values:
                time_left = self.config.timeout_seconds - (time.perf_counter() - started)
                if remaining <= 0 or time_left <= 0:
                    unknown.add("time_limit" if time_left <= 0 else "step_limit")
                    break
                outcome = self._concrete_run(row, remaining, max(1, int(time_left)))
                used += 1
                steps += outcome["steps"]
                remaining -= outcome["steps"]
                blocks.update(outcome["visited_blocks"])
                edges.update(outcome["edges"])
                if outcome["unknown"]:
                    unknown.add(outcome["unknown"])
                if outcome["allocator"]:
                    name = outcome["allocator"]
                    witnesses.append({
                        "allocator": name,
                        "category": self.config.allocators[name],
                        "status": "concrete_witness",
                        "arguments": {item.name: value for item, value in zip(self.config.inputs, row)},
                    })
            return {"steps": steps, "states_created": 0, "concrete_inputs": used, "solver_calls": 0,
                    "visited_blocks": blocks, "edges": edges, "witnesses": witnesses, "unknown": sorted(unknown),
                    "elapsed_seconds": round(time.perf_counter() - started, 6)}

        seeded_started = time.perf_counter()
        seed_result = concrete_inputs(list(self.config.seeds), self.config.max_steps)
        seed_symbolic = self._symbolic_run(
            max(0, self.config.max_steps - seed_result["steps"]),
            self.config.max_states,
            max(0.0, self.config.timeout_seconds - (time.perf_counter() - seeded_started)),
            prioritise=(seed_result["edges"], target_reachable),
        )
        seeded = self._merge(seed_result, seed_symbolic, "seed_first")
        rng = random.Random(self.config.random_seed)
        random_rows = [tuple(rng.getrandbits(item.bits) for item in self.config.inputs)
                       for _ in range(self.config.random_trials)]
        random_result = concrete_inputs(random_rows, self.config.max_steps)
        plain = self._symbolic_run(
            self.config.max_steps,
            self.config.max_states,
            self.config.timeout_seconds,
        )
        strategies = {
            "seed_first": seeded,
            "seeded_random": self._merge(random_result, {}, "seeded_random"),
            "bounded_symbolic": self._merge({}, plain, "bounded_symbolic"),
        }
        for name, result in strategies.items():
            for witness in result["witnesses"]:
                witness["native_validation"] = "not_run_by_analyzer"
        return {
            "schema_version": 1,
            "angr_version": self.angr.__version__,
            "binary": str(self.config.binary),
            "architecture": "ELF x86-64",
            "entry": self.config.entry,
            "research_note": "Bounded seed-first selective concolic exploration inspired by Driller; not a Driller implementation.",
            "budget": {"max_steps": self.config.max_steps, "max_states": self.config.max_states,
                       "timeout_seconds_per_strategy": self.config.timeout_seconds},
            "strategies": strategies,
        }

    @staticmethod
    def _merge(first: dict[str, Any], second: dict[str, Any], name: str) -> dict[str, Any]:
        return {
            "name": name,
            "steps": first.get("steps", 0) + second.get("steps", 0),
            "unique_blocks": len(first.get("visited_blocks", set()) | second.get("visited_blocks", set())),
            "states_created": first.get("states_created", 0) + second.get("states_created", 0),
            "concrete_inputs": first.get("concrete_inputs", 0) + second.get("concrete_inputs", 0),
            "solver_calls": first.get("solver_calls", 0) + second.get("solver_calls", 0),
            "elapsed_seconds": round(first.get("elapsed_seconds", 0.0) + second.get("elapsed_seconds", 0.0), 6),
            "visited_blocks": sorted(first.get("visited_blocks", set()) | second.get("visited_blocks", set())),
            "witnesses": first.get("witnesses", []) + second.get("witnesses", []),
            "unknown": sorted(set(first.get("unknown", [])) | set(second.get("unknown", []))),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find bounded allocation paths in a trusted ELF x86-64 binary.")
    parser.add_argument("mode", choices=("analyze", "explore", "kernel-scan"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--syscall-prefix", default="__x64_sys_")
    parser.add_argument("--max-entries", type=int, default=500)
    parser.add_argument("--analyze-entry")
    parser.add_argument("--max-steps", type=int, default=512)
    parser.add_argument("--max-states", type=int, default=256)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        if args.mode == "kernel-scan":
            if args.binary is None or args.config is not None:
                raise InputError("kernel-scan requires --binary and does not accept --config")
            if not 1 <= args.max_entries <= 5000:
                raise InputError("max-entries must be from 1 through 5000")
            if not 1 <= args.max_steps <= 100_000 or not 1 <= args.max_states <= 10_000:
                raise InputError("kernel scan analysis bounds are outside supported limits")
            if not 1 <= args.timeout_seconds <= 300:
                raise InputError("timeout-seconds must be from 1 through 300")
            if __package__:
                from .kernel_scan import KernelScanError, scan_kernel
            else:
                from kernel_scan import KernelScanError, scan_kernel
            try:
                result = scan_kernel(
                    args.binary, analyzer_types=(Analyzer, Config, Input),
                    syscall_prefix=args.syscall_prefix, max_entries=args.max_entries,
                    analyze_entry=args.analyze_entry, max_steps=args.max_steps,
                    max_states=args.max_states, timeout_seconds=args.timeout_seconds,
                )
            except KernelScanError as exc:
                raise InputError(str(exc)) from exc
        else:
            if args.config is None or args.binary is not None:
                raise InputError(f"{args.mode} requires --config and does not accept --binary")
            config = load_config(args.config.resolve())
            analyzer = Analyzer(config)
            result = analyzer.analyze() if args.mode == "analyze" else analyzer.explore()
    except (InputError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    except Exception as exc:
        print(json.dumps({"error": "analysis failed", "type": type(exc).__name__, "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
