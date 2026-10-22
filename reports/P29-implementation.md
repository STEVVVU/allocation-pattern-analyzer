# P29 implementation report

## Result

Implemented the allocation-pattern analyzer on angr release `v9.2.207`, commit `9037fb8c6ee4a2df61ba64b7a561373f5eb6b253`. The CLI accepts a trusted ELF x86-64 binary, declared C entry and allocator symbols, unsigned integer arguments, and explicit step/state/time bounds. It uses angr's `CFGFast`, `factory.call_state`, and Claripy solver, and emits JSON separating static callgraph candidates, satisfiable witnesses, and unresolved states.

Witness call chains come from the executing state's recorded basic-block history, mapped to CFGFast function ownership; the result also includes the executed block trace and `call_chain_complete`. They do not reuse a static shortest callgraph path. The regression fixture deliberately includes a syntactically direct but infeasible allocator call and a feasible two-function wrapper route. The verifier confirms the candidate chain is the direct route while the witness trace follows `entry_multi_route -> multi_outer -> multi_inner -> mapping_alloc`.

For multiple declared symbolic inputs, angr 9.2.207's `SimSolver` does not expose `batch_eval`. The CLI therefore evaluates one concatenated bitvector and decodes all arguments from that single satisfying model. The two-input regression accepts only `(7, 11)` or `(13, 17)`; the verifier independently checks this joint predicate and the native Linux counter oracle checks the exact result for each extracted tuple.

The CLI also provides `kernel-scan` for the coursework's core static pipeline. It discovers `__x64_sys_*` functions and known slab and mapping allocator symbols in a trusted x86-64 ELF, builds CFGFast once, and reports each discovered entry's syntactic candidate chains. A missing callgraph candidate is reported as unknown, not unreachable. Optional symbolic execution of one chosen entry reuses the existing analyzer with a placeholder 64-bit syscall context and is explicitly marked `kernel_state: not_modeled`; its output is not a real kernel witness. The hosted driver compiles and scans an owned syscall-shaped fixture locally, while the workflow builds and scans official Linux 6.6.

`explore` compares a bounded seed-first strategy (concrete argument simulation in angr followed by symbolic prioritization on uncovered allocator-reaching edges), deterministic seeded-random concrete simulation, and plain bounded symbolic execution. This is a small adaptation of Driller's selective concolic idea, not a full Driller implementation. On the conditional fixture the final Windows run observed:

| Strategy | Steps | Unique blocks | Explicit allocator checks | Witnesses | Elapsed seconds | Limits |
| --- | ---: | ---: | ---: | ---: | --- |
| Seed-first | 7 | 3 | 1 | 1 | 0.02 | none |
| Seeded random | 512 | 2 | 0 | 0 | 1.09 | `step_limit` |
| Bounded symbolic | 3 | 3 | 1 | 1 | 0.01 | none |

The controlled C fixtures cover direct slab allocation, mapping allocation through a wrapper, competing feasible/infeasible routes, a correlated two-input predicate, a conditional branch, an infeasible allocator candidate, bounded loop behavior, known indirect calls, and an unsupported arbitrary function pointer. The driver analyzes the known-indirect and loop entry points, and checks a one-step loop budget reports `step_limit`. A separate per-case Python oracle models the expected harmless allocation counters; on Linux each reported witness must match both that oracle and the native runner's exact counter pair. The infeasible case must report zero native counters. Unsupported indirect control flow is left unresolved (`unconstrained_successor`); it is never executed by the driver.

## Changed and preserved artifacts

- `allocation_analyzer/cli.py`: config validation, ELF/symbol checks, CFG candidates, bounded symbolic witnesses, trace-based function chains, and exploration comparison.
- `fixtures/allocation_paths.c`, `fixtures/direct.json`, `fixtures/conditional.json`: owned harmless source and reproducible sample configs.
- `.agents/skills/verify-allocation-pattern-analyzer/`: maintained Launch/Doctor/Drive/Evidence/Cleanup driver, feature map, and invocation notes. The driver verifies fixture witnesses against a separate deterministic native-counter oracle on Linux and retains evidence after owned scratch cleanup.
- `.agents/skills/verify-allocation-pattern-analyzer/scripts/build-kernel-vmlinux.sh`: downloads the official Linux 6.6 source archive, verifies its pinned SHA-256, builds `tinyconfig` plus KALLSYMS `vmlinux`, and records source, config, and image hashes.
- `.github/workflows/allocation-pattern-checks.yml`: pinned Ubuntu 24.04 workflow with `workflow_dispatch`, `contents: read`, exact Python/dependency/Rust pins, fixture and actual-kernel scan journeys, an injected-failure cleanup journey, and a retained evidence artifact.
- `requirements-ci.txt`, `docs/development.md`, `docs/dependency-provenance.md`, and root `README.md`: reproducible setup, scope/limits, research attribution, source/addition distinction, and build provenance.
- `docs/upstream/README.md` preserves the original README byte-for-byte. Git blob `207209332fabd4b21188d42ca7c65a6a4b02a739` matches `v9.2.207:README.md`.
- `archive/upstream-github-workflows/{ci,coverage,nightly-ci}.yml` preserves inherited workflow files byte-for-byte; each file's Git blob ID matches its original `v9.2.207` path. Those external/reusable workflow definitions are removed from active execution and replaced by the focused read-only workflow.
- Existing `LICENSE`, `COPYRIGHT`, security notices, angr source, and Git history remain from the tagged checkout. No upstream angr source was modified.

## Environment and provenance

Python 3.11.9 is isolated at `C:\Users\steve\.codex\tools\coursework-allocation`; no shared interpreter or environment was modified. The exact PyPI angr 9.2.207 sdist SHA-256 is `badddc89e925c4bec90e8669734671ec66da89a3380812be5bc9474bef3ec820`. No official cp311 angr wheel is published for this release, so its extension was built from the exact sdist using Rust/Cargo 1.99.1, MSVC 14.44, and nmake. The generated local wheel SHA-256 is `a80d883d153ea443167d67fd4e44e66c89d4f9acd718d3ed90653050bf77570e`; this wheel is not checked in. Matching platform pyvex wheel hashes, the bitstring compatibility artifact, and the full dependency version freeze are recorded in `docs/dependency-provenance.md` and `requirements-ci.txt`.

The installed CLI imports angr from the isolated environment's `site-packages`, not this source checkout. `pip check` passed. Local LLVM clang/lld compiled the freestanding ELF fixture; Windows cannot execute that Linux ELF natively.

## Verification evidence

Commands run locally:

```powershell
& 'C:\Users\steve\.codex\tools\coursework-allocation\Scripts\python.exe' -I -m py_compile allocation_analyzer/cli.py .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py tests/test_config.py
& 'C:\Users\steve\.codex\tools\coursework-allocation\Scripts\python.exe' -I tests/test_config.py
& 'C:\Users\steve\.codex\tools\coursework-allocation\Scripts\python.exe' -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All --run-id p29-final-windows-004
& 'C:\Users\steve\.codex\tools\coursework-allocation\Scripts\python.exe' -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All --run-id p29-final-failure-windows-003 --inject-failure
git diff --check
```

Windows evidence after the correlated-input follow-up is `.agents/runs/p29-followup-win-002/evidence.json`; it records the joint-predicate witnesses and the bounded-loop `step_limit`. The kernel scanner and unknown-state assertion pass on the owned syscall-shaped fixture in `.agents/runs/p29-kernel-scan-win-002/evidence.json`; its callgraph path is classified as a slab candidate and the optional symbolic result is marked as incomplete kernel state. Python compilation, all five config tests, the full Windows Launch/Doctor/Drive/Evidence/Cleanup flow, and `git diff --check` pass. Windows native fixture execution remains `not_run`.

The actual-kernel hosted path is configured but not yet observed. The workflow downloads `https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz`, pinned to SHA-256 `d926a06c63dd8ac7df3f86ee1ffc2ce2a3b81a2d168484e76b5b389aba8e56d0`, from the official [kernel.org checksum index](https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc). It builds `ARCH=x86_64 tinyconfig`, enables `KALLSYMS` and `KALLSYMS_ALL`, then scans the resulting `vmlinux` with a 900-second timeout and 8192 MiB address-space cap. The actual kernel's symbol coverage, CFG candidates, source/config/image artifact bundle, and native fixture oracle still require the hosted workflow run; no kernel coverage claim is made before those outputs are reviewed.

## Pending hosted verification and limits

The Ubuntu workflow has not been run because this agent has no permission to publish or trigger it. Native fixture execution and native oracle comparison are therefore pending; Windows evidence explicitly records native checks as `not_run`. Main owns publication and should dispatch `Allocation pattern checks`, inspect its artifact, and require all native checks to pass before claiming Linux verification. I made no commits, pushes, repository settings changes, or GitHub calls. No kernel image/sample was downloaded or analyzed; the project makes no whole-kernel, safety, vulnerability, LASS, exploit, or side-channel claim.
