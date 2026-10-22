# P29 implementation report

## Result

Implemented the allocation-pattern analyzer on angr release `v9.2.207`, commit `9037fb8c6ee4a2df61ba64b7a561373f5eb6b253`. The CLI accepts a trusted ELF x86-64 binary, declared C entry and allocator symbols, unsigned integer arguments, and explicit step/state/time bounds. It uses angr's `CFGFast`, `factory.call_state`, and Claripy solver, and emits JSON separating static callgraph candidates, satisfiable witnesses, and unresolved states.

Witness call chains come from the executing state's recorded basic-block history, mapped to CFGFast function ownership; the result also includes the executed block trace and `call_chain_complete`. They do not reuse a static shortest callgraph path. The regression fixture deliberately includes a syntactically direct but infeasible allocator call and a feasible two-function wrapper route. The verifier confirms the candidate chain is the direct route while the witness trace follows `entry_multi_route -> multi_outer -> multi_inner -> mapping_alloc`.

For multiple declared symbolic inputs, angr 9.2.207's `SimSolver` does not expose `batch_eval`. The CLI therefore evaluates one concatenated bitvector and decodes all arguments from that single satisfying model. The two-input regression accepts only `(7, 11)` or `(13, 17)`; the verifier independently checks this joint predicate and the native Linux counter oracle checks the exact result for each extracted tuple.

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
- `.agents/skills/verify-allocation-pattern-analyzer/`: maintained Launch/Doctor/Drive/Evidence/Cleanup driver, feature map, and invocation notes. The driver verifies witnesses against a separate deterministic native-counter oracle on Linux and retains evidence after owned scratch cleanup.
- `.github/workflows/allocation-pattern-checks.yml`: pinned Ubuntu 24.04 workflow with `workflow_dispatch`, `contents: read`, exact Python/dependency/Rust pins, both ordinary and injected-failure journeys, and an evidence artifact.
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

Results before this follow-up: Python compilation passed; all five config validation tests passed; Launch/Doctor/Drive/Evidence/Cleanup passed with six analyzer checks; cleanup removed the generated ELF and preserved JSON/transcript; the injected failure returned the expected failure and still recorded cleanup/evidence. Follow-up Windows evidence is `.agents/runs/p29-followup-win-002/evidence.json`: the correlated case yielded two joint-predicate witnesses, direct/wrapper/competing-route/conditional/loop/known-indirect controls were all driven, and the one-step loop reported `step_limit`. Native outcomes are explicitly `not_run` on Windows. Per-case native assertions and the stronger required-case evidence guard are in place for Ubuntu. Python compilation and all five config tests pass after the follow-up. A second injected-failure journey at `.agents/runs/p29-followup-failure-win-001/evidence.json` recorded the expected failure, removed the ELF scratch binary, and retained the ten-case evidence. The hosted Ubuntu native proof remains pending.

## Pending hosted verification and limits

The Ubuntu workflow has not been run because this agent has no permission to publish or trigger it. Native fixture execution and native oracle comparison are therefore pending; Windows evidence explicitly records native checks as `not_run`. Main owns publication and should dispatch `Allocation pattern checks`, inspect its artifact, and require all native checks to pass before claiming Linux verification. I made no commits, pushes, repository settings changes, or GitHub calls. No kernel image/sample was downloaded or analyzed; the project makes no whole-kernel, safety, vulnerability, LASS, exploit, or side-channel claim.
