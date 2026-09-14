# SDD ledger — plan: docs/superpowers/plans/2026-09-14-staged-keypackage-construction.md

## Plan pre-flight scan

| Scope | Relationship checked | Result | Ruling |
|---|---|---|---|
| Task 1 | Produces `CONTRACT.md`/`DESIGN.md`; Task 2 consumes them | Compatible; Task 1 must finish before RED tests | Contract is binding for later API names and coverage. |
| Task 2 | Modifies `openmls/src/key_packages/tests.rs`; Task 3 modifies same implementation module and may modify verifier/errors | Compatible; tests must be committed before implementation | Preserve RED assertions and use the contract to resolve names. |
| Task 3 | Produces staged public API; Task 4 consumes it from tests/consumer | Compatible; exact signatures are deliberately contract-driven | No public TBS exposure; opaque consuming API required. |
| Task 4 | Modifies key-package tests and creates consumer; Task 5 consumes outputs and docs | Compatible; green evidence precedes regression/forward-port | Consumer may use only documented public API. |
| Task 5 | Finalizes `CONSUMER-API.md`, evidence, and forward-port | Compatible; forward-port is separate from v0.9 branch | No upstream issue before the API is proven, per user instruction. |

| Task | Internal consistency | Ruling |
|---|---|---|
| 1 | Contract/evidence files match exploratory scope | Resolve exact binding location from source before locking contract. |
| 2 | Tests cover all required invariants and have a RED run | Do not implement production code in this task. |
| 3 | Implementation files align with v0.9.0 structure | Keep changes minimal and preserve one-shot builder behavior. |
| 4 | Consumer and negative tests exercise the public interface | Reject any test that reconstructs canonical bytes externally. |
| 5 | Evidence and forward-port are downstream of green v0.9 work | Do not claim upstream compatibility until independently tested. |

## Rulings

- Ruling: Use `dasobral/openmls` as origin and branch from `openmls-v0.9.0` — the user explicitly requires a maintained fork and the handoff pins this baseline — cost if wrong: remote history/branch adjustment.
- Ruling: Use the opaque prepared-state design — prior project review approved it over raw TBS exposure and callback-only staging — cost if wrong: API redesign before implementation.
- Ruling: Keep the OpenMLS workstream separate from `agent-trust` — it is a generic enabling library change — cost if wrong: consumer boundary becomes non-reusable.

## Task 1 review

- Review verdict: changes requested before acceptance.
- Blocking finding B1: staged preparation must enforce capability advertisement for every retained non-default top-level extension and every retained leaf extension, including builder-inserted `LastResort`; otherwise a signed package can fail normal MLS validation.
- Non-blocking findings N1–N3: qualify verifier preconditions and numeric extension recognition; explicitly avoid secret-bearing derived `Debug` implementations.
- Ruling: return Task 1 to its contract worker for documentation-only correction, then re-review before commit — the contract is the security boundary and Task 2 must inherit an unambiguous validity rule.

- Task 1: fix round 1 (B1/N1–N3 addressed, 0 open; documentation-only; no commit by worker).
- Task 1: complete (commits `60ef85e7..5d12485e`, replacement review clean).
- Coordinator verification note: the original baseline passed with 282/285 tests; the stock characterization was independently recorded RED with exit 101. A coordinator rerun after the new terminal instance failed with exit 127 because cargo/rustc are absent from this instance; this is an environment limitation, not a test result.

## Baseline

- Command: `rustc --version && cargo --version && cargo test -p openmls --lib`
- Result: exit 0; Rust/cargo 1.98.1; 285 tests discovered, 282 passed, 0 failed, 3 ignored.
- Base checkout: `openmls-v0.9.0` at `3a3e35de3feeca8f6605143c464d5452ae584d43`.

## Task 2 review and completion

- RED test author added focused unit and external integration coverage; no production files changed.
- First review blocked on missing capability-vector mutations and missing LeafNode malformed-extension cases; both were added.
- Second review blocked on missing public verifier coverage; external TLS parse/validate/recompute equality was added.
- Final review: APPROVE; all requested coverage present, `git diff --check` clean, and missing Rust toolchain evidence honest.
- Task 2: complete (RED tests/evidence ready for implementation).
