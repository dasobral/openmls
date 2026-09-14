# Staged KeyPackage Construction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic, public, single-use OpenMLS API that freezes a KeyPackage construction state, exposes library-produced canonical binding bytes, accepts an external binding, and finalizes normal signed and stored MLS material.

**Architecture:** Keep `KeyPackageTbs` and signing internals private. Add an opaque prepared state with consuming transitions for preparation, binding insertion, and finalization; the contract task decides the exact binding location and excluded fields from the MLS wire structures. Preserve the existing one-shot builder by routing it through the same internal primitives where possible.

**Tech Stack:** Rust 1.98.1, OpenMLS `openmls-v0.9.0`, `tls_codec`, existing OpenMLS crypto/signature/storage traits, cargo test, rustfmt, and clippy.

**Spec:** `CONTRACT.md` and `DESIGN.md` at repository root.

## Global Constraints

- Base implementation branch: `agent-trust/keypackage-staging-v0.9` from `openmls-v0.9.0` commit `3a3e35de3feeca8f6605143c464d5452ae584d43`.
- Public API must be generic and contain no `agent_trust`, LAP, APF, authorization, or project-specific semantics.
- The canonical preimage must be produced by OpenMLS TLS serialization; application reconstruction and sidecar/post-hoc hashes are forbidden.
- External binding insertion must precede every MLS signature that is intended to cover it.
- Prepared finalization is consuming or explicitly single-use; signer and storage semantics must remain safe.
- Test authors and implementers are different workers; tests run RED before implementation and assertions are never weakened.
- Coordinator owns integration, commits, verification, dependency pinning, and packaging; workers receive closed briefs and do not spawn workers.

### Task 1: Freeze contract and characterize stock API

**Files:**
- Create: `CONTRACT.md`
- Create: `DESIGN.md`
- Create: `evidence/stock-api-red.txt`
- Create: `evidence/toolchain.txt`
- Test: `openmls/src/key_packages/tests.rs` or a dedicated test-only example selected after inspecting repository conventions

**Interfaces:**
- Produces the exact field coverage, binding location, canonical serialization rule, state transitions, and error semantics consumed by every later task.

- [ ] **Step 1: Document the contract.** Record the frozen public material, binding field and extension type, excluded recursive field/signatures, verifier recomputation bytes, allowed transitions, storage behavior, and one-shot semantics. Explicitly stop if the chosen preimage is circular.
- [ ] **Step 2: Add an executable stock characterization.** Demonstrate that the required prepare → canonical preimage → external insertion → final-signature sequence is unavailable through stock public APIs without private internals or look-alike serialization.
- [ ] **Step 3: Run the characterization and capture the actual blocked result.** Record command, exit code, compiler/toolchain, and the relevant failure text in `evidence/stock-api-red.txt`.
- [ ] **Step 4: Commit contract and characterization evidence.**

### Task 2: Add staged API RED tests

**Files:**
- Modify: `openmls/src/key_packages/tests.rs`
- Modify: `openmls/src/key_packages/key_package_in.rs` only if verifier-facing tests require a public entry point
- Create: `evidence/staged-api-red.txt`

**Interfaces:**
- Consumes the public contract from Task 1.
- Produces failing tests for deterministic preimages, field coverage/exclusion, insertion, final signatures, immutability, single-use finalization, signer mismatch, malformed/duplicate bindings, and ordinary-builder compatibility.

- [ ] **Step 1: Write tests for prepare-state freezing and repeated byte-identical preimages.**
- [ ] **Step 2: Write tests for covered-field tampering, designated binding exclusion, final insertion, and both MLS signature verifications.**
- [ ] **Step 3: Write tests for parsed-object verifier recomputation, prohibited post-extraction mutation, single-use finalization, signer/ciphersuite mismatch, malformed/duplicate binding extensions, and ordinary `build()` behavior.**
- [ ] **Step 4: Run only the new tests and capture genuine RED output in `evidence/staged-api-red.txt`.**
- [ ] **Step 5: Commit the RED tests without production implementation.**

### Task 3: Implement minimal opaque staged construction

**Files:**
- Modify: `openmls/src/key_packages/mod.rs`
- Modify: `openmls/src/key_packages/key_package_in.rs` if required by the contract
- Modify: `openmls/src/key_packages/errors.rs`
- Modify: `openmls/src/treesync/node/leaf_node.rs` only if staging must share an internal leaf construction primitive

**Interfaces:**
- Produces public prepared-state types and consuming methods exactly as fixed by `CONTRACT.md`; internal TBS types remain private.
- Preserves the existing `KeyPackageBuilder::build()` behavior and storage path.

- [ ] **Step 1: Implement preparation by generating and freezing all covered key material and construction fields.**
- [ ] **Step 2: Implement library-produced canonical stripped preimage serialization with explicit self-exclusion.**
- [ ] **Step 3: Implement validated consuming external-binding insertion and final signing/storage.**
- [ ] **Step 4: Implement verifier-side canonical recomputation from the final parsed public object.**
- [ ] **Step 5: Run the Task 2 tests and make only the minimal fixes required by their assertions.**
- [ ] **Step 6: Run rustfmt and commit the implementation.**

### Task 4: Prove normal MLS compatibility and cryptographic negatives

**Files:**
- Modify: `openmls/src/key_packages/tests.rs`
- Create: `lap-binding-consumer/Cargo.toml`
- Create: `lap-binding-consumer/src/main.rs`
- Create: `evidence/staged-api-green.txt`
- Create: `evidence/welcome-green.txt`

**Interfaces:**
- Consumes only the public staged API from Task 3.
- Produces a standalone generic consumer proof and normal publish/parse/validate/Add/Welcome/application-message coverage.

- [ ] **Step 1: Add negative tests for object substitution, tampered init/encryption/signature keys, credential and covered-extension changes, malformed/duplicate binding, sidecar-only verification, and noncanonical look-alike bytes.**
- [ ] **Step 2: Add the standalone consumer that certifies the canonical preimage, finalizes, serializes, parses, recomputes, and verifies it.**
- [ ] **Step 3: Extend the consumer to execute Add + Welcome and verify the prepared member can use stored private keys and exchange application messages.**
- [ ] **Step 4: Run cryptographic negatives and the consumer, recording exact commands and exits in the evidence files.**
- [ ] **Step 5: Commit the compatibility and consumer proof.**

### Task 5: Regression, review, forward-port, and package

**Files:**
- Modify: `CONSUMER-API.md`
- Create: `evidence/regression-green.txt`
- Create: `evidence/commits.txt`
- Modify: `evidence/toolchain.txt`
- Create: clean forward-port branch `feat/staged-keypackage-construction` from current upstream `main`

**Interfaces:**
- Produces the consumer-facing API contract, exact fork commit, verification evidence, and a separately validated generic forward-port.

- [ ] **Step 1: Run repository tests, rustfmt check, clippy as required by repository CI, and the standalone consumer.**
- [ ] **Step 2: Record toolchain, host architecture, base SHA, fork head SHA, commands, exit codes, counts, and changed behavior.**
- [ ] **Step 3: Perform a whole-branch security/API review and resolve only evidenced findings.**
- [ ] **Step 4: Write `CONSUMER-API.md` with dependency, exact SHA, public calls, errors, features, storage/provider requirements, example, and consumer/provider invariants.**
- [ ] **Step 5: Forward-port the smallest generic change to current upstream `main`, run the same focused tests, and keep it separate from the v0.9 branch.**
- [ ] **Step 6: Push the experimental branch and clean forward-port branch to `dasobral/openmls`; package the complete handback and commit list.**

