# Task 2 report: staged KeyPackage RED tests

## Changed files

- `openmls/src/key_packages/tests.rs`: added focused RED tests for stable
  canonical preimages, complete frozen-field coverage, exact binding exclusion
  and insertion, both MLS signatures, parsed-object recomputation, read-only
  extraction, consuming finalization and one storage write, signer/credential/
  ciphersuite mismatches, malformed and duplicate extensions, staged
  advertisement rules, retained top-level/leaf/LastResort extensions, and
  ordinary `build()` compatibility.
- `openmls/tests/stock_staged_key_package_api.rs`: pinned the public opaque
  state types, consuming UFCS transitions, borrowed canonical bytes, and the
  absence of Clone, Copy, Debug, Serialize, and Deserialize implementations.
- `evidence/staged-api-red.txt`: recorded the exact focused commands and their
  genuine output, plus the reviewer-blocker follow-up without inventing a new
  compiler result.

Reviewer-blocker fixes added independent canonical-byte mutations for all four
remaining `FrankenCapabilities` vectors (`versions`, `ciphersuites`,
`proposals`, and `credentials`). The malformed-extension test now also forges
leaf-node extension lists through serde and asserts exact LeafNode-located
`NonCanonicalExtensionType`, `DuplicateExtensionType`, and
`InvalidExtensionForLocation` errors.

## Test commands and result

Both focused commands were attempted:

```text
cargo test -p openmls --lib --no-default-features key_packages::tests::staged_
cargo test -p openmls --test stock_staged_key_package_api --no-default-features
```

Both exited 127 with `/bin/bash: line 1: cargo: command not found`. No Rust test
or compiler result is claimed. The toolchain remained unavailable during the
review fixes, so the prior genuine output was retained rather than replaced or
embellished. `git diff --check` exited 0 after the review changes.

## Concerns

- `cargo`, `rustc`, `rustup`, and `rustfmt` are absent from PATH in this Task 2
  environment, although Task 1's retained evidence records a previously
  available Rust 1.98.1 toolchain. The coordinator must compile and format the
  tests before implementation review.
- The tests intentionally reference the frozen staged API and error variants;
  stock OpenMLS cannot compile them until Task 3 supplies those production
  definitions.
- The reviewer-requested capability-vector and leaf-node malformed-extension
  coverage is present but cannot be compiler-verified in this environment.
- No production implementation file was changed and no commit was created.
