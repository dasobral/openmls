# Staged KeyPackage Construction Design

## Stock OpenMLS constraints

OpenMLS 0.9.0 has the right internal boundaries but no public pause point:

- `KeyPackageBuilder::build` generates both HPKE key pairs, creates and signs a
  leaf node, builds the private `KeyPackageTbs`, signs it, stores the resulting
  bundle, and returns only the finished value.
- `KeyPackageTbs` and its fields are private. Its `Signable` implementation is
  the only stock path that obtains its canonical TLS bytes for the outer MLS
  signature.
- `LeafNode::new`, `NewLeafNodeParams`, and the mutable leaf/TBS payloads are
  crate-private.
- Public `KeyPackage` accessors are read-only. `KeyPackageIn` can be parsed and
  validated but cannot be used to mutate and re-sign an existing package.
- `Extensions<T>` can be built publicly, but adding a binding before `build`
  necessarily happens before random init and leaf encryption keys exist. A
  second `build` generates different covered material.

Consequently an external consumer cannot freeze stock generated material,
obtain canonical stripped `KeyPackageTBS` bytes, insert a derived binding into
that same object, and then request the final MLS signature. Reconstructing an
equivalent-looking TBS in application code would violate the canonical
serialization requirement and depend on private layout.

## Why the top-level extension is the binding field

The binding belongs in `KeyPackageTBS.extensions`, represented as an unknown
extension selected by the application. This is an RFC-compatible extensibility
point and remains generic.

The alternative `LeafNode.extensions` location was rejected. Inserting there
would invalidate the leaf-node signature and require a second leaf signing step
before the outer signature. More importantly, the canonical stripped input
would no longer be the TLS serialization of an MLS `KeyPackageTBS`: it would
need a synthetic unsigned leaf representation or a placeholder leaf signature.

At the selected location, preparation can finish and sign the leaf first. The
canonical input is then the ordinary private `KeyPackageTbs` with one extension
absent. Binding insertion changes only the top-level extension vector, and the
outer KeyPackage signature is created afterward. The final package retains both
normal MLS signatures. Staged preparation additionally enforces the static
extension validity and capability-advertisement conditions needed for the
retained top-level and leaf extension lists; later use still performs normal
receive and group-context validation.

## Internal representation

`PreparedKeyPackage` owns:

- the designated unknown extension code point;
- a private `KeyPackageTbs` with the binding absent and a signed leaf present;
- the canonical detached TLS serialization of that TBS;
- the generated HPKE init private key; and
- the generated leaf encryption private key.

`BoundKeyPackage` owns the same private material after adding
`Extension::Unknown(code_point, UnknownExtension(binding_bytes))` to the
top-level TBS extension list. It does not expose the mutable TBS or binding.

Neither state is cloneable, serializable, deserializable, or debug-formattable.
This prevents duplicate finalization and avoids creating a persistence or log
format for half-built cryptographic material. In particular, neither state may
derive `Debug`: private-key debug output can expose secrets under
`crypto-debug`. Any future debug implementation must explicitly redact every
field and remain secret-safe under every feature configuration.

## Preparation algorithm

`KeyPackageBuilder::prepare` uses staged-only validation before sharing private
key-generation/leaf-construction primitives with stock creation:

1. convert the supplied numeric code point through
   `ExtensionType::from(code_point)` and accept only the exact
   `Unknown(code_point)` result for this feature configuration;
2. apply stock builder defaults and `ensure_last_resort`;
3. reject an already-retained top-level entry with the designated numeric code
   point;
4. scan top-level extensions in stored order, rejecting noncanonical
   enum/numeric identities, duplicate encoded code points, invalid KeyPackage
   extensions, and unadvertised non-default extensions;
5. scan leaf extensions in stored order, rejecting noncanonical enum/numeric
   identities, duplicate encoded code points, invalid leaf extensions, and any
   extension absent from the effective leaf capabilities;
6. require the effective leaf capabilities to advertise the designated binding
   type;
7. perform the stock signature-scheme and crypto-provider support checks;
8. generate a fresh HPKE init key pair and leaf encryption key pair;
9. create and sign the `LeafNode` with source `KeyPackage` and the selected
   lifetime, capabilities, and leaf extensions;
10. verify the produced leaf signature with the signature public key embedded
    in the frozen leaf;
11. construct the private `KeyPackageTbs` with protocol version
    `ProtocolVersion::default()` and without the binding extension; and
12. store `key_package_tbs.tls_serialize_detached()` as the canonical bytes.

The order above is first-error-wins. Within each extension list, each entry's
checks occur in the stated order before moving to the next entry. Numeric
identity checks compare the emitted `u16` with the result of parsing that `u16`
through this build's `ExtensionType::from`; this catches typed values that would
change meaning on TLS round trip. Duplicate detection is numeric, not merely
enum equality.

`LastResort` is inserted before the scan, is non-default, and therefore requires
explicit advertisement. Staging never mutates capabilities to repair an input.
This validation is deliberately not called by ordinary `build()`.

No storage write occurs.

## Binding and finalization algorithms

`PreparedKeyPackage::with_external_binding` rejects empty bytes, adds exactly
one unknown top-level extension under the reserved code point, and consumes the
prepared state to return `BoundKeyPackage`.

`BoundKeyPackage::finalize` performs the same signature-scheme check as stock
creation, signs the bound `KeyPackageTbs` through the existing labeled
`Signable` path (`"KeyPackageTBS"`), and verifies the resulting signature under
the frozen leaf credential key. It then forms a `KeyPackageBundle`, calculates
the final KeyPackage hash reference, writes that bundle to storage once, and
returns it.

The canonical bytes are raw detached TLS serialization of `KeyPackageTbs`.
They are not the MLS `SignContent` wrapper used internally for the outer
signature. The external binding protocol is responsible for any additional
domain separation it requires.

## Verifier algorithm

`KeyPackage::canonical_binding_bytes(code_point)` structurally canonicalizes the
value it receives. It validates the code point using this build's
`ExtensionType::from`, finds the top-level unknown extension, rejects missing or
empty content, clones the private TBS, removes that extension, and serializes the
stripped TBS through the same `tls_codec` implementation used during
preparation.

The method cannot prove its receiver was MLS-validated and cannot authenticate
either signature or the external binding. `KeyPackage` is also constructible by
Serde deserialization, local construction, and a feature-gated unchecked path.
For untrusted wire input, callers must TLS-decode `KeyPackageIn`, run normal
`KeyPackageIn::validate`, then canonicalize and verify the application binding.
Callers using the package in an Add operation must also let the normal
group-context/leaf-local validation run; standalone KeyPackage validation does
not replace it.

Normal TLS decoding rejects duplicate encoded extension types before producing
`KeyPackageIn`, but this is not an unconditional property of every possible
`KeyPackage` construction path. Canonicalization does not build a parallel
public struct and successful byte production alone is not a validity result.

## Compatibility boundary

The implementation should run staged-only extension validation first, then
extract small private helpers from stock creation so `build` and `prepare` can
share key generation and leaf construction. The staged validation helper must
not be called from ordinary `build()`. The public one-shot method keeps its
existing signature, accepted-input behavior, error type, final wire encoding,
hash-reference key, and single `write_key_package` operation.

No public TBS, private key, mutable leaf, callback mutation hook, or post-hoc
binding API is introduced. No feature flag is required for the generic staged
API.
