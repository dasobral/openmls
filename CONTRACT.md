# Staged KeyPackage Construction Contract

## Scope and baseline

This contract applies to OpenMLS `0.9.0` at tag `openmls-v0.9.0`, commit
`3a3e35de3feeca8f6605143c464d5452ae584d43`. The API is generic. It assigns no
LAP, authorization, certificate, or application-specific meaning to the
external binding bytes.

The stock one-shot API remains:

```rust
KeyPackageBuilder::build(
    self,
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &impl Signer,
    credential_with_key: CredentialWithKey,
) -> Result<KeyPackageBundle, KeyPackageNewError>
```

Its observable signing, storage, and return behavior must not change.

## Binding location and representation

The external binding is exactly one top-level KeyPackage extension in
`KeyPackageTBS.extensions`. It is not a `LeafNode.extensions` entry and is not a
sidecar value.

The caller selects a `u16` extension code point. Staging converts that numeric
value with `ExtensionType::from(code_point)` and accepts it only when this
OpenMLS build returns `ExtensionType::Unknown(code_point)`. Extension types
recognized by the active OpenMLS feature set, and GREASE values, are rejected.
This is a build-specific recognition check, not a query of the complete IANA
registry. For example, code point `6` is recognized as `AppDataDictionary` only
when `extensions-draft` is enabled. The final representation is:

```rust
Extension::Unknown(code_point, UnknownExtension(binding_bytes))
```

`binding_bytes` must be non-empty. OpenMLS treats the bytes as opaque and does
not define their application-level encoding or verification.

Before preparation, the caller must configure the leaf capabilities to contain
`ExtensionType::Unknown(code_point)`. Preparation also rejects a builder whose
`key_package_extensions` already contain that numeric code point.

After applying builder defaults, including `ensure_last_resort`, staging must
validate every retained extension before exposing canonical bytes:

- every retained top-level extension must have a canonical enum/numeric
  representation, be unique by its encoded `u16`, and be valid in a KeyPackage;
- every retained non-default top-level extension must be advertised in
  `LeafNode.capabilities.extensions`; this includes a builder-inserted
  `LastResort` extension;
- every retained leaf extension must have a canonical enum/numeric
  representation, be unique by its encoded `u16`, be valid in a leaf node, and
  be advertised in `LeafNode.capabilities.extensions`; and
- the absent-but-designated binding extension type must be advertised in the
  same capabilities list.

Staging never repairs these failures by adding capabilities. Capabilities and
the leaf signature are covered by the canonical bytes, so all checks complete
before the leaf is signed and before `PreparedKeyPackage` is returned.

## Frozen public material

Successful preparation generates and freezes all of the following public
material:

| Structure | Frozen fields |
|---|---|
| `KeyPackageTBS` | `protocol_version`, `ciphersuite`, `init_key`, complete signed `leaf_node`, and every preconfigured top-level extension other than the designated binding extension |
| `LeafNode` | `encryption_key`, `signature_key`, `credential`, `capabilities`, `leaf_node_source` including `Lifetime`, leaf-node extensions, and the leaf-node signature |

The corresponding private HPKE init key and leaf encryption private key are
retained inside the opaque prepared state. They are not part of the canonical
bytes and are not exposed.

After preparation, no covered public field can be changed. In particular,
binding insertion cannot replace, reorder, or append any field other than the
one designated top-level extension.

## Canonical binding bytes

The canonical binding bytes are exactly:

```text
TLS-Serialize(KeyPackageTBS with the designated binding extension absent)
```

OpenMLS must produce these bytes by calling its `tls_codec` serialization on
the private `KeyPackageTbs`. Applications must not reconstruct a look-alike
structure, splice final wire bytes, hash a sidecar, or serialize fields
individually.

The extension vector is serialized in its stripped form, including the length
prefix for the stripped vector. The canonical bytes cover the complete signed
leaf node, including its leaf-node signature. They exclude exactly:

- the designated external binding extension, because including a value derived
  from the bytes would be recursive; and
- the outer KeyPackage signature, because it is not a field of `KeyPackageTBS`
  and is created only after binding insertion.

No placeholder, empty extension, or empty signature is serialized into the
canonical bytes.

This preimage is not circular: the leaf-node signature covers only
`LeafNodeTBS`, which contains no top-level KeyPackage extension; the external
binding is derived from the stripped `KeyPackageTBS`; and the final outer
KeyPackage signature covers the `KeyPackageTBS` after the binding is inserted.

## Verifier recomputation

`KeyPackage::canonical_binding_bytes` is a structural canonicalization helper,
not a verification boundary. Its caller must supply a `KeyPackage` that has
already undergone the validation appropriate to the caller's use. For untrusted
MLS wire input, the minimum sequence is TLS parsing into `KeyPackageIn`, normal
`KeyPackageIn::validate`, then canonicalization and application-level binding
verification. A caller preparing to use the package in a group must also apply
the normal group-context and leaf-local checks required by that operation;
standalone `KeyPackageIn::validate` does not establish every Add-path leaf
invariant.

Subject to that precondition, the verifier supplies the same code point and
OpenMLS:

1. requires a non-empty `Extension::Unknown(code_point, ...)` in the top-level
   extension list;
2. clones the private `KeyPackageTbs` representation;
3. removes exactly that extension;
4. TLS-serializes the resulting `KeyPackageTbs`; and
5. returns those bytes.

The result must be byte-for-byte identical to the prepared state's canonical
bytes. Successful canonicalization alone authenticates neither MLS signature
nor the external binding. Public Serde deserialization, locally constructed
values, and the feature-gated unchecked conversion can produce `KeyPackage`
values without normal receive validation; this method cannot distinguish those
origins because it has no crypto-provider parameter.

Duplicate numeric extension types are rejected before `KeyPackageIn` is
produced only on the normal TLS decoding path. That statement does not apply to
all Serde or unchecked construction paths. MLS validation remains responsible
for both the leaf-node signature and the final KeyPackage signature, and the
application remains responsible for verifying the external binding over the
returned bytes.

## Public state machine

The following signatures are frozen for the staged API:

```rust
impl KeyPackageBuilder {
    pub fn prepare(
        self,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        binding_extension_type: u16,
    ) -> Result<PreparedKeyPackage, KeyPackageStagingError>;
}

impl PreparedKeyPackage {
    pub fn canonical_binding_bytes(&self) -> &[u8];

    pub fn with_external_binding(
        self,
        binding_bytes: Vec<u8>,
    ) -> Result<BoundKeyPackage, KeyPackageStagingError>;
}

impl BoundKeyPackage {
    pub fn finalize(
        self,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
    ) -> Result<KeyPackageBundle, KeyPackageStagingError>;
}

impl KeyPackage {
    pub fn canonical_binding_bytes(
        &self,
        binding_extension_type: u16,
    ) -> Result<Vec<u8>, KeyPackageStagingError>;
}
```

`PreparedKeyPackage` and `BoundKeyPackage` are public opaque types with private
fields. Neither type implements `Clone`, `Copy`, `Debug`, serialization,
deserialization, or constructors other than the transitions above. In
particular, implementations must not derive `Debug` over secret-bearing fields;
if debugging support is added in a later contract revision, it must use an
explicitly redacted implementation that is safe even with `crypto-debug`.

Allowed transitions are:

```text
KeyPackageBuilder --prepare--> PreparedKeyPackage
PreparedKeyPackage --with_external_binding--> BoundKeyPackage
BoundKeyPackage --finalize--> KeyPackageBundle
```

There is no transition backward, no mutation after binding insertion, no
finalization of an unbound state, and no second finalization. Consumption by
value enforces one-shot behavior even when a transition returns an error.

## Error semantics

The staged methods use `KeyPackageStagingError` with these variants and
meanings:

```rust
pub enum KeyPackageStagingError {
    KeyPackageNewError(KeyPackageNewError),
    InvalidBindingExtensionType(u16),
    DuplicateBindingExtension(u16),
    BindingExtensionNotAdvertised(u16),
    NonCanonicalExtensionType {
        location: StagedExtensionLocation,
        extension_type: u16,
    },
    DuplicateExtensionType {
        location: StagedExtensionLocation,
        extension_type: u16,
    },
    InvalidExtensionForLocation {
        location: StagedExtensionLocation,
        extension_type: u16,
    },
    ExtensionNotAdvertised {
        location: StagedExtensionLocation,
        extension_type: u16,
    },
    EmptyBinding,
    MissingBindingExtension(u16),
    SignerMismatch,
    TlsSerializationError,
}

pub enum StagedExtensionLocation {
    KeyPackage,
    LeafNode,
}
```

- `KeyPackageNewError` transparently preserves existing unsupported
  ciphersuite, ciphersuite/signature-scheme mismatch, signature, library, and
  storage failures.
- `InvalidBindingExtensionType` means `ExtensionType::from(code_point)` resolves
  to a type recognized by this OpenMLS build or to GREASE instead of
  `ExtensionType::Unknown(code_point)`.
- `DuplicateBindingExtension` means the builder already contains the reserved
  numeric top-level extension code point.
- `BindingExtensionNotAdvertised` means the frozen leaf capabilities do not
  contain the designated unknown extension type.
- `NonCanonicalExtensionType` means a retained extension's enum identity does
  not equal `ExtensionType::from(u16::from(extension.extension_type()))`; this
  rejects representations such as `Extension::Unknown(10, ...)` when numeric
  code point `10` is recognized as `LastResort`.
- `DuplicateExtensionType` means two retained entries in the same indicated
  list encode the same numeric `u16`, even if their enum variants differ.
- `InvalidExtensionForLocation` means a retained extension is not valid in the
  indicated top-level KeyPackage or leaf-node extension list.
- `ExtensionNotAdvertised` means a retained extension subject to the capability
  rule is absent from the frozen `LeafNode.capabilities.extensions`. For
  `StagedExtensionLocation::KeyPackage`, this check applies to every non-default
  retained extension, including `LastResort`; for `LeafNode`, it applies to
  every retained extension.
- `EmptyBinding` rejects an empty inserted binding and an empty binding found
  during verifier recomputation.
- `MissingBindingExtension` is returned only by verifier recomputation when the
  final KeyPackage lacks the designated extension.
- `SignerMismatch` means a signature produced during preparation or
  finalization does not verify under the frozen credential signature key even
  though its signature scheme may match.
- `TlsSerializationError` maps failure to produce canonical bytes without
  exposing private TBS types.

Preparation validation order is deterministic and first-error-wins:

1. convert and validate the designated binding code point;
2. apply `ensure_last_resort`;
3. reject any retained top-level extension with the designated numeric code
   point;
4. scan retained top-level extensions in stored order, checking for each entry:
   canonical enum/numeric identity, duplicate numeric identity among earlier
   entries, validity in a KeyPackage, then capability advertisement when the
   extension is non-default;
5. scan retained leaf extensions in stored order, checking for each entry:
   canonical enum/numeric identity, duplicate numeric identity among earlier
   entries, validity in a leaf node, then capability advertisement;
6. require advertisement of the designated binding type;
7. perform the existing ciphersuite/signature-scheme and provider-support
   checks;
8. generate and sign the leaf, then verify that signature under the frozen
   signature key; and
9. serialize the canonical bytes and only then return `PreparedKeyPackage`.

No canonical byte slice is observable before all nine steps succeed.
`with_external_binding` checks `EmptyBinding` before insertion. Finalization
checks the existing signature-scheme condition, signs, verifies the produced
outer signature under the frozen key, computes the hash reference, and only
then writes storage. Verifier canonicalization validates the supplied binding
code point before checking missing or empty binding content.

## Storage and one-shot builder behavior

Preparation and binding insertion perform no storage writes. Finalization:

1. signs the bound `KeyPackageTbs` with the final signer;
2. verifies that signature under the frozen credential signature key;
3. constructs the `KeyPackageBundle` from the final KeyPackage and retained
   private keys;
4. computes the hash reference from the final signed KeyPackage; and
5. writes the bundle exactly once with `write_key_package` under that final
   hash reference before returning it.

A signing, signer-validation, serialization, or hash-reference failure performs
no storage write. A storage backend can define its own atomicity, as with stock
`build`; OpenMLS reports `KeyPackageNewError::StorageError` through
`KeyPackageStagingError::KeyPackageNewError`. Because finalization consumes the
bound state, it cannot be retried through the same value.

The ordinary `KeyPackageBuilder::build()` path remains one-shot: it generates,
signs, stores, and returns one normal `KeyPackageBundle` exactly as in OpenMLS
0.9.0. It does not create a binding extension and does not expose a prepared
state. The staged-only retained-extension checks above must not be placed in a
shared helper invoked by ordinary `build()`; preserving stock behavior includes
preserving its existing acceptance and later-validation boundaries.
