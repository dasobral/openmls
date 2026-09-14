//! Compile-time characterization of the staged KeyPackage API missing from
//! stock OpenMLS 0.9.0.
//!
//! This integration test is intentionally RED until the public staged API is
//! implemented. As an external crate, it cannot access private TBS or signing
//! internals, and it does not reconstruct look-alike serialization.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

const BINDING_EXTENSION_TYPE: u16 = 0xf042;

// These assertions compile only while the staged states remain opaque,
// non-duplicable, non-debuggable, and non-serializable. An accidental impl of
// one of the listed traits makes method resolution ambiguous at compile time.
macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}

            let _ = <$type as AmbiguousIfImpl<_>>::marker;
        };
    };
}

macro_rules! assert_not_deserialize {
    ($type:ty) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T> AmbiguousIfImpl<u8> for T where T: for<'de> serde::Deserialize<'de> {}

            let _ = <$type as AmbiguousIfImpl<_>>::marker;
        };
    };
}

assert_not_impl!(PreparedKeyPackage: Clone);
assert_not_impl!(PreparedKeyPackage: Copy);
assert_not_impl!(PreparedKeyPackage: std::fmt::Debug);
assert_not_impl!(PreparedKeyPackage: serde::Serialize);
assert_not_deserialize!(PreparedKeyPackage);
assert_not_impl!(BoundKeyPackage: Clone);
assert_not_impl!(BoundKeyPackage: Copy);
assert_not_impl!(BoundKeyPackage: std::fmt::Debug);
assert_not_impl!(BoundKeyPackage: serde::Serialize);
assert_not_deserialize!(BoundKeyPackage);

#[openmls_test]
fn stock_api_cannot_stage_key_package_external_binding() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("generate signature key pair");
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(b"staged key package".to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(BINDING_EXTENSION_TYPE)])
        .build();

    let prepared: PreparedKeyPackage = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential_with_key,
            BINDING_EXTENSION_TYPE,
        )
        .expect("prepare and freeze public KeyPackage material");

    let canonical_bytes = PreparedKeyPackage::canonical_binding_bytes(&prepared).to_vec();
    let external_binding = canonical_bytes.clone();
    let bound: BoundKeyPackage =
        PreparedKeyPackage::with_external_binding(prepared, external_binding)
        .expect("insert the externally produced binding");
    let bundle = BoundKeyPackage::finalize(bound, provider, &signer)
        .expect("sign and store the bound KeyPackage");

    let serialized_key_package = bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize the finalized KeyPackage");
    let validated_key_package = KeyPackageIn::tls_deserialize_exact(&serialized_key_package)
        .expect("TLS-parse the finalized KeyPackage")
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect("validate both MLS signatures on the finalized KeyPackage");
    let recomputed_canonical_bytes = KeyPackage::canonical_binding_bytes(
        &validated_key_package,
        BINDING_EXTENSION_TYPE,
    )
    .expect("recompute canonical binding bytes from the validated KeyPackage");

    assert_eq!(recomputed_canonical_bytes, canonical_bytes);
}
