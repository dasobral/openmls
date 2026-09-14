use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const BINDING_EXTENSION_TYPE: u16 = 0xf042;

fn main() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("generate signature key pair");
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(b"generic staged consumer".to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(BINDING_EXTENSION_TYPE)])
        .build();

    let prepared = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .prepare(
            ciphersuite,
            &provider,
            &signer,
            credential_with_key,
            BINDING_EXTENSION_TYPE,
        )
        .expect("prepare staged KeyPackage");

    let canonical = prepared.canonical_binding_bytes().to_vec();
    let bundle = prepared
        .with_external_binding(canonical.clone())
        .expect("insert external binding")
        .finalize(&provider, &signer)
        .expect("finalize staged KeyPackage");

    let wire = bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize finalized KeyPackage");
    let validated = KeyPackageIn::tls_deserialize_exact(&wire)
        .expect("parse finalized KeyPackage")
        .validate(&provider.crypto(), ProtocolVersion::Mls10)
        .expect("validate finalized KeyPackage");
    let recomputed = validated
        .canonical_binding_bytes(BINDING_EXTENSION_TYPE)
        .expect("recompute canonical binding bytes");

    assert_eq!(recomputed, canonical);
    assert_eq!(
        bundle
            .key_package()
            .extensions()
            .iter()
            .filter(|extension| {
                u16::from(extension.extension_type()) == BINDING_EXTENSION_TYPE
            })
            .count(),
        1
    );
    println!("staged KeyPackage binding verified");
}
