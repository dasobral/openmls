use crate::{prelude::ExtensionTypeNotValidInLeafNodeError, test_utils::*};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::{Ciphersuite, SignatureScheme};

use tls_codec::{Deserialize, Serialize};

use crate::{
    extensions::errors::*,
    extensions::*,
    key_packages::{errors::*, *},
    storage::OpenMlsProvider,
};

const STAGED_BINDING_EXTENSION_TYPE: u16 = 0xf042;
const STAGED_TOP_LEVEL_EXTENSION_TYPE: u16 = 0xf043;
const STAGED_LEAF_EXTENSION_TYPE: u16 = 0xf044;

fn credential_with_key(identity: &[u8], signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn staged_capabilities(ciphersuite: Ciphersuite, extensions: &[ExtensionType]) -> Capabilities {
    Capabilities::new(None, Some(&[ciphersuite]), Some(extensions), None, None)
}

fn staging_error<T>(result: Result<T, KeyPackageStagingError>) -> KeyPackageStagingError {
    match result {
        Ok(_) => panic!("expected staged KeyPackage construction to fail"),
        Err(error) => error,
    }
}

fn duplicate_first_extension<T>(extensions: Extensions<T>) -> Extensions<T>
where
    Extensions<T>: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut serialized = serde_json::to_value(extensions).expect("serialize extensions");
    let entries = serialized
        .get_mut("unique")
        .and_then(serde_json::Value::as_array_mut)
        .expect("Extensions must serialize its entries as `unique`");
    entries.push(entries.first().expect("one extension").clone());
    serde_json::from_value(serialized).expect("deserialize deliberately duplicated extensions")
}

fn assert_tbs_mutation_changes_canonical_bytes(
    canonical_bytes: &[u8],
    tbs: &frankenstein::FrankenKeyPackageTbs,
    mutate: impl FnOnce(&mut frankenstein::FrankenKeyPackageTbs),
) {
    let mut tampered = tbs.clone();
    mutate(&mut tampered);
    assert_ne!(
        canonical_bytes,
        tampered
            .tls_serialize_detached()
            .expect("serialize tampered KeyPackageTBS"),
        "changing a covered field must change the canonical binding bytes"
    );
}

/// Helper function to generate key packages
pub(crate) fn key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (KeyPackageBundle, Credential, SignatureKeyPair) {
    let credential = BasicCredential::new(b"Sasha".to_vec());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signer,
            CredentialWithKey {
                credential: credential.clone().into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("An unexpected error occurred.");

    (key_package, credential.into(), signer)
}

/// Ensure that invalid leaf node extensions cannot be added to the KeyPackage
#[test]
fn key_package_builder_leaf_node_extensions_validation() {
    // create an extension that is invalid in the leaf node
    let extension = Extension::ExternalSenders(ExternalSendersExtension::new());
    assert!(!extension.extension_type().is_valid_in_leaf_node());

    let extensions_result: Result<Extensions<LeafNode>, _> = Extensions::single(extension);
    let err = extensions_result
        .expect_err("expected validation to fail because this type is not valid in leaf nodes");

    assert_eq!(
        err,
        InvalidExtensionError::ExtensionTypeNotValidInLeafNode(
            ExtensionTypeNotValidInLeafNodeError(ExtensionType::ExternalSenders)
        ),
    );
}

#[test]
fn key_package_rejects_unsupported_ciphersuite() {
    use crate::test_utils::restricted_provider::RestrictedProvider;

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // The provider supports some ciphersuite, but not `ciphersuite`.
    let provider =
        RestrictedProvider::new(vec![Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256]);

    // The signer matches the ciphersuite's signature scheme, so the
    // ciphersuite/signature-scheme mismatch check passes and the provider
    // support check is what fails.
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = BasicCredential::new(b"Sasha".to_vec());

    let err = KeyPackage::builder()
        .build(
            ciphersuite,
            &provider,
            &signer,
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect_err("key package creation should fail for an unsupported ciphersuite");

    assert!(matches!(
        err,
        KeyPackageNewError::UnsupportedCiphersuite(cs) if cs == ciphersuite
    ));
}

#[openmls_test::openmls_test]
fn generate_key_package() {
    let provider = &Provider::default();
    let (key_package, _credential, _signature_keys) = key_package(ciphersuite, provider);

    let kpi = KeyPackageIn::from(key_package.key_package().clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());
}

#[openmls_test::openmls_test]
fn serialization() {
    let provider = &Provider::default();
    let (key_package, _, _) = key_package(ciphersuite, provider);

    let encoded = key_package
        .key_package()
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::from(
        KeyPackageIn::tls_deserialize(&mut encoded.as_slice())
            .expect("An unexpected error occurred."),
    );
    assert_eq!(key_package.key_package(), &decoded_key_package);
}

#[openmls_test::openmls_test]
fn application_id_extension() {
    let provider = &Provider::default();
    let credential = BasicCredential::new(b"Sasha".to_vec());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let id = b"application id" as &[u8];
    let key_package = KeyPackage::builder()
        .leaf_node_extensions(
            Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(id)))
                .expect("failed to create single-element extensions list"),
        )
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.into(),
            },
        )
        .expect("An unexpected error occurred.");

    let kpi = KeyPackageIn::from(key_package.key_package().clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

    // Check ID
    assert_eq!(
        Some(id),
        key_package
            .key_package()
            .leaf_node()
            .extensions()
            .application_id()
            .map(|e| e.as_slice())
    );
}

/// Test that the key package is correctly validated:
/// - The protocol version is correct
/// - The init key is not equal to the encryption key
#[openmls_test::openmls_test]
fn key_package_validation() {
    let provider = &Provider::default();
    let (key_package_orig, _, _) = key_package(ciphersuite, provider);

    // === Protocol version ===

    let mut franken_key_package =
        frankenstein::FrankenKeyPackage::from(key_package_orig.key_package().clone());
    // Set an invalid protocol version
    franken_key_package.protocol_version = 999;

    let key_package_in = KeyPackageIn::from(franken_key_package);

    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid protocol version error
    assert_eq!(err, KeyPackageVerifyError::InvalidProtocolVersion);

    // === Init/encryption key ===

    let mut franken_key_package =
        frankenstein::FrankenKeyPackage::from(key_package_orig.key_package().clone());
    // Set an invalid init key
    franken_key_package.init_key = franken_key_package.leaf_node.encryption_key.clone();

    let key_package_in = KeyPackageIn::from(franken_key_package);

    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid init/encryption key error
    assert_eq!(err, KeyPackageVerifyError::InitKeyEqualsEncryptionKey);
}

/// Validation of a key package that carries many distinct extensions and
/// advertises a long capabilities list must succeed.
///
/// The capabilities list starts with padding entries that are never looked up,
/// so a linear scan per extension would do the full quadratic amount of work
/// here. The check uses a set lookup instead.
#[openmls_test::openmls_test]
fn key_package_validation_with_many_extensions() {
    // Distinct extension types for the key package. The range avoids the
    // registered types and the GREASE values.
    const FIRST_TYPE: u16 = 0xf000;
    const EXTENSION_COUNT: u16 = 1000;
    // Padding type for the capabilities list. It is not among the key package
    // extensions, so it is never looked up.
    const PADDING_TYPE: u16 = 0x0fff;
    const PADDING_COUNT: usize = 50_000;

    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    let extension_types: Vec<u16> = (FIRST_TYPE..FIRST_TYPE + EXTENSION_COUNT).collect();

    let key_package_extensions = Extensions::try_from(
        extension_types
            .iter()
            .map(|extension_type| Extension::Unknown(*extension_type, UnknownExtension(vec![])))
            .collect::<Vec<_>>(),
    )
    .expect("unknown extensions are valid in key packages");

    let mut capability_extensions = vec![ExtensionType::Unknown(PADDING_TYPE); PADDING_COUNT];
    capability_extensions.extend(
        extension_types
            .iter()
            .map(|extension_type| ExtensionType::Unknown(*extension_type)),
    );

    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&capability_extensions),
            None,
            None,
        ))
        .key_package_extensions(key_package_extensions)
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("failed to build the key package");

    let serialized = key_package
        .key_package()
        .tls_serialize_detached()
        .expect("failed to serialize the key package");

    let key_package_in =
        KeyPackageIn::tls_deserialize_exact(&serialized).expect("failed to parse the key package");

    key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect("validation should accept supported extensions");
}

/// Test that a key package is correctly built with a last resort extension when
/// the last resort flag is set during the build process.
#[openmls_test::openmls_test]
fn last_resort_key_package() {
    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // build without any other extensions
    let key_package = KeyPackage::builder()
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());

    // build with empty extensions
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());

    // build with extension
    let key_package = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::Unknown(0xFF00, UnknownExtension(vec![0x00])))
                .expect("failed to create single-element extensions list"),
        )
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());
}

/// Preparation exposes the library's exact TLS serialization of the frozen
/// KeyPackageTBS. Every field below is covered; only the designated binding
/// extension and the later outer KeyPackage signature are absent.
#[openmls_test::openmls_test]
fn staged_prepare_freezes_complete_canonical_tbs() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let advertised = [
        ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE),
        ExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE),
        ExtensionType::Unknown(STAGED_LEAF_EXTENSION_TYPE),
        ExtensionType::LastResort,
    ];
    let lifetime = Lifetime::default();
    let prepared = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .key_package_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_TOP_LEVEL_EXTENSION_TYPE,
                UnknownExtension(vec![0x11, 0x22]),
            ))
            .unwrap(),
        )
        .leaf_node_capabilities(staged_capabilities(ciphersuite, &advertised))
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_LEAF_EXTENSION_TYPE,
                UnknownExtension(vec![0x33, 0x44]),
            ))
            .unwrap(),
        )
        .mark_as_last_resort()
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential_with_key(b"frozen staged state", &signer),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .expect("prepare staged KeyPackage");

    let canonical_bytes = prepared.canonical_binding_bytes().to_vec();
    assert!(!canonical_bytes.is_empty());
    assert_eq!(
        prepared.canonical_binding_bytes(),
        canonical_bytes.as_slice(),
        "repeated extraction must be byte-identical"
    );

    // The returned slice is read-only. Mutating an owned caller copy cannot
    // mutate the opaque prepared state.
    let mut caller_copy = canonical_bytes.clone();
    caller_copy[0] ^= 1;
    assert_ne!(caller_copy.as_slice(), prepared.canonical_binding_bytes());
    assert_eq!(prepared.canonical_binding_bytes(), canonical_bytes.as_slice());

    let tbs = frankenstein::FrankenKeyPackageTbs::tls_deserialize_exact(&canonical_bytes)
        .expect("canonical bytes are exactly one KeyPackageTBS");
    assert_eq!(tbs.protocol_version, 1);
    assert_eq!(tbs.ciphersuite, u16::from(ciphersuite));
    assert_eq!(
        tbs.leaf_node.capabilities.extensions,
        advertised.iter().copied().map(u16::from).collect::<Vec<_>>()
    );
    assert!(matches!(
        tbs.leaf_node.leaf_node_source,
        frankenstein::FrankenLeafNodeSource::KeyPackage(_)
    ));
    assert!(!tbs.leaf_node.signature.as_slice().is_empty());
    assert_eq!(
        tbs.extensions
            .iter()
            .map(frankenstein::FrankenExtension::extension_type)
            .collect::<Vec<_>>(),
        vec![
            frankenstein::FrankenExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE),
            frankenstein::FrankenExtensionType::LastResort,
        ]
    );
    assert!(!tbs.extensions.iter().any(|extension| {
        u16::from(extension.extension_type()) == STAGED_BINDING_EXTENSION_TYPE
    }));

    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value.protocol_version ^= 1;
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value.ciphersuite ^= 1;
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let mut bytes = value.init_key.as_slice().to_vec();
        bytes[0] ^= 1;
        value.init_key = bytes.into();
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let mut bytes = value.leaf_node.encryption_key.as_slice().to_vec();
        bytes[0] ^= 1;
        value.leaf_node.encryption_key = bytes.into();
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let mut bytes = value.leaf_node.signature_key.as_slice().to_vec();
        bytes[0] ^= 1;
        value.leaf_node.signature_key = bytes.into();
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let credential: Credential = BasicCredential::new(b"different credential".to_vec()).into();
        value.leaf_node.credential = credential.into();
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value
            .leaf_node
            .capabilities
            .extensions
            .push(STAGED_BINDING_EXTENSION_TYPE + 10);
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value.leaf_node.capabilities.versions[0] = 0xffff;
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let alternate_ciphersuite =
            if ciphersuite == Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 {
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            } else {
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            };
        value.leaf_node.capabilities.ciphersuites[0] = u16::from(alternate_ciphersuite);
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value
            .leaf_node
            .capabilities
            .proposals
            .push(u16::from(crate::messages::proposals::ProposalType::Add));
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value.leaf_node.capabilities.credentials[0] =
            u16::from(crate::credentials::CredentialType::X509);
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let frankenstein::FrankenLeafNodeSource::KeyPackage(lifetime) =
            &mut value.leaf_node.leaf_node_source
        else {
            panic!("prepared leaf must have a KeyPackage lifetime");
        };
        lifetime.not_before += 1;
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let frankenstein::FrankenLeafNodeSource::KeyPackage(lifetime) =
            &mut value.leaf_node.leaf_node_source
        else {
            panic!("prepared leaf must have a KeyPackage lifetime");
        };
        lifetime.not_after += 1;
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value
            .leaf_node
            .extensions
            .push(frankenstein::FrankenExtension::Unknown(
                STAGED_LEAF_EXTENSION_TYPE + 10,
                vec![0x55].into(),
            ));
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        let mut bytes = value.leaf_node.signature.as_slice().to_vec();
        bytes[0] ^= 1;
        value.leaf_node.signature = bytes.into();
    });
    assert_tbs_mutation_changes_canonical_bytes(&canonical_bytes, &tbs, |value| {
        value
            .extensions
            .push(frankenstein::FrankenExtension::Unknown(
                STAGED_TOP_LEVEL_EXTENSION_TYPE + 10,
                vec![0x66].into(),
            ));
    });
}

/// Binding inserts exactly one designated top-level extension. The final
/// package validates both MLS signatures, and a parsed/validated verifier
/// recomputes the preparation bytes byte-for-byte.
#[openmls_test::openmls_test]
fn staged_binding_insertion_signatures_and_verifier_recomputation() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let advertised = [
        ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE),
        ExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE),
        ExtensionType::Unknown(STAGED_LEAF_EXTENSION_TYPE),
        ExtensionType::LastResort,
    ];
    let prepared = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_TOP_LEVEL_EXTENSION_TYPE,
                UnknownExtension(vec![0xa1]),
            ))
            .unwrap(),
        )
        .leaf_node_capabilities(staged_capabilities(ciphersuite, &advertised))
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_LEAF_EXTENSION_TYPE,
                UnknownExtension(vec![0xb2]),
            ))
            .unwrap(),
        )
        .mark_as_last_resort()
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential_with_key(b"bound staged state", &signer),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .expect("prepare staged KeyPackage");
    let canonical_bytes = prepared.canonical_binding_bytes().to_vec();
    let binding = vec![0xde, 0xad, 0xbe, 0xef];
    let bundle = prepared
        .with_external_binding(binding.clone())
        .expect("insert external binding")
        .finalize(provider, &signer)
        .expect("finalize staged KeyPackage");
    let key_package = bundle.key_package();

    let extensions = key_package.extensions().iter().cloned().collect::<Vec<_>>();
    assert_eq!(
        extensions,
        vec![
            Extension::Unknown(
                STAGED_TOP_LEVEL_EXTENSION_TYPE,
                UnknownExtension(vec![0xa1])
            ),
            Extension::LastResort(LastResortExtension::default()),
            Extension::Unknown(
                STAGED_BINDING_EXTENSION_TYPE,
                UnknownExtension(binding.clone())
            ),
        ],
        "binding insertion must retain order and append only the designated extension"
    );
    assert_eq!(
        key_package
            .leaf_node()
            .extensions()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec![Extension::Unknown(
            STAGED_LEAF_EXTENSION_TYPE,
            UnknownExtension(vec![0xb2])
        )]
    );

    let mut stripped_tbs = key_package.payload.clone();
    assert_eq!(
        stripped_tbs
            .extensions
            .remove(ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE)),
        Some(Extension::Unknown(
            STAGED_BINDING_EXTENSION_TYPE,
            UnknownExtension(binding)
        ))
    );
    assert_eq!(
        stripped_tbs.tls_serialize_detached().unwrap(),
        canonical_bytes,
        "the final TBS must differ from preparation by exactly the binding extension"
    );

    let wire = key_package.tls_serialize_detached().unwrap();
    let validated = KeyPackageIn::tls_deserialize_exact(&wire)
        .expect("parse final KeyPackage")
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect("both leaf and outer KeyPackage signatures verify");
    assert_eq!(
        validated
            .canonical_binding_bytes(STAGED_BINDING_EXTENSION_TYPE)
            .expect("recompute canonical binding bytes from validated parsed object"),
        canonical_bytes
    );

    let franken = frankenstein::FrankenKeyPackage::from(key_package.clone());
    let mut invalid_leaf_signature = franken.clone();
    let mut signature = invalid_leaf_signature
        .leaf_node
        .signature
        .as_slice()
        .to_vec();
    signature[0] ^= 1;
    invalid_leaf_signature.leaf_node.signature = signature.into();
    assert_eq!(
        KeyPackageIn::from(invalid_leaf_signature)
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap_err(),
        KeyPackageVerifyError::InvalidLeafNodeSignature
    );

    let mut invalid_outer_signature = franken;
    let mut signature = invalid_outer_signature.signature.as_slice().to_vec();
    signature[0] ^= 1;
    invalid_outer_signature.signature = signature.into();
    assert_eq!(
        KeyPackageIn::from(invalid_outer_signature)
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap_err(),
        KeyPackageVerifyError::InvalidSignature
    );
}

/// Preparation and binding insertion do not write storage. Consuming
/// finalization writes the completed bundle exactly once under its final hash.
#[test]
fn staged_finalization_is_single_use_and_stores_once() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let capabilities = staged_capabilities(
        ciphersuite,
        &[ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE)],
    );
    let initial_entries = provider.storage().values.read().unwrap().len();

    let prepared = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .prepare(
            ciphersuite,
            &provider,
            &signer,
            credential_with_key(b"single use", &signer),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .expect("prepare staged KeyPackage");
    assert_eq!(provider.storage().values.read().unwrap().len(), initial_entries);

    let bound = prepared
        .with_external_binding(vec![0x01])
        .expect("bind staged KeyPackage");
    assert_eq!(provider.storage().values.read().unwrap().len(), initial_entries);

    // `BoundKeyPackage::finalize` consumes `bound`; a second finalization of
    // this state is unrepresentable. The public integration test additionally
    // pins the by-value receiver through UFCS.
    let bundle = BoundKeyPackage::finalize(bound, &provider, &signer)
        .expect("single consuming finalization succeeds");
    assert_eq!(
        provider.storage().values.read().unwrap().len(),
        initial_entries + 1
    );
    let reference = bundle.key_package().hash_ref(provider.crypto()).unwrap();
    let stored: Option<KeyPackageBundle> = provider.storage().key_package(&reference).unwrap();
    assert_eq!(
        stored.expect("final bundle stored").key_package(),
        bundle.key_package()
    );
}

#[openmls_test::openmls_test]
fn staged_signer_credential_and_ciphersuite_mismatches_are_rejected() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let other_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let capabilities = staged_capabilities(
        ciphersuite,
        &[ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE)],
    );

    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities.clone())
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential_with_key(b"wrong credential key", &other_signer),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(error, KeyPackageStagingError::SignerMismatch));

    let mismatched_scheme = if ciphersuite.signature_algorithm() == SignatureScheme::ED25519 {
        SignatureScheme::ECDSA_SECP256R1_SHA256
    } else {
        SignatureScheme::ED25519
    };
    let mismatched_signer = SignatureKeyPair::new(mismatched_scheme).unwrap();
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities.clone())
            .prepare(
                ciphersuite,
                provider,
                &mismatched_signer,
                credential_with_key(b"wrong ciphersuite signer", &mismatched_signer),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::KeyPackageNewError(
            KeyPackageNewError::CiphersuiteSignatureSchemeMismatch
        )
    ));

    let prepared = KeyPackage::builder()
        .leaf_node_capabilities(capabilities.clone())
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential_with_key(b"final signer mismatch", &signer),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .unwrap();
    let error = staging_error(
        prepared
            .with_external_binding(vec![0x02])
            .unwrap()
            .finalize(provider, &other_signer),
    );
    assert!(matches!(error, KeyPackageStagingError::SignerMismatch));

    let prepared = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential_with_key(b"final ciphersuite mismatch", &signer),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .unwrap();
    let error = staging_error(
        prepared
            .with_external_binding(vec![0x03])
            .unwrap()
            .finalize(provider, &mismatched_signer),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::KeyPackageNewError(
            KeyPackageNewError::CiphersuiteSignatureSchemeMismatch
        )
    ));
}

#[openmls_test::openmls_test]
fn staged_binding_and_extension_malformations_are_rejected() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = || credential_with_key(b"staged validation", &signer);

    for invalid_type in [1, 10, 0x0a0a] {
        let error = staging_error(KeyPackage::builder().prepare(
            ciphersuite,
            provider,
            &signer,
            credential(),
            invalid_type,
        ));
        assert!(matches!(
            error,
            KeyPackageStagingError::InvalidBindingExtensionType(value)
                if value == invalid_type
        ));
    }

    #[cfg(feature = "extensions-draft")]
    {
        let error = staging_error(KeyPackage::builder().prepare(
            ciphersuite,
            provider,
            &signer,
            credential(),
            6,
        ));
        assert!(matches!(
            error,
            KeyPackageStagingError::InvalidBindingExtensionType(6)
        ));
    }

    #[cfg(not(feature = "extensions-draft"))]
    {
        KeyPackage::builder()
            .leaf_node_capabilities(staged_capabilities(
                ciphersuite,
                &[ExtensionType::Unknown(6)],
            ))
            .prepare(ciphersuite, provider, &signer, credential(), 6)
            .expect("code point 6 is unknown without extensions-draft");
    }

    let advertised_binding = staged_capabilities(
        ciphersuite,
        &[ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE)],
    );
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(advertised_binding.clone())
            .key_package_extensions(
                Extensions::single(Extension::Unknown(
                    STAGED_BINDING_EXTENSION_TYPE,
                    UnknownExtension(vec![0x01]),
                ))
                .unwrap(),
            )
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::DuplicateBindingExtension(STAGED_BINDING_EXTENSION_TYPE)
    ));

    let error = staging_error(KeyPackage::builder().prepare(
        ciphersuite,
        provider,
        &signer,
        credential(),
        STAGED_BINDING_EXTENSION_TYPE,
    ));
    assert!(matches!(
        error,
        KeyPackageStagingError::BindingExtensionNotAdvertised(STAGED_BINDING_EXTENSION_TYPE)
    ));

    let prepared = KeyPackage::builder()
        .leaf_node_capabilities(advertised_binding.clone())
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential(),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .unwrap();
    assert!(matches!(
        staging_error(prepared.with_external_binding(Vec::new())),
        KeyPackageStagingError::EmptyBinding
    ));

    let unbound_bundle = KeyPackage::builder()
        .build(ciphersuite, provider, &signer, credential())
        .unwrap();
    let unbound_wire = unbound_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let unbound = KeyPackageIn::tls_deserialize_exact(&unbound_wire)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    assert!(matches!(
        unbound.canonical_binding_bytes(STAGED_BINDING_EXTENSION_TYPE),
        Err(KeyPackageStagingError::MissingBindingExtension(
            STAGED_BINDING_EXTENSION_TYPE
        ))
    ));
    assert!(matches!(
        unbound.canonical_binding_bytes(10),
        Err(KeyPackageStagingError::InvalidBindingExtensionType(10))
    ));

    let empty_binding_bundle = KeyPackage::builder()
        .leaf_node_capabilities(advertised_binding.clone())
        .key_package_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_BINDING_EXTENSION_TYPE,
                UnknownExtension(Vec::new()),
            ))
            .unwrap(),
        )
        .build(ciphersuite, provider, &signer, credential())
        .unwrap();
    let empty_binding_wire = empty_binding_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let empty_binding = KeyPackageIn::tls_deserialize_exact(&empty_binding_wire)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    assert!(matches!(
        empty_binding.canonical_binding_bytes(STAGED_BINDING_EXTENSION_TYPE),
        Err(KeyPackageStagingError::EmptyBinding)
    ));

    let noncanonical_top = Extensions::single(Extension::Unknown(
        u16::from(ExtensionType::LastResort),
        UnknownExtension(vec![0x99]),
    ))
    .unwrap();
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(advertised_binding.clone())
            .key_package_extensions(noncanonical_top)
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::NonCanonicalExtensionType {
            location: StagedExtensionLocation::KeyPackage,
            extension_type: 10,
        }
    ));

    let duplicated_top = duplicate_first_extension(
        Extensions::single(Extension::Unknown(
            STAGED_TOP_LEVEL_EXTENSION_TYPE,
            UnknownExtension(vec![0x77]),
        ))
        .unwrap(),
    );
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(staged_capabilities(
                ciphersuite,
                &[
                    ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE),
                    ExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE),
                ],
            ))
            .key_package_extensions(duplicated_top)
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::DuplicateExtensionType {
            location: StagedExtensionLocation::KeyPackage,
            extension_type: STAGED_TOP_LEVEL_EXTENSION_TYPE,
        }
    ));

    let invalid_top_value = serde_json::to_value(
        Extensions::<LeafNode>::single(Extension::ApplicationId(ApplicationIdExtension::new(
            b"not valid at top level",
        )))
        .unwrap(),
    )
    .unwrap();
    let invalid_top: Extensions<KeyPackage> = serde_json::from_value(invalid_top_value).unwrap();
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(advertised_binding.clone())
            .key_package_extensions(invalid_top)
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::InvalidExtensionForLocation {
            location: StagedExtensionLocation::KeyPackage,
            extension_type: 1,
        }
    ));

    let noncanonical_leaf_value = serde_json::to_value(
        Extensions::<KeyPackage>::single(Extension::Unknown(
            u16::from(ExtensionType::ApplicationId),
            UnknownExtension(vec![0xaa]),
        ))
        .unwrap(),
    )
    .unwrap();
    let noncanonical_leaf: Extensions<LeafNode> =
        serde_json::from_value(noncanonical_leaf_value).unwrap();
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(advertised_binding.clone())
            .leaf_node_extensions(noncanonical_leaf)
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::NonCanonicalExtensionType {
            location: StagedExtensionLocation::LeafNode,
            extension_type: 1,
        }
    ));

    let duplicated_leaf = duplicate_first_extension(
        Extensions::<LeafNode>::single(Extension::Unknown(
            STAGED_LEAF_EXTENSION_TYPE,
            UnknownExtension(vec![0xbb]),
        ))
        .unwrap(),
    );
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(staged_capabilities(
                ciphersuite,
                &[
                    ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE),
                    ExtensionType::Unknown(STAGED_LEAF_EXTENSION_TYPE),
                ],
            ))
            .leaf_node_extensions(duplicated_leaf)
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::DuplicateExtensionType {
            location: StagedExtensionLocation::LeafNode,
            extension_type: STAGED_LEAF_EXTENSION_TYPE,
        }
    ));

    let invalid_leaf_value = serde_json::to_value(
        Extensions::<KeyPackage>::single(Extension::LastResort(
            LastResortExtension::default(),
        ))
        .unwrap(),
    )
    .unwrap();
    let invalid_leaf: Extensions<LeafNode> = serde_json::from_value(invalid_leaf_value).unwrap();
    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(advertised_binding.clone())
            .leaf_node_extensions(invalid_leaf)
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::InvalidExtensionForLocation {
            location: StagedExtensionLocation::LeafNode,
            extension_type: 10,
        }
    ));

    let prepared = KeyPackage::builder()
        .leaf_node_capabilities(advertised_binding)
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential(),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .unwrap();
    let bundle = prepared
        .with_external_binding(vec![0x88])
        .unwrap()
        .finalize(provider, &signer)
        .unwrap();
    let mut duplicate_wire = frankenstein::FrankenKeyPackage::from(bundle);
    let binding = duplicate_wire
        .extensions
        .iter()
        .find(|extension| {
            u16::from(extension.extension_type()) == STAGED_BINDING_EXTENSION_TYPE
        })
        .unwrap()
        .clone();
    duplicate_wire.extensions.push(binding);
    assert!(
        KeyPackageIn::tls_deserialize_exact(&duplicate_wire.tls_serialize_detached().unwrap())
            .is_err(),
        "normal TLS decoding must reject duplicate numeric binding extensions"
    );
}

#[openmls_test::openmls_test]
fn staged_retained_extensions_require_explicit_advertisement() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = || credential_with_key(b"extension advertisement", &signer);
    let binding_only = staged_capabilities(
        ciphersuite,
        &[ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE)],
    );

    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(binding_only.clone())
            .key_package_extensions(
                Extensions::single(Extension::Unknown(
                    STAGED_TOP_LEVEL_EXTENSION_TYPE,
                    UnknownExtension(vec![0x01]),
                ))
                .unwrap(),
            )
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::ExtensionNotAdvertised {
            location: StagedExtensionLocation::KeyPackage,
            extension_type: STAGED_TOP_LEVEL_EXTENSION_TYPE,
        }
    ));

    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(binding_only.clone())
            .leaf_node_extensions(
                Extensions::single(Extension::Unknown(
                    STAGED_LEAF_EXTENSION_TYPE,
                    UnknownExtension(vec![0x02]),
                ))
                .unwrap(),
            )
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::ExtensionNotAdvertised {
            location: StagedExtensionLocation::LeafNode,
            extension_type: STAGED_LEAF_EXTENSION_TYPE,
        }
    ));

    let error = staging_error(
        KeyPackage::builder()
            .leaf_node_capabilities(binding_only)
            .mark_as_last_resort()
            .prepare(
                ciphersuite,
                provider,
                &signer,
                credential(),
                STAGED_BINDING_EXTENSION_TYPE,
            ),
    );
    assert!(matches!(
        error,
        KeyPackageStagingError::ExtensionNotAdvertised {
            location: StagedExtensionLocation::KeyPackage,
            extension_type: 10,
        }
    ));

    let all_advertised = [
        ExtensionType::Unknown(STAGED_BINDING_EXTENSION_TYPE),
        ExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE),
        ExtensionType::Unknown(STAGED_LEAF_EXTENSION_TYPE),
        ExtensionType::LastResort,
    ];
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(staged_capabilities(ciphersuite, &all_advertised))
        .key_package_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_TOP_LEVEL_EXTENSION_TYPE,
                UnknownExtension(vec![0x03]),
            ))
            .unwrap(),
        )
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_LEAF_EXTENSION_TYPE,
                UnknownExtension(vec![0x04]),
            ))
            .unwrap(),
        )
        .mark_as_last_resort()
        .prepare(
            ciphersuite,
            provider,
            &signer,
            credential(),
            STAGED_BINDING_EXTENSION_TYPE,
        )
        .unwrap()
        .with_external_binding(vec![0x05])
        .unwrap()
        .finalize(provider, &signer)
        .unwrap();
    assert!(bundle.key_package().last_resort());
    assert!(bundle
        .key_package()
        .extensions()
        .contains(ExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE)));
    assert!(bundle
        .key_package()
        .leaf_node()
        .extensions()
        .contains(ExtensionType::Unknown(STAGED_LEAF_EXTENSION_TYPE)));
}

/// The existing one-shot builder deliberately keeps its stock acceptance
/// boundary. Staged-only advertisement checks must not leak into `build()`.
#[openmls_test::openmls_test]
fn staged_api_preserves_ordinary_build_with_unadvertised_extensions_and_last_resort() {
    let provider = &Provider::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let bundle = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_TOP_LEVEL_EXTENSION_TYPE,
                UnknownExtension(vec![0x10]),
            ))
            .unwrap(),
        )
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                STAGED_LEAF_EXTENSION_TYPE,
                UnknownExtension(vec![0x20]),
            ))
            .unwrap(),
        )
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signer,
            credential_with_key(b"ordinary builder", &signer),
        )
        .expect("ordinary build must retain its stock accepted-input behavior");

    assert!(bundle.key_package().last_resort());
    assert!(bundle
        .key_package()
        .extensions()
        .contains(ExtensionType::Unknown(STAGED_TOP_LEVEL_EXTENSION_TYPE)));
    assert!(bundle
        .key_package()
        .leaf_node()
        .extensions()
        .contains(ExtensionType::Unknown(STAGED_LEAF_EXTENSION_TYPE)));

    let wire = bundle.key_package().tls_serialize_detached().unwrap();
    assert_eq!(
        KeyPackageIn::tls_deserialize_exact(&wire)
            .unwrap()
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap_err(),
        KeyPackageVerifyError::UnsupportedExtension,
        "normal receive validation, not ordinary build, owns this stock check"
    );
}

/// Build a batch of virtual-client KeyPackages and verify the first carries a
/// reproducible derivation info. Registers an emulation epoch on a VC-capable
/// emulator group, calls `build_vc_batch`, and checks that the batch reports
/// generation 0, that the first leaf carries a `VC_COMPONENT_ID` entry in its
/// `app_data_dictionary`, and that the embedded `DerivationInfo` decrypts
/// (with the epoch's encryption key) to a `DerivationInfoTbe` whose
/// `leaf_index`, `generation`, and `key_package_index` match the emulator
/// leaf, the consumed generation, and the batch index. Also checks that a
/// count of 0 is rejected with `EmptyBatch`.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn build_vc_key_package_carries_reproducible_derivation_info() {
    use crate::{
        components::vc_derivation_info::{
            DerivationInfo, DerivationInfoTbe, EmulationEpochState, VirtualClientOperationType,
            VC_COMPONENT_ID,
        },
        credentials::test_utils::new_credential,
        extensions::{AppDataDictionary, AppDataDictionaryExtension},
        group::{MlsGroup, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
        key_packages::errors::KeyPackageNewError,
        treesync::node::leaf_node::Capabilities,
    };
    use tls_codec::{DeserializeBytes as _, Serialize as _};

    let provider = Provider::default();

    // VC-capable leaf config: declares AppDataDictionary support and lists
    // VC_COMPONENT_ID in its AppComponents entry (component id 1).
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build();
    let vc_leaf_extensions = {
        let supported_components: Vec<u16> = vec![VC_COMPONENT_ID];
        let app_components_body = supported_components
            .tls_serialize_detached()
            .expect("serialize AppComponents body");
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(1, app_components_body);
        let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
        Extensions::from_vec(vec![ext]).expect("build leaf-node Extensions")
    };

    // Emulator group: source of safe_export_secret(VC_COMPONENT_ID).
    let (emulator_credential, emulator_signer) =
        new_credential(&provider, b"Emulator", ciphersuite.signature_algorithm());
    let emulator_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .with_leaf_node_extensions(vc_leaf_extensions.clone())
        .expect("attach emulator leaf-node extensions")
        .build();
    let mut emulator = MlsGroup::new(
        &provider,
        &emulator_signer,
        &emulator_config,
        emulator_credential,
    )
    .expect("create emulator group");
    let emulation_leaf_index = emulator.own_leaf_index();

    let epoch_id = emulator
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("register vc emulation epoch");

    // The virtual client's own signing identity for the KeyPackage.
    let (vc_credential, vc_signer) = new_credential(
        &provider,
        b"VirtualClient",
        ciphersuite.signature_algorithm(),
    );

    // A count of 0 is rejected before any state is loaded or consumed.
    let empty = KeyPackage::builder().build_vc_batch(
        ciphersuite,
        &provider,
        &vc_signer,
        vc_credential.clone(),
        epoch_id.clone(),
        0,
    );
    assert_eq!(empty.unwrap_err(), KeyPackageNewError::EmptyBatch);

    let mut batch = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(vc_leaf_extensions)
        .build_vc_batch(
            ciphersuite,
            &provider,
            &vc_signer,
            vc_credential,
            epoch_id.clone(),
            1,
        )
        .expect("build_vc_batch must succeed");

    assert_eq!(
        batch.generation, 0,
        "the first key_package operation must consume generation 0"
    );
    assert_eq!(
        batch.key_packages.len(),
        1,
        "a count of 1 must produce one KeyPackage"
    );
    let (bundle, key_package_info) = batch.key_packages.remove(0);
    assert_eq!(
        key_package_info.key_package_index, 0,
        "the only KeyPackage in the batch has index 0"
    );

    // The leaf carries a VC_COMPONENT_ID entry in its app_data_dictionary.
    let leaf = bundle.key_package().leaf_node();
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .expect("leaf must carry an AppDataDictionary extension")
        .dictionary();
    let derivation_info_bytes = dictionary
        .get(&VC_COMPONENT_ID)
        .expect("leaf must carry a VC_COMPONENT_ID entry");

    // The embedded DerivationInfo decrypts with the epoch's encryption key.
    let state: EmulationEpochState = provider
        .storage()
        .vc_emulation_epoch_state(&epoch_id)
        .expect("load emulation epoch state")
        .expect("emulation epoch state present");
    let (_leaf_index, epoch_encryption_key, emulation_ciphersuite) = state.into_parts();
    let derivation_info = DerivationInfo::tls_deserialize_exact_bytes(derivation_info_bytes)
        .expect("deserialize DerivationInfo");
    assert_eq!(derivation_info.epoch_id(), &epoch_id);
    let leaf_encryption_key = leaf
        .encryption_key()
        .tls_serialize_detached()
        .expect("serialize leaf encryption key");
    let tbe = derivation_info
        .decrypt(
            provider.crypto(),
            emulation_ciphersuite,
            &epoch_encryption_key,
            &leaf_encryption_key,
            VirtualClientOperationType::KeyPackage,
        )
        .expect("decrypt DerivationInfoTbe");
    let DerivationInfoTbe::KeyPackage {
        leaf_index,
        generation: tbe_generation,
        key_package_index,
    } = tbe
    else {
        panic!("a key-package leaf must decode to the KeyPackage variant");
    };
    assert_eq!(leaf_index, emulation_leaf_index);
    assert_eq!(tbe_generation, batch.generation);
    assert_eq!(key_package_index, key_package_info.key_package_index);
}
