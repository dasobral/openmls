//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s.

use openmls_traits::types::Ciphersuite;
use thiserror::Error;

use crate::{
    ciphersuite::signable::SignatureError, error::LibraryError,
    prelude::ExtensionTypeNotValidInKeyPackageError, treesync::errors::LifetimeError,
};

/// KeyPackage verify error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageVerifyError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`LifetimeError`] for more details.
    #[error(transparent)]
    LifetimeError(#[from] LifetimeError),
    /// The lifetime of the leaf node is missing.
    #[error("The lifetime of the leaf node is missing.")]
    MissingLifetime,
    /// A key package extension is not supported in the leaf's capabilities.
    #[error("A key package extension is not supported in the leaf's capabilities.")]
    UnsupportedExtension,
    /// The key package signature is not valid.
    #[error("The key package signature is not valid.")]
    InvalidSignature,
    /// The leaf node signature is not valid.
    #[error("The leaf node signature is not valid.")]
    InvalidLeafNodeSignature,
    /// Invalid LeafNode source type
    #[error("Invalid LeafNode source type")]
    InvalidLeafNodeSourceType,
    /// The init key and the encryption key are equal.
    #[error("The init key and the encryption key are equal.")]
    InitKeyEqualsEncryptionKey,
    /// The protocol version is not valid.
    #[error("The protocol version is not valid.")]
    InvalidProtocolVersion,
    /// The provided extension is not allowed in key packages
    #[error(transparent)]
    ExtensionTypeNotValidInKeyPackage(#[from] ExtensionTypeNotValidInKeyPackageError),
}

/// KeyPackage extension support error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum KeyPackageExtensionSupportError {
    /// The key package does not support all required extensions.
    #[error("The key package does not support all required extensions.")]
    UnsupportedExtension,
}

/// KeyPackage new error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageNewError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The ciphersuite does not match the signature scheme.
    #[error("The ciphersuite does not match the signature scheme.")]
    CiphersuiteSignatureSchemeMismatch,
    /// The ciphersuite is not supported by the crypto provider.
    #[error("Ciphersuite {0:?} is not supported by the crypto provider.")]
    UnsupportedCiphersuite(Ciphersuite),
    /// Accessing storage failed.
    #[error("Accessing storage failed.")]
    StorageError,
    /// See [`SignatureError`] for more details.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    /// A virtual-clients operation failed while building the key package.
    #[cfg(feature = "virtual-clients-draft")]
    #[error(transparent)]
    VirtualClientsError(#[from] crate::components::vc_derivation_info::VirtualClientsError),
    /// A virtual-clients KeyPackage batch was requested with a count of 0.
    #[cfg(feature = "virtual-clients-draft")]
    #[error("A virtual-clients KeyPackage batch must request at least one KeyPackage.")]
    EmptyBatch,
}

/// Location of an extension list checked during staged KeyPackage preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedExtensionLocation {
    /// The top-level KeyPackage extension list.
    KeyPackage,
    /// The LeafNode extension list.
    LeafNode,
}

/// Errors returned by the staged KeyPackage construction API.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageStagingError {
    /// An error from the ordinary KeyPackage creation path.
    #[error(transparent)]
    KeyPackageNewError(#[from] KeyPackageNewError),
    /// The selected code point is recognized or GREASE in this build.
    #[error("invalid binding extension type {0}")]
    InvalidBindingExtensionType(u16),
    /// The builder already contains the designated binding code point.
    #[error("binding extension type {0} is already present")]
    DuplicateBindingExtension(u16),
    /// The designated binding type is absent from leaf capabilities.
    #[error("binding extension type {0} is not advertised")]
    BindingExtensionNotAdvertised(u16),
    /// A retained extension has a non-canonical enum/numeric representation.
    #[error("non-canonical {location:?} extension type {extension_type}")]
    NonCanonicalExtensionType {
        /// The extension-list location.
        location: StagedExtensionLocation,
        /// The encoded extension type.
        extension_type: u16,
    },
    /// Two retained extensions encode the same numeric type.
    #[error("duplicate {location:?} extension type {extension_type}")]
    DuplicateExtensionType {
        /// The extension-list location.
        location: StagedExtensionLocation,
        /// The encoded extension type.
        extension_type: u16,
    },
    /// A retained extension is not valid in its list.
    #[error("invalid extension type {extension_type} for {location:?}")]
    InvalidExtensionForLocation {
        /// The extension-list location.
        location: StagedExtensionLocation,
        /// The encoded extension type.
        extension_type: u16,
    },
    /// A retained extension is not advertised in leaf capabilities.
    #[error("{location:?} extension type {extension_type} is not advertised")]
    ExtensionNotAdvertised {
        /// The extension-list location.
        location: StagedExtensionLocation,
        /// The encoded extension type.
        extension_type: u16,
    },
    /// The supplied external binding is empty.
    #[error("the external binding is empty")]
    EmptyBinding,
    /// The designated binding is absent from a final KeyPackage.
    #[error("binding extension type {0} is missing")]
    MissingBindingExtension(u16),
    /// A signature did not verify under the frozen credential key.
    #[error("the signer does not match the credential signature key")]
    SignerMismatch,
    /// Canonical TLS serialization failed.
    #[error("canonical TLS serialization failed")]
    TlsSerializationError,
}
