use std::cell::RefCell;
use std::net::IpAddr;

use rcgen::string::{Ia5String, PrintableString};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, OtherNameValue, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_ML_DSA_44, PKCS_ML_DSA_65, PKCS_ML_DSA_87,
    PKCS_RSA_SHA256, PublicKeyData, SanType, SignatureAlgorithm, SigningKey,
};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::{KeyError, KeyType, StoredKey};

const EMAIL_ADDRESS: [u64; 7] = [1, 2, 840, 113549, 1, 9, 1];
const SERIAL_NUMBER: [u64; 4] = [2, 5, 4, 5];
const USER_PRINCIPAL_NAME: [u64; 10] = [1, 3, 6, 1, 4, 1, 311, 20, 2, 3];

/// A kind of name in the subject of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameType {
    CommonName,
    Organization,
    OrganizationalUnit,
    Country,
    State,
    Locality,
    Email,
    SerialNumber,
    /// Any other attribute type, by the arcs of its OBJECT IDENTIFIER.
    Other(Vec<u64>),
}

/// A name the certificate is also valid for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlternativeName {
    Dns(String),
    Email(String),
    /// The user principal name of Windows (otherName 1.3.6.1.4.1.311.20.2.3).
    Upn(String),
    Ip(IpAddr),
    Uri(String),
}

/// What a certificate request asks to be named.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestSubject {
    /// The subject, in the order it is written.
    pub names: Vec<(NameType, String)>,
    pub alternative_names: Vec<AlternativeName>,
}

/// The PKCS#10 request (DER) for the subject, signed by the key.
///
/// A subject holds each name type once: a second name of a type replaces the first.
pub fn signing_request(key: &dyn StoredKey, subject: &RequestSubject) -> Result<Vec<u8>, KeyError> {
    let signer = KeySigner::new(key)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name(&subject.names)?;
    params.subject_alt_names = subject
        .alternative_names
        .iter()
        .map(subject_alt_name)
        .collect::<Result<_, _>>()?;
    let request = params
        .serialize_request(&signer)
        .map_err(|error| signer.error(error))?;
    let der = request.der().to_vec();
    log::info!(
        "request signed: {:?} key, {} bytes",
        key.key_type(),
        der.len()
    );
    Ok(der)
}

fn failed(error: impl std::fmt::Display) -> KeyError {
    KeyError::Failed(error.to_string())
}

fn distinguished_name(names: &[(NameType, String)]) -> Result<DistinguishedName, KeyError> {
    let mut name = DistinguishedName::new();
    for (kind, value) in names {
        let (dn_type, value) = match kind {
            NameType::CommonName => (DnType::CommonName, value.as_str().into()),
            NameType::Organization => (DnType::OrganizationName, value.as_str().into()),
            NameType::OrganizationalUnit => (DnType::OrganizationalUnitName, value.as_str().into()),
            NameType::Country => (
                DnType::CountryName,
                DnValue::PrintableString(
                    PrintableString::try_from(value.as_str()).map_err(failed)?,
                ),
            ),
            NameType::State => (DnType::StateOrProvinceName, value.as_str().into()),
            NameType::Locality => (DnType::LocalityName, value.as_str().into()),
            NameType::Email => (
                DnType::CustomDnType(EMAIL_ADDRESS.to_vec()),
                DnValue::Ia5String(Ia5String::try_from(value.as_str()).map_err(failed)?),
            ),
            NameType::SerialNumber => (
                DnType::CustomDnType(SERIAL_NUMBER.to_vec()),
                DnValue::PrintableString(
                    PrintableString::try_from(value.as_str()).map_err(failed)?,
                ),
            ),
            NameType::Other(oid) => (DnType::CustomDnType(oid.clone()), value.as_str().into()),
        };
        name.push(dn_type, value);
    }
    Ok(name)
}

fn subject_alt_name(name: &AlternativeName) -> Result<SanType, KeyError> {
    Ok(match name {
        AlternativeName::Dns(name) => {
            SanType::DnsName(Ia5String::try_from(name.as_str()).map_err(failed)?)
        }
        AlternativeName::Email(name) => {
            SanType::Rfc822Name(Ia5String::try_from(name.as_str()).map_err(failed)?)
        }
        AlternativeName::Upn(name) => SanType::OtherName((
            USER_PRINCIPAL_NAME.to_vec(),
            OtherNameValue::Utf8String(name.clone()),
        )),
        AlternativeName::Ip(address) => SanType::IpAddress(*address),
        AlternativeName::Uri(name) => {
            SanType::URI(Ia5String::try_from(name.as_str()).map_err(failed)?)
        }
    })
}

/// Lets rcgen sign with a key that stays in its storage.
struct KeySigner<'a> {
    key: &'a dyn StoredKey,
    algorithm: &'static SignatureAlgorithm,
    /// The subjectPublicKey of the key, without the algorithm.
    public_key: Vec<u8>,
    /// What the storage answered when it failed to sign: rcgen's own error cannot carry it.
    signing_error: RefCell<Option<KeyError>>,
}

impl<'a> KeySigner<'a> {
    fn new(key: &'a dyn StoredKey) -> Result<Self, KeyError> {
        let algorithm = match key.key_type() {
            KeyType::Rsa { .. } => &PKCS_RSA_SHA256,
            KeyType::EcP256 => &PKCS_ECDSA_P256_SHA256,
            KeyType::EcP384 => &PKCS_ECDSA_P384_SHA384,
            KeyType::EcP521 => &PKCS_ECDSA_P521_SHA512,
            KeyType::MlDsa44 => &PKCS_ML_DSA_44,
            KeyType::MlDsa65 => &PKCS_ML_DSA_65,
            KeyType::MlDsa87 => &PKCS_ML_DSA_87,
        };
        let (_, info) = SubjectPublicKeyInfo::from_der(key.public_key()).map_err(failed)?;
        Ok(Self {
            key,
            algorithm,
            public_key: info.subject_public_key.data.to_vec(),
            signing_error: RefCell::new(None),
        })
    }

    /// The error of the storage if it caused rcgen's, otherwise rcgen's.
    fn error(&self, error: rcgen::Error) -> KeyError {
        self.signing_error.take().unwrap_or_else(|| failed(error))
    }
}

impl PublicKeyData for KeySigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl SigningKey for KeySigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key.sign(message).map_err(|error| {
            *self.signing_error.borrow_mut() = Some(error);
            rcgen::Error::RemoteKeyError
        })
    }
}

#[cfg(test)]
mod tests;
