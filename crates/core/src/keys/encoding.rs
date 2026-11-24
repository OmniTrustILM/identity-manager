//! The public keys and signatures of the key storages in the forms a certificate request needs.

use sha2::{Digest, Sha256, Sha384, Sha512};

use super::{KeyError, KeyType, rsa_types};

/// The curves of the ECDSA key types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
}

/// The parameter sets of ML-DSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

// OBJECT IDENTIFIERs as DER, tag and length included.
const RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
const ML_DSA_44: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];
const ML_DSA_65: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];
const ML_DSA_87: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
];
const NULL: &[u8] = &[0x05, 0x00];

// The magic numbers of the CNG public key blobs, in the byte order of the structure (little endian).
const RSA_PUBLIC_MAGIC: u32 = 0x3141_5352;
const ECDSA_P256_PUBLIC_MAGIC: u32 = 0x3153_4345;
const ECDSA_P384_PUBLIC_MAGIC: u32 = 0x3353_4345;
const ECDSA_P521_PUBLIC_MAGIC: u32 = 0x3553_4345;
const ML_DSA_PUBLIC_MAGIC: u32 = 0x4B50_5344;

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        length @ 0..=0x7F => out.push(length as u8),
        length @ 0x80..=0xFF => out.extend([0x81, length as u8]),
        length => out.extend([0x82, (length >> 8) as u8, length as u8]),
    }
    out.extend(content);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

/// A DER INTEGER from an unsigned big-endian number.
fn integer(unsigned: &[u8]) -> Vec<u8> {
    let start = unsigned.iter().take_while(|byte| **byte == 0).count();
    let digits = &unsigned[start.min(unsigned.len().saturating_sub(1))..];
    let mut content = Vec::with_capacity(digits.len() + 1);
    if digits.first().is_none_or(|byte| byte & 0x80 != 0) {
        content.push(0);
    }
    content.extend(digits);
    der(0x02, &content)
}

fn spki(algorithm: &[&[u8]], key: &[u8]) -> Vec<u8> {
    let bit_string = der(0x03, &[&[0u8][..], key].concat());
    sequence(&[&sequence(algorithm), &bit_string])
}

/// The SubjectPublicKeyInfo of an RSA key from its PKCS#1 `RSAPublicKey`.
pub fn spki_from_rsa_pkcs1(pkcs1: &[u8]) -> Vec<u8> {
    spki(&[RSA_ENCRYPTION, NULL], pkcs1)
}

/// The SubjectPublicKeyInfo of an ECDSA key from its uncompressed point (`04 || X || Y`).
pub fn spki_from_ec_point(curve: Curve, point: &[u8]) -> Vec<u8> {
    let curve = match curve {
        Curve::P256 => P256,
        Curve::P384 => P384,
        Curve::P521 => P521,
    };
    spki(&[EC_PUBLIC_KEY, curve], point)
}

/// The SubjectPublicKeyInfo of an ML-DSA key from its raw public key.
pub fn spki_from_ml_dsa(set: MlDsaSet, raw: &[u8]) -> Vec<u8> {
    let oid = match set {
        MlDsaSet::MlDsa44 => ML_DSA_44,
        MlDsaSet::MlDsa65 => ML_DSA_65,
        MlDsaSet::MlDsa87 => ML_DSA_87,
    };
    spki(&[oid], raw)
}

fn malformed(what: &str) -> KeyError {
    KeyError::Failed(format!("malformed {what} public key blob"))
}

fn field(blob: &[u8], at: usize) -> Result<u32, KeyError> {
    blob.get(at..at + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| malformed("CNG"))
}

fn slice(blob: &[u8], from: usize, length: u32) -> Result<&[u8], KeyError> {
    let end = from
        .checked_add(length as usize)
        .ok_or_else(|| malformed("CNG"))?;
    blob.get(from..end).ok_or_else(|| malformed("CNG"))
}

/// The PKCS#1 `RSAPublicKey` of a `BCRYPT_RSAPUBLIC_BLOB`.
pub fn rsa_pkcs1_from_cng(blob: &[u8]) -> Result<Vec<u8>, KeyError> {
    if field(blob, 0)? != RSA_PUBLIC_MAGIC {
        return Err(malformed("RSA"));
    }
    let exponent_length = field(blob, 8)?;
    let modulus_length = field(blob, 12)?;
    let exponent = slice(blob, 24, exponent_length)?;
    let modulus = slice(blob, 24 + exponent_length as usize, modulus_length)?;
    Ok(sequence(&[&integer(modulus), &integer(exponent)]))
}

/// The curve and the uncompressed point of a `BCRYPT_ECCPUBLIC_BLOB`.
pub fn ec_point_from_cng(blob: &[u8]) -> Result<(Curve, Vec<u8>), KeyError> {
    let curve = match field(blob, 0)? {
        ECDSA_P256_PUBLIC_MAGIC => Curve::P256,
        ECDSA_P384_PUBLIC_MAGIC => Curve::P384,
        ECDSA_P521_PUBLIC_MAGIC => Curve::P521,
        _ => return Err(malformed("EC")),
    };
    let length = field(blob, 4)?;
    let coordinates = slice(
        blob,
        8,
        length.checked_mul(2).ok_or_else(|| malformed("EC"))?,
    )?;
    Ok((curve, [&[0x04][..], coordinates].concat()))
}

/// The parameter set and the raw public key of a `BCRYPT_PQDSA_PUBLIC_BLOB`: a header of the magic, the size
/// of the parameter set name and the size of the key, then the name as UTF-16 ("44", "65" or "87") and the
/// key.
pub fn ml_dsa_from_cng(blob: &[u8]) -> Result<(MlDsaSet, Vec<u8>), KeyError> {
    if field(blob, 0)? != ML_DSA_PUBLIC_MAGIC {
        return Err(malformed("ML-DSA"));
    }
    let name_length = field(blob, 4)?;
    let key_length = field(blob, 8)?;
    let name = slice(blob, 12, name_length)?;
    let key = slice(blob, 12 + name_length as usize, key_length)?;
    let units: Vec<u16> = name
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    let set = match String::from_utf16_lossy(&units).as_str() {
        "44" => MlDsaSet::MlDsa44,
        "65" => MlDsaSet::MlDsa65,
        "87" => MlDsaSet::MlDsa87,
        _ => return Err(malformed("ML-DSA")),
    };
    Ok((set, key.to_vec()))
}

/// The key type and the SubjectPublicKeyInfo of a CNG public key blob (RSA, ECDSA or ML-DSA).
pub fn public_key_from_cng(blob: &[u8]) -> Result<(KeyType, Vec<u8>), KeyError> {
    match field(blob, 0)? {
        RSA_PUBLIC_MAGIC => {
            let key_type = KeyType::Rsa {
                bits: field(blob, 4)?,
            };
            Ok((key_type, spki_from_rsa_pkcs1(&rsa_pkcs1_from_cng(blob)?)))
        }
        ML_DSA_PUBLIC_MAGIC => {
            let (set, raw) = ml_dsa_from_cng(blob)?;
            let key_type = match set {
                MlDsaSet::MlDsa44 => KeyType::MlDsa44,
                MlDsaSet::MlDsa65 => KeyType::MlDsa65,
                MlDsaSet::MlDsa87 => KeyType::MlDsa87,
            };
            Ok((key_type, spki_from_ml_dsa(set, &raw)))
        }
        _ => {
            let (curve, point) = ec_point_from_cng(blob)?;
            let key_type = match curve {
                Curve::P256 => KeyType::EcP256,
                Curve::P384 => KeyType::EcP384,
                Curve::P521 => KeyType::EcP521,
            };
            Ok((key_type, spki_from_ec_point(curve, &point)))
        }
    }
}

/// The key types a CNG provider may offer, from the names of the signature algorithms it lists and the
/// smallest and largest RSA key length it reports. A listed ML-DSA stands for all three parameter sets, which
/// the provider does not list; the caller keeps those it can create.
pub fn key_types_from_cng(algorithms: &[String], rsa_lengths: Option<(u32, u32)>) -> Vec<KeyType> {
    let listed = |name: &str| algorithms.iter().any(|algorithm| algorithm == name);
    let mut types = Vec::new();
    if let Some((min, max)) = rsa_lengths.filter(|_| listed("RSA")) {
        types.extend(rsa_types(min, max));
    }
    for (name, key_type) in [
        ("ECDSA_P256", KeyType::EcP256),
        ("ECDSA_P384", KeyType::EcP384),
        ("ECDSA_P521", KeyType::EcP521),
    ] {
        if listed(name) {
            types.push(key_type);
        }
    }
    if listed("ML-DSA") {
        types.extend([KeyType::MlDsa44, KeyType::MlDsa65, KeyType::MlDsa87]);
    }
    types
}

/// The DER `ECDSA-Sig-Value` of a raw signature, `r || s` with both numbers of the same length.
pub fn ecdsa_der_from_raw(r_s: &[u8]) -> Result<Vec<u8>, KeyError> {
    if r_s.is_empty() || !r_s.len().is_multiple_of(2) {
        return Err(KeyError::Failed("malformed raw ECDSA signature".to_owned()));
    }
    let (r, s) = r_s.split_at(r_s.len() / 2);
    Ok(sequence(&[&integer(r), &integer(s)]))
}

/// The digest a storage signs for this key type: SHA-256 for RSA and P-256, SHA-384 for P-384, SHA-512 for
/// P-521. ML-DSA signs the whole message, so it has none.
pub fn digest(key_type: KeyType, message: &[u8]) -> Option<Vec<u8>> {
    match key_type {
        KeyType::Rsa { .. } | KeyType::EcP256 => Some(Sha256::digest(message).to_vec()),
        KeyType::EcP384 => Some(Sha384::digest(message).to_vec()),
        KeyType::EcP521 => Some(Sha512::digest(message).to_vec()),
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => None,
    }
}
