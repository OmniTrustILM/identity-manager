use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use rcgen::{
    KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512,
    PKCS_ML_DSA_44, PKCS_ML_DSA_65, PKCS_ML_DSA_87, PKCS_RSA_SHA256, PublicKeyData, RsaKeySize,
    SignatureAlgorithm,
};
use sha2::{Digest, Sha256};

use super::encoding::*;
use super::testing::{InMemoryStorage, check_contract, verify};
use super::*;

fn generated(alg: &'static SignatureAlgorithm) -> KeyPair {
    KeyPair::generate_for(alg).expect("key generation")
}

fn all_storages() -> [Storage; 3] {
    [Storage::Keychain, Storage::Software, Storage::Tpm]
}

fn cng_ec_blob(magic: u32, point: &[u8]) -> Vec<u8> {
    let coordinates = &point[1..];
    let mut blob = magic.to_le_bytes().to_vec();
    blob.extend(((coordinates.len() / 2) as u32).to_le_bytes());
    blob.extend(coordinates);
    blob
}

fn cng_rsa_blob(exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut blob = 0x3141_5352u32.to_le_bytes().to_vec();
    blob.extend(((modulus.len() * 8) as u32).to_le_bytes());
    blob.extend((exponent.len() as u32).to_le_bytes());
    blob.extend((modulus.len() as u32).to_le_bytes());
    blob.extend([0u8; 8]);
    blob.extend(exponent);
    blob.extend(modulus);
    blob
}

fn cng_ml_dsa_blob(set_name: &str, key: &[u8]) -> Vec<u8> {
    let name: Vec<u8> = set_name
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut blob = 0x4B50_5344u32.to_le_bytes().to_vec();
    blob.extend((name.len() as u32).to_le_bytes());
    blob.extend((key.len() as u32).to_le_bytes());
    blob.extend(name);
    blob.extend(key);
    blob
}

// RSA public key

#[test]
fn rsa_spki_equals_the_one_of_aws_lc() {
    for size in [RsaKeySize::_2048, RsaKeySize::_3072] {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, size).unwrap();
        assert_eq!(
            spki_from_rsa_pkcs1(key.der_bytes()),
            key.subject_public_key_info()
        );
    }
}

#[test]
fn rsa_cng_blob_gives_pkcs1() {
    let modulus = [vec![0xC0], vec![0x01; 127]].concat();
    let blob = cng_rsa_blob(&[0x01, 0x00, 0x01], &modulus);
    let expected = [
        &[0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00][..],
        &modulus,
        &[0x02, 0x03, 0x01, 0x00, 0x01],
    ]
    .concat();
    assert_eq!(rsa_pkcs1_from_cng(&blob).unwrap(), expected);
}

#[test]
fn rsa_cng_blob_round_trips_through_spki() {
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let (exponent, modulus) = rsa_parts(key.der_bytes());
    let pkcs1 = rsa_pkcs1_from_cng(&cng_rsa_blob(&exponent, &modulus)).unwrap();
    assert_eq!(spki_from_rsa_pkcs1(&pkcs1), key.subject_public_key_info());
}

/// The exponent and the modulus of a PKCS#1 public key, without the sign byte.
fn rsa_parts(pkcs1: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (_, sequence) = x509_parser::der_parser::der::parse_der_sequence(pkcs1).unwrap();
    let integers = sequence.as_sequence().unwrap();
    let unsigned = |index: usize| {
        let bytes = integers[index].as_slice().unwrap();
        bytes.strip_prefix(&[0]).unwrap_or(bytes).to_vec()
    };
    (unsigned(1), unsigned(0))
}

#[test]
fn rsa_cng_blob_that_is_cut_short_is_refused() {
    let blob = cng_rsa_blob(&[1, 0, 1], &[0xC0; 128]);
    assert!(rsa_pkcs1_from_cng(&blob[..blob.len() - 1]).is_err());
    assert!(rsa_pkcs1_from_cng(&[]).is_err());
}

#[test]
fn rsa_cng_blob_with_another_magic_is_refused() {
    let mut blob = cng_rsa_blob(&[1, 0, 1], &[0xC0; 128]);
    blob[0] ^= 0xFF;
    assert!(rsa_pkcs1_from_cng(&blob).is_err());
}

// EC public key

const CURVES: [(&SignatureAlgorithm, Curve, u32); 3] = [
    (&PKCS_ECDSA_P256_SHA256, Curve::P256, 0x3153_4345),
    (&PKCS_ECDSA_P384_SHA384, Curve::P384, 0x3353_4345),
    (&PKCS_ECDSA_P521_SHA512, Curve::P521, 0x3553_4345),
];

#[test]
fn ec_spki_equals_the_one_of_aws_lc() {
    for (alg, curve, _) in CURVES {
        let key = generated(alg);
        assert_eq!(
            spki_from_ec_point(curve, key.der_bytes()),
            key.subject_public_key_info(),
            "{curve:?}"
        );
    }
}

#[test]
fn ec_cng_blob_gives_curve_and_point() {
    for (alg, curve, magic) in CURVES {
        let key = generated(alg);
        let blob = cng_ec_blob(magic, key.der_bytes());
        assert_eq!(
            ec_point_from_cng(&blob).unwrap(),
            (curve, key.der_bytes().to_vec())
        );
    }
}

#[test]
fn ec_cng_blob_with_a_wrong_length_or_magic_is_refused() {
    let key = generated(&PKCS_ECDSA_P256_SHA256);
    let blob = cng_ec_blob(0x3153_4345, key.der_bytes());
    assert!(ec_point_from_cng(&blob[..blob.len() - 1]).is_err());
    assert!(ec_point_from_cng(&cng_ec_blob(0x1234_5678, key.der_bytes())).is_err());
    assert!(ec_point_from_cng(&[]).is_err());
}

// ML-DSA public key

const SETS: [(&SignatureAlgorithm, MlDsaSet, &str); 3] = [
    (&PKCS_ML_DSA_44, MlDsaSet::MlDsa44, "44"),
    (&PKCS_ML_DSA_65, MlDsaSet::MlDsa65, "65"),
    (&PKCS_ML_DSA_87, MlDsaSet::MlDsa87, "87"),
];

#[test]
fn ml_dsa_spki_equals_the_one_of_aws_lc() {
    for (alg, set, name) in SETS {
        let key = generated(alg);
        assert_eq!(
            spki_from_ml_dsa(set, key.der_bytes()),
            key.subject_public_key_info(),
            "{name}"
        );
    }
}

#[test]
fn ml_dsa_cng_blob_gives_set_and_key() {
    for (alg, set, name) in SETS {
        let key = generated(alg);
        let blob = cng_ml_dsa_blob(name, key.der_bytes());
        assert_eq!(
            ml_dsa_from_cng(&blob).unwrap(),
            (set, key.der_bytes().to_vec())
        );
    }
}

#[test]
fn ml_dsa_cng_blob_with_an_unknown_set_or_cut_short_is_refused() {
    let blob = cng_ml_dsa_blob("99", &[7; 32]);
    assert!(ml_dsa_from_cng(&blob).is_err());
    let blob = cng_ml_dsa_blob("44", &[7; 32]);
    assert!(ml_dsa_from_cng(&blob[..blob.len() - 1]).is_err());
    assert!(ml_dsa_from_cng(&[]).is_err());
}

#[test]
fn ml_dsa_cng_blob_with_another_magic_is_refused() {
    let mut blob = cng_ml_dsa_blob("44", &[7; 32]);
    blob[..4].copy_from_slice(&0x4B53_5344u32.to_le_bytes());
    assert!(ml_dsa_from_cng(&blob).is_err());
}

// Any CNG public key

#[test]
fn a_cng_public_key_blob_gives_its_key_type_and_spki() {
    let key = generated(&PKCS_ECDSA_P384_SHA384);
    let blob = cng_ec_blob(0x3353_4345, key.der_bytes());
    assert_eq!(
        public_key_from_cng(&blob).unwrap(),
        (KeyType::EcP384, key.subject_public_key_info())
    );
    let key = generated(&PKCS_ML_DSA_65);
    let blob = cng_ml_dsa_blob("65", key.der_bytes());
    assert_eq!(
        public_key_from_cng(&blob).unwrap(),
        (KeyType::MlDsa65, key.subject_public_key_info())
    );
    let blob = cng_rsa_blob(&[1, 0, 1], &[0xC3; 256]);
    let (key_type, spki) = public_key_from_cng(&blob).unwrap();
    assert_eq!(key_type, KeyType::Rsa { bits: 2048 });
    assert_eq!(
        spki,
        spki_from_rsa_pkcs1(&rsa_pkcs1_from_cng(&blob).unwrap())
    );
    assert!(public_key_from_cng(&[]).is_err());
}

// Key types of a CNG provider

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(ToString::to_string).collect()
}

#[test]
fn the_listed_algorithms_give_the_candidate_key_types() {
    let listed = names(&[
        "RSA",
        "ECDSA_P256",
        "ECDSA_P521",
        "ML-DSA",
        "ECDH_P256",
        "SHA1",
    ]);
    assert_eq!(
        key_types_from_cng(&listed, Some((1024, 3072))),
        [
            KeyType::Rsa { bits: 2048 },
            KeyType::Rsa { bits: 3072 },
            KeyType::EcP256,
            KeyType::EcP521,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
            KeyType::MlDsa87,
        ]
    );
}

#[test]
fn rsa_needs_to_be_listed_and_to_report_its_lengths() {
    assert_eq!(
        key_types_from_cng(&names(&["ECDSA_P384"]), Some((2048, 4096))),
        [KeyType::EcP384]
    );
    assert_eq!(key_types_from_cng(&names(&["RSA"]), None), []);
    assert_eq!(key_types_from_cng(&[], None), []);
}

// ECDSA signature

#[test]
fn ecdsa_raw_signature_becomes_der() {
    let mut raw = vec![0u8; 64];
    raw[31] = 1;
    raw[63] = 2;
    assert_eq!(
        ecdsa_der_from_raw(&raw).unwrap(),
        [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
    );
}

#[test]
fn ecdsa_integer_with_a_high_bit_gets_a_zero_byte() {
    let raw = [vec![0x80; 32], vec![0x7F; 32]].concat();
    let der = ecdsa_der_from_raw(&raw).unwrap();
    assert_eq!(&der[..6], &[0x30, 0x45, 0x02, 0x21, 0x00, 0x80]);
    assert_eq!(&der[37..39], &[0x02, 0x20]);
    assert_eq!(der[39], 0x7F);
    assert_eq!(der.len(), 2 + 35 + 34);
}

#[test]
fn ecdsa_zero_integers_stay_one_byte() {
    assert_eq!(
        ecdsa_der_from_raw(&[0; 64]).unwrap(),
        [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
    );
}

#[test]
fn ecdsa_long_integers_use_a_long_form_length() {
    let der = ecdsa_der_from_raw(&[0xFF; 132]).unwrap();
    assert_eq!(&der[..4], &[0x30, 0x81, 0x8A, 0x02]);
    assert_eq!(der.len(), 3 + 2 * (2 + 67));
}

#[test]
fn ecdsa_raw_signature_of_odd_or_no_length_is_refused() {
    assert!(ecdsa_der_from_raw(&[]).is_err());
    assert!(ecdsa_der_from_raw(&[1; 63]).is_err());
}

#[test]
fn ecdsa_der_from_raw_verifies_against_the_public_key() {
    let key = generated(&PKCS_ECDSA_P256_SHA256);
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.serialized_der()).unwrap();
    for _ in 0..50 {
        let raw = pair
            .sign(&aws_lc_rs::rand::SystemRandom::new(), b"message")
            .unwrap();
        let der = ecdsa_der_from_raw(raw.as_ref()).unwrap();
        let public = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
            key.der_bytes(),
        );
        public.verify(b"message", &der).unwrap();
    }
}

// Digest

#[test]
fn digest_follows_the_key_type() {
    let message = b"abc";
    assert_eq!(
        digest(KeyType::Rsa { bits: 2048 }, message).unwrap(),
        Sha256::digest(message).to_vec()
    );
    assert_eq!(
        digest(KeyType::EcP256, message).unwrap(),
        Sha256::digest(message).to_vec()
    );
    assert_eq!(digest(KeyType::EcP384, message).unwrap().len(), 48);
    assert_eq!(digest(KeyType::EcP521, message).unwrap().len(), 64);
}

#[test]
fn digest_has_no_prehash_for_ml_dsa() {
    for key_type in [KeyType::MlDsa44, KeyType::MlDsa65, KeyType::MlDsa87] {
        assert_eq!(digest(key_type, b"abc"), None);
    }
}

// Types

#[test]
fn key_id_survives_json() {
    let id = KeyId {
        storage: Storage::Tpm,
        name: "IdentityManager-0a1b".to_owned(),
    };
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(serde_json::from_str::<KeyId>(&json).unwrap(), id);
}

#[test]
fn rsa_types_are_the_common_sizes_inside_the_range() {
    let bits = |min, max| {
        rsa_types(min, max)
            .into_iter()
            .map(|key_type| match key_type {
                KeyType::Rsa { bits } => bits,
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(bits(2048, 8192), [2048, 3072, 4096, 6144, 8192]);
    assert_eq!(bits(1024, 4096), [2048, 3072, 4096]);
    assert_eq!(bits(3000, 6144), [3072, 4096, 6144]);
    assert_eq!(bits(2048, 2048), [2048]);
    assert!(bits(4096, 2048).is_empty());
    assert!(bits(512, 1024).is_empty());
}

// No storage

#[test]
fn no_key_storage_offers_nothing() {
    let storage = NoKeyStorage;
    assert!(storage.offered().is_empty());
    for storage_kind in all_storages() {
        assert!(matches!(
            storage.create(storage_kind, KeyType::EcP256),
            Err(KeyError::NotOffered)
        ));
        let id = KeyId {
            storage: storage_kind,
            name: "gone".to_owned(),
        };
        assert!(storage.open(&id).unwrap().is_none());
        storage.delete(&id).unwrap();
    }
    check_contract(&storage);
}

// Stand-in

#[test]
fn stand_in_meets_the_contract() {
    check_contract(&InMemoryStorage::new(&[
        Storage::Keychain,
        Storage::Software,
    ]));
}

#[test]
fn stand_in_offers_every_type_it_can_make_in_each_storage() {
    let offers = InMemoryStorage::new(&[Storage::Software, Storage::Tpm]).offered();
    assert_eq!(offers.len(), 2);
    for offer in offers {
        assert_eq!(offer.types.len(), 3 + 3 + 3);
        assert!(offer.types.contains(&KeyType::EcP521));
        assert!(offer.types.contains(&KeyType::MlDsa87));
    }
}

#[test]
fn stand_in_signs_every_type_it_offers() {
    let storage = InMemoryStorage::new(&[Storage::Software]);
    for key_type in storage.offered().remove(0).types {
        let key = storage.create(Storage::Software, key_type).unwrap();
        let signature = key.sign(b"message").unwrap();
        assert!(verify(key.as_ref(), b"message", &signature), "{key_type:?}");
        assert!(!verify(key.as_ref(), b"other", &signature), "{key_type:?}");
    }
}

#[test]
fn stand_in_that_refuses_gives_refused() {
    let storage = InMemoryStorage::new(&[Storage::Software]).refusing_to_sign();
    let key = storage.create(Storage::Software, KeyType::EcP256).unwrap();
    assert!(matches!(key.sign(b"message"), Err(KeyError::Refused)));
    let opened = storage.open(key.id()).unwrap().unwrap();
    assert!(matches!(opened.sign(b"message"), Err(KeyError::Refused)));
}
