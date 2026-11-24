use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use super::*;
use crate::keys::testing::{InMemoryStorage, verify};
use crate::keys::{KeyStorage, KeyType, Storage};

const ALL_TYPES: [KeyType; 9] = [
    KeyType::Rsa { bits: 2048 },
    KeyType::Rsa { bits: 3072 },
    KeyType::Rsa { bits: 4096 },
    KeyType::EcP256,
    KeyType::EcP384,
    KeyType::EcP521,
    KeyType::MlDsa44,
    KeyType::MlDsa65,
    KeyType::MlDsa87,
];

fn named(common_name: &str) -> RequestSubject {
    RequestSubject {
        names: vec![(NameType::CommonName, common_name.to_string())],
        alternative_names: Vec::new(),
    }
}

fn key_of(key_type: KeyType) -> Box<dyn StoredKey> {
    InMemoryStorage::new(&[Storage::Software])
        .create(Storage::Software, key_type)
        .unwrap()
}

fn request_for(subject: &RequestSubject) -> Vec<u8> {
    signing_request(key_of(KeyType::EcP256).as_ref(), subject).unwrap()
}

fn parse(der: &[u8]) -> X509CertificationRequest<'_> {
    let (rest, request) = X509CertificationRequest::from_der(der).unwrap();
    assert!(rest.is_empty());
    request
}

fn alternative_names(request: &X509CertificationRequest<'_>) -> Vec<String> {
    let Some(extensions) = request.requested_extensions() else {
        return Vec::new();
    };
    extensions
        .filter_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter().map(|name| format!("{name:?}")))
        .collect()
}

#[test]
fn every_key_type_gives_a_request_with_a_valid_signature() {
    for key_type in ALL_TYPES {
        let key = key_of(key_type);
        let der = signing_request(key.as_ref(), &named("device")).unwrap();
        let request = parse(&der);
        assert_eq!(
            request.certification_request_info.subject_pki.raw,
            key.public_key(),
            "{key_type:?}"
        );
        assert!(
            verify(
                key.as_ref(),
                request.certification_request_info.raw,
                request.signature_value.data.as_ref()
            ),
            "{key_type:?}"
        );
    }
}

#[test]
fn a_request_for_another_message_does_not_verify() {
    let key = key_of(KeyType::EcP256);
    let der = signing_request(key.as_ref(), &named("device")).unwrap();
    let request = parse(&der);
    assert!(!verify(
        key.as_ref(),
        b"other",
        request.signature_value.data.as_ref()
    ));
}

#[test]
fn subject_keeps_its_order() {
    let subject = RequestSubject {
        names: vec![
            (NameType::Country, "DE".into()),
            (NameType::Organization, "Example".into()),
            (NameType::OrganizationalUnit, "Unit".into()),
            (NameType::CommonName, "device".into()),
            (NameType::State, "Bavaria".into()),
            (NameType::Locality, "Munich".into()),
            (NameType::Email, "a@example.com".into()),
            (NameType::SerialNumber, "42".into()),
            (
                NameType::Other(vec![0, 9, 2342, 19200300, 100, 1, 25]),
                "example".into(),
            ),
        ],
        alternative_names: Vec::new(),
    };
    let der = request_for(&subject);
    let request = parse(&der);
    let found: Vec<(String, String)> = request
        .certification_request_info
        .subject
        .iter_attributes()
        .map(|attribute| {
            (
                attribute.attr_type().to_id_string(),
                attribute.as_str().unwrap().to_string(),
            )
        })
        .collect();
    let expected: Vec<(&str, &str)> = vec![
        ("2.5.4.6", "DE"),
        ("2.5.4.10", "Example"),
        ("2.5.4.11", "Unit"),
        ("2.5.4.3", "device"),
        ("2.5.4.8", "Bavaria"),
        ("2.5.4.7", "Munich"),
        ("1.2.840.113549.1.9.1", "a@example.com"),
        ("2.5.4.5", "42"),
        ("0.9.2342.19200300.100.1.25", "example"),
    ];
    let expected: Vec<(String, String)> = expected
        .into_iter()
        .map(|(oid, value)| (oid.to_string(), value.to_string()))
        .collect();
    assert_eq!(found, expected);
}

#[test]
fn each_alternative_name_type_is_requested() {
    let subject = RequestSubject {
        names: vec![(NameType::CommonName, "device".into())],
        alternative_names: vec![
            AlternativeName::Dns("device.example.com".into()),
            AlternativeName::Email("a@example.com".into()),
            AlternativeName::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            AlternativeName::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            AlternativeName::Uri("https://example.com/device".into()),
        ],
    };
    let der = request_for(&subject);
    let request = parse(&der);
    let extensions = request.requested_extensions().unwrap().collect::<Vec<_>>();
    let [ParsedExtension::SubjectAlternativeName(san)] = extensions.as_slice() else {
        panic!("one subject alternative name extension, found {extensions:?}");
    };
    let names: Vec<&GeneralName> = san.general_names.iter().collect();
    assert!(matches!(
        names[0],
        GeneralName::DNSName("device.example.com")
    ));
    assert!(matches!(names[1], GeneralName::RFC822Name("a@example.com")));
    assert!(matches!(names[2], GeneralName::IPAddress([192, 0, 2, 1])));
    assert!(
        matches!(names[3], GeneralName::IPAddress(bytes) if *bytes == Ipv6Addr::LOCALHOST.octets())
    );
    assert!(matches!(
        names[4],
        GeneralName::URI("https://example.com/device")
    ));
    assert_eq!(names.len(), 5);
}

#[test]
fn upn_is_an_other_name_with_a_utf8_string() {
    let subject = RequestSubject {
        names: vec![(NameType::CommonName, "device".into())],
        alternative_names: vec![AlternativeName::Upn("user@example.com".into())],
    };
    let der = request_for(&subject);
    let request = parse(&der);
    let extensions = request.requested_extensions().unwrap().collect::<Vec<_>>();
    let [ParsedExtension::SubjectAlternativeName(san)] = extensions.as_slice() else {
        panic!("one subject alternative name extension");
    };
    let [GeneralName::OtherName(oid, value)] = san.general_names.as_slice() else {
        panic!("one otherName");
    };
    assert_eq!(oid.to_id_string(), "1.3.6.1.4.1.311.20.2.3");
    // [0] EXPLICIT { UTF8String "user@example.com" }
    let mut expected = vec![
        0xA0,
        2 + "user@example.com".len() as u8,
        0x0C,
        "user@example.com".len() as u8,
    ];
    expected.extend(b"user@example.com");
    assert_eq!(value.to_vec(), expected);
}

#[test]
fn no_extension_is_requested_without_alternative_names() {
    let der = request_for(&named("device"));
    let request = parse(&der);
    assert!(request.requested_extensions().is_none());
    assert!(request.certification_request_info.attributes().is_empty());
    assert!(alternative_names(&request).is_empty());
}

#[test]
fn only_the_alternative_names_are_requested_as_extensions() {
    let subject = RequestSubject {
        names: vec![(NameType::CommonName, "device".into())],
        alternative_names: vec![AlternativeName::Dns("device.example.com".into())],
    };
    let der = request_for(&subject);
    let request = parse(&der);
    assert_eq!(request.requested_extensions().unwrap().count(), 1);
}

#[test]
fn a_key_that_refuses_to_sign_gives_refused() {
    let storage = InMemoryStorage::new(&[Storage::Software]).refusing_to_sign();
    for key_type in [
        KeyType::Rsa { bits: 2048 },
        KeyType::EcP256,
        KeyType::MlDsa44,
    ] {
        let key = storage.create(Storage::Software, key_type).unwrap();
        assert_eq!(
            signing_request(key.as_ref(), &named("device")),
            Err(KeyError::Refused),
            "{key_type:?}"
        );
    }
}
