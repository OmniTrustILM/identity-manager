use std::net::Ipv4Addr;

use super::*;
use crate::keys::NameType;

fn names(items: &[(NameType, &str)]) -> Vec<(NameType, String)> {
    items
        .iter()
        .map(|(kind, value)| (kind.clone(), value.to_string()))
        .collect()
}

fn sans(items: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
    items
        .iter()
        .map(|(kind, values)| {
            (
                kind.to_string(),
                values.iter().map(ToString::to_string).collect(),
            )
        })
        .collect()
}

fn of(dn: &str) -> Result<RequestSubject, Unmappable> {
    registered_subject(Some(dn), &[])
}

#[test]
fn the_names_come_out_from_the_most_general_down() {
    assert_eq!(
        of("CN=web,OU=Ops,O=Example,C=DE").unwrap().names,
        names(&[
            (NameType::Country, "DE"),
            (NameType::Organization, "Example"),
            (NameType::OrganizationalUnit, "Ops"),
            (NameType::CommonName, "web"),
        ])
    );
}

#[test]
fn every_key_gives_its_name_type() {
    for (text, kind) in [
        ("cn=a", NameType::CommonName),
        ("O=a", NameType::Organization),
        ("OU=a", NameType::OrganizationalUnit),
        ("C=DE", NameType::Country),
        ("ST=a", NameType::State),
        ("L=a", NameType::Locality),
        ("E=a@b.example", NameType::Email),
        ("EMAILADDRESS=a@b.example", NameType::Email),
        ("SERIALNUMBER=7", NameType::SerialNumber),
        ("DC=example", NameType::DomainComponent),
        ("OID.1.2.3=a", NameType::Other(vec![1, 2, 3])),
        ("1.2.3.4=a", NameType::Other(vec![1, 2, 3, 4])),
    ] {
        assert_eq!(of(text).unwrap().names[0].0, kind, "{text}");
    }
}

#[test]
fn escapes_are_read() {
    assert_eq!(
        of(r"CN=a\,b\+c\\d\=e,O=x").unwrap().names,
        names(&[
            (NameType::Organization, "x"),
            (NameType::CommonName, r"a,b+c\d=e")
        ])
    );
    assert_eq!(
        of(r"CN=caf\C3\A9").unwrap().names,
        names(&[(NameType::CommonName, "café")])
    );
    assert_eq!(
        of("CN=a, O=b").unwrap().names,
        names(&[(NameType::Organization, "b"), (NameType::CommonName, "a")])
    );
}

#[test]
fn no_subject_is_no_names() {
    assert!(registered_subject(None, &[]).unwrap().names.is_empty());
    assert!(of("").unwrap().names.is_empty());
}

#[test]
fn a_name_this_application_cannot_write_refuses() {
    assert_eq!(
        of("CN=a,STREET=x").unwrap_err(),
        Unmappable::Unsupported {
            label: "STREET".into()
        }
    );
    for text in ["CN", "=a", "CN=", "CN=#0c0161", "CN=a+O=b", r"CN=a\"] {
        assert!(
            matches!(of(text), Err(Unmappable::Invalid { .. })),
            "{text}"
        );
    }
}

#[test]
fn two_names_of_a_type_refuse() {
    assert_eq!(
        of("OU=a,OU=b").unwrap_err(),
        Unmappable::Repeated { label: "OU".into() }
    );
}

#[test]
fn the_alternative_names_follow_the_names_core_gives_their_types() {
    let found = registered_subject(
        None,
        &sans(&[
            ("dNSName", &["a.example", "b.example"]),
            ("iPAddress", &["10.0.0.1"]),
            ("rfc822Name", &["me@example.com"]),
            ("uniformResourceIdentifier", &["https://a.example/x"]),
            ("otherName", &["1.3.6.1.4.1.311.20.2.3=me@corp.example"]),
            ("directoryName", &[]),
            ("registeredID", &[]),
        ]),
    )
    .unwrap();
    assert_eq!(
        found.alternative_names,
        [
            AlternativeName::Dns("a.example".into()),
            AlternativeName::Dns("b.example".into()),
            AlternativeName::Ip(Ipv4Addr::new(10, 0, 0, 1).into()),
            AlternativeName::Email("me@example.com".into()),
            AlternativeName::Uri("https://a.example/x".into()),
            AlternativeName::Upn("me@corp.example".into()),
        ]
    );
}

#[test]
fn an_alternative_name_this_application_cannot_write_refuses() {
    for (kind, value) in [
        ("directoryName", "CN=x"),
        ("otherName", "1.2.3=x"),
        ("otherName", "no equals"),
        ("x400Address", "x"),
    ] {
        assert!(
            matches!(
                registered_subject(None, &sans(&[(kind, &[value])])),
                Err(Unmappable::Unsupported { .. })
            ),
            "{kind}"
        );
    }
    assert!(matches!(
        registered_subject(None, &sans(&[("iPAddress", &["not an address"])])),
        Err(Unmappable::Invalid { .. })
    ));
}
