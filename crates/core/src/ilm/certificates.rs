//! Certificates as ILM lists them: the search request, the pages it answers with, and the match by fingerprint.

use std::str::FromStr;

use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::IlmUrl;
use super::profile::IlmError;
use crate::identity::Fingerprint;

/// The most fingerprints ILM is asked about in one request.
pub const MATCH_LIMIT: usize = 1000;
/// The size of a page of the list the person browses.
pub const PAGE_SIZE: u32 = 50;
/// The most certificates registered in advance that one check lists.
pub const REGISTERED_LIMIT: u32 = 100;

macro_rules! ilm_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $code:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
            /// A value this application does not know.
            Other(String),
        }

        impl $name {
            pub fn from_code(code: &str) -> Self {
                match code {
                    $($code => Self::$variant,)+
                    other => Self::Other(other.to_string()),
                }
            }

            pub fn code(&self) -> &str {
                match self {
                    $(Self::$variant => $code,)+
                    Self::Other(other) => other,
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.code())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Ok(Self::from_code(&String::deserialize(deserializer)?))
            }
        }
    };
}

ilm_enum!(
    /// Where a certificate stands in its life in ILM.
    State {
        Requested => "requested",
        Rejected => "rejected",
        PendingApproval => "pending_approval",
        PendingIssue => "pending_issue",
        PendingRevoke => "pending_revoke",
        PendingRegistration => "pending_registration",
        Registered => "registered",
        Failed => "failed",
        Issued => "issued",
        Revoked => "revoked",
    }
);

ilm_enum!(
    /// Whether the person may still complete a certificate registered in advance.
    RegistrationState {
        Active => "active",
        Expired => "expired",
        Locked => "locked",
        Closed => "closed",
    }
);

ilm_enum!(
    /// What ILM's last validation of a certificate found.
    ValidationStatus {
        NotChecked => "not_checked",
        Failed => "failed",
        Inactive => "inactive",
        Invalid => "invalid",
        Valid => "valid",
        Revoked => "revoked",
        Expiring => "expiring",
        Expired => "expired",
    }
);

/// The RA Profile that manages a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaProfile {
    pub uuid: String,
    pub name: String,
    /// The authority the profile issues from, when ILM says.
    #[serde(default)]
    pub authority_uuid: Option<String>,
}

/// A certificate in ILM's inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IlmCertificate {
    pub uuid: String,
    pub name: String,
    pub subject_dn: Option<String>,
    pub issuer_name: Option<String>,
    pub serial: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub not_before: Option<i64>,
    /// Milliseconds since the Unix epoch.
    pub not_after: Option<i64>,
    pub fingerprint: Option<Fingerprint>,
    /// The public key as text, such as "RSA 2048".
    pub key: Option<String>,
    pub state: State,
    pub validation_status: ValidationStatus,
    pub ra_profile: Option<RaProfile>,
    pub owner: Option<String>,
    pub groups: Vec<String>,
    pub archived: bool,
}

/// One page of ILM's certificate list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePage {
    pub certificates: Vec<IlmCertificate>,
    /// Starts at 1.
    pub page_number: u32,
    pub total_pages: u32,
    pub total_items: u64,
    /// How many items of this page could not be read and are left out.
    #[serde(default)]
    pub skipped: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCertificate {
    uuid: Option<String>,
    display_name: Option<String>,
    common_name: Option<String>,
    subject_dn: Option<String>,
    issuer_common_name: Option<String>,
    issuer_dn: Option<String>,
    serial_number: Option<String>,
    not_before: Option<Value>,
    not_after: Option<Value>,
    fingerprint: Option<String>,
    public_key_algorithm: Option<String>,
    key_size: Option<u32>,
    state: Option<String>,
    validation_status: Option<String>,
    ra_profile: Option<RawNamed>,
    owner: Option<String>,
    groups: Option<Vec<RawNamed>>,
    #[serde(default)]
    archived: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawNamed {
    uuid: Option<String>,
    name: Option<String>,
    authority_instance_uuid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPage {
    certificates: Vec<Value>,
    #[serde(default)]
    page_number: u32,
    #[serde(default)]
    total_pages: u32,
    #[serde(default)]
    total_items: u64,
}

fn present(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn key_text(algorithm: Option<String>, size: Option<u32>) -> Option<String> {
    let algorithm = present(algorithm)?;
    Some(match size {
        Some(size) => format!("{algorithm} {size}"),
        None => algorithm,
    })
}

impl RawCertificate {
    /// The certificate, or why it cannot be one.
    fn into_certificate(self) -> Result<IlmCertificate, &'static str> {
        let uuid = present(self.uuid).ok_or("no uuid")?;
        let subject_dn = present(self.subject_dn);
        let name = present(self.display_name)
            .or_else(|| present(self.common_name))
            .or_else(|| subject_dn.clone())
            .ok_or("no name")?;
        let state = present(self.state).ok_or("no state")?;
        let validation_status = present(self.validation_status).ok_or("no validation status")?;
        let ra_profile = self.ra_profile.and_then(|profile| {
            Some(RaProfile {
                uuid: present(profile.uuid)?,
                name: present(profile.name)?,
                authority_uuid: present(profile.authority_instance_uuid),
            })
        });
        Ok(IlmCertificate {
            uuid,
            name,
            subject_dn,
            issuer_name: present(self.issuer_common_name).or_else(|| present(self.issuer_dn)),
            serial: present(self.serial_number),
            not_before: self.not_before.as_ref().and_then(millis),
            not_after: self.not_after.as_ref().and_then(millis),
            fingerprint: self
                .fingerprint
                .and_then(|text| Fingerprint::from_str(&text).ok()),
            key: key_text(self.public_key_algorithm, self.key_size),
            state: State::from_code(&state),
            validation_status: ValidationStatus::from_code(&validation_status),
            ra_profile,
            owner: present(self.owner),
            groups: self
                .groups
                .unwrap_or_default()
                .into_iter()
                .filter_map(|group| present(group.name))
                .collect(),
            archived: self.archived,
        })
    }
}

/// A time as ILM writes it: an ISO 8601 text, or milliseconds since the epoch.
pub(super) fn millis(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => parse_iso(text),
        _ => None,
    }
}

fn parse_iso(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once('T')?;
    let mut date = date.splitn(3, '-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let split = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(split);
    let mut clock = clock.splitn(3, ':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let seconds: f64 = clock.next().unwrap_or("0").parse().ok()?;
    let offset = match zone {
        "" | "Z" | "z" => 0,
        zone => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let (hours, minutes) = zone[1..].split_once(':').unwrap_or((&zone[1..], "0"));
            sign * (hours.parse::<i64>().ok()? * 60 + minutes.parse::<i64>().ok()?)
        }
    };
    let days = days_from_civil(year, month, day);
    let whole = ((days * 24 + hour) * 60 + minute - offset) * 60;
    Some(whole * 1000 + (seconds * 1000.0).round() as i64)
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A fingerprint as ILM's search wants it: lowercase hex without colons.
pub fn search_text(fingerprint: &Fingerprint) -> String {
    fingerprint.to_string().replace(':', "").to_lowercase()
}

/// One search of ILM's certificate list.
#[derive(Debug, Clone, PartialEq)]
pub struct Search {
    filters: Vec<Value>,
    items_per_page: u32,
    page_number: u32,
}

fn property_filter(field: &str, condition: &str, value: Value) -> Value {
    json!({
        "fieldSource": "property",
        "fieldIdentifier": field,
        "condition": condition,
        "value": value,
    })
}

impl Search {
    /// A page of the whole list, or of the certificates whose common name contains `text`.
    pub fn page(page_number: u32, text: Option<&str>) -> Self {
        let filters = text
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(|text| property_filter("COMMON_NAME", "CONTAINS", json!(text)))
            .into_iter()
            .collect();
        Self {
            filters,
            items_per_page: PAGE_SIZE,
            page_number: page_number.max(1),
        }
    }

    /// The first page of the certificates registered in advance and owned by `username`.
    pub fn registered(username: &str) -> Self {
        Self {
            filters: vec![
                property_filter("CERTIFICATE_STATE", "EQUALS", json!(["registered"])),
                property_filter("OWNER", "EQUALS", json!([username])),
            ],
            items_per_page: REGISTERED_LIMIT,
            page_number: 1,
        }
    }

    /// The searches that find all of `fingerprints`: one per [`MATCH_LIMIT`], none for no fingerprints.
    pub fn matching(fingerprints: &[Fingerprint]) -> Vec<Self> {
        fingerprints
            .chunks(MATCH_LIMIT)
            .map(|chunk| Self {
                filters: vec![property_filter(
                    "FINGERPRINT",
                    "EQUALS",
                    json!(chunk.iter().map(search_text).collect::<Vec<_>>()),
                )],
                items_per_page: chunk.len() as u32,
                page_number: 1,
            })
            .collect()
    }

    /// The same search for page `page_number`.
    pub fn at_page(&self, page_number: u32) -> Self {
        Self {
            page_number,
            ..self.clone()
        }
    }

    pub fn request(&self, client: &Client, ilm: &IlmUrl) -> RequestBuilder {
        client
            .post(format!("{}/v1/certificates", ilm.api()))
            .json(&json!({
                "filters": self.filters,
                "itemsPerPage": self.items_per_page,
                "pageNumber": self.page_number,
            }))
    }
}

/// Reads ILM's answer to a search. A certificate that cannot be read is left out and logged.
pub async fn read_page(response: Response) -> Result<CertificatePage, IlmError> {
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(IlmError::Unauthorized);
    }
    if !status.is_success() {
        log::warn!("ILM answered the certificate search with {status}");
        return Err(IlmError::Unexpected(status.as_u16()));
    }
    let page = response.json::<RawPage>().await.map_err(|_| {
        log::warn!("ILM sent a certificate page this application cannot read");
        IlmError::Malformed
    })?;
    let mut skipped = 0;
    let certificates = page
        .certificates
        .into_iter()
        .filter_map(|item| {
            let uuid = item
                .get("uuid")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            let certificate = serde_json::from_value::<RawCertificate>(item)
                .map_err(|_| "not a certificate")
                .and_then(RawCertificate::into_certificate);
            match certificate {
                Ok(certificate) => Some(certificate),
                Err(reason) => {
                    log::debug!("Skipped ILM certificate {uuid}: {reason}");
                    skipped += 1;
                    None
                }
            }
        })
        .collect();
    Ok(CertificatePage {
        certificates,
        page_number: page.page_number,
        total_pages: page.total_pages,
        total_items: page.total_items,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn full() -> Value {
        json!({
            "uuid": "u-1",
            "displayName": "Display",
            "commonName": "common",
            "subjectDn": "CN=common,O=Acme",
            "issuerCommonName": "Issuer CA",
            "issuerDn": "CN=Issuer CA",
            "serialNumber": "0A1B",
            "notBefore": "2026-01-01T10:30:00.000+00:00",
            "notAfter": "2027-01-01T00:00:00Z",
            "publicKeyAlgorithm": "RSA",
            "keySize": 2048,
            "state": "issued",
            "validationStatus": "valid",
            "raProfile": { "uuid": "ra-1", "name": "Servers", "enabled": true },
            "fingerprint": HEX,
            "groups": [{ "uuid": "g-1", "name": "Web" }, { "uuid": "g-2", "name": "Ops" }],
            "owner": "jdoe",
            "archived": true,
            "somethingNew": { "a": 1 }
        })
    }

    fn parsed(item: Value) -> Result<IlmCertificate, &'static str> {
        serde_json::from_value::<RawCertificate>(item)
            .map_err(|_| "not a certificate")
            .and_then(RawCertificate::into_certificate)
    }

    #[test]
    fn a_full_item_is_read() {
        let certificate = parsed(full()).unwrap();
        assert_eq!(certificate.uuid, "u-1");
        assert_eq!(certificate.name, "Display");
        assert_eq!(certificate.subject_dn.as_deref(), Some("CN=common,O=Acme"));
        assert_eq!(certificate.issuer_name.as_deref(), Some("Issuer CA"));
        assert_eq!(certificate.serial.as_deref(), Some("0A1B"));
        assert_eq!(certificate.not_before, Some(1_767_263_400_000));
        assert_eq!(certificate.not_after, Some(1_798_761_600_000));
        assert_eq!(certificate.key.as_deref(), Some("RSA 2048"));
        assert_eq!(certificate.state, State::Issued);
        assert_eq!(certificate.validation_status, ValidationStatus::Valid);
        let ra = certificate.ra_profile.unwrap();
        assert_eq!((ra.uuid.as_str(), ra.name.as_str()), ("ra-1", "Servers"));
        assert_eq!(certificate.owner.as_deref(), Some("jdoe"));
        assert_eq!(certificate.groups, ["Web", "Ops"]);
        assert!(certificate.archived);
        assert_eq!(search_text(&certificate.fingerprint.unwrap()), HEX);
    }

    #[test]
    fn a_minimal_item_is_read() {
        let certificate = parsed(json!({
            "uuid": "u-2", "displayName": "Only", "state": "requested", "validationStatus": "not_checked"
        }))
        .unwrap();
        assert_eq!(certificate.name, "Only");
        assert_eq!(certificate.state, State::Requested);
        assert_eq!(certificate.validation_status, ValidationStatus::NotChecked);
        assert_eq!(certificate.subject_dn, None);
        assert_eq!(certificate.issuer_name, None);
        assert_eq!(certificate.serial, None);
        assert_eq!(certificate.not_after, None);
        assert_eq!(certificate.fingerprint, None);
        assert_eq!(certificate.key, None);
        assert_eq!(certificate.ra_profile, None);
        assert_eq!(certificate.owner, None);
        assert!(certificate.groups.is_empty());
        assert!(!certificate.archived);
    }

    #[test]
    fn unknown_states_are_kept_as_other() {
        let certificate = parsed(json!({
            "uuid": "u", "displayName": "n", "state": "quantum", "validationStatus": "shiny"
        }))
        .unwrap();
        assert_eq!(certificate.state, State::Other("quantum".into()));
        assert_eq!(
            certificate.validation_status,
            ValidationStatus::Other("shiny".into())
        );
    }

    #[test]
    fn every_known_code_has_a_variant() {
        for code in [
            "requested",
            "rejected",
            "pending_approval",
            "pending_issue",
            "pending_revoke",
            "pending_registration",
            "registered",
            "failed",
            "issued",
            "revoked",
        ] {
            assert!(!matches!(State::from_code(code), State::Other(_)), "{code}");
        }
        for code in [
            "not_checked",
            "failed",
            "inactive",
            "invalid",
            "valid",
            "revoked",
            "expiring",
            "expired",
        ] {
            assert!(
                !matches!(
                    ValidationStatus::from_code(code),
                    ValidationStatus::Other(_)
                ),
                "{code}"
            );
        }
    }

    #[test]
    fn the_fingerprint_is_read_from_hex_in_any_form() {
        for text in [HEX.to_string(), HEX.to_uppercase()] {
            let mut item = full();
            item["fingerprint"] = json!(text);
            assert_eq!(
                search_text(&parsed(item).unwrap().fingerprint.unwrap()),
                HEX
            );
        }
        let mut item = full();
        item["fingerprint"] = json!("zz");
        assert_eq!(parsed(item).unwrap().fingerprint, None);
    }

    #[test]
    fn the_key_is_text() {
        let key = |algorithm: Value, size: Value| {
            let mut item = full();
            item["publicKeyAlgorithm"] = algorithm;
            item["keySize"] = size;
            parsed(item).unwrap().key
        };
        assert_eq!(
            key(json!("ECDSA"), json!(256)).as_deref(),
            Some("ECDSA 256")
        );
        assert_eq!(
            key(json!("ML-DSA-65"), json!(null)).as_deref(),
            Some("ML-DSA-65")
        );
        assert_eq!(key(json!(null), json!(2048)), None);
    }

    #[test]
    fn the_name_falls_back() {
        let name = |display: Value, common: Value, subject: Value| {
            let mut item = full();
            item["displayName"] = display;
            item["commonName"] = common;
            item["subjectDn"] = subject;
            parsed(item)
        };
        assert_eq!(
            name(json!(""), json!("common"), json!("CN=x"))
                .unwrap()
                .name,
            "common"
        );
        assert_eq!(
            name(json!(null), json!(null), json!("CN=x")).unwrap().name,
            "CN=x"
        );
        assert_eq!(name(json!(null), json!(null), json!(null)), Err("no name"));
    }

    #[test]
    fn the_issuer_falls_back_to_its_dn() {
        let mut item = full();
        item.as_object_mut().unwrap().remove("issuerCommonName");
        assert_eq!(
            parsed(item).unwrap().issuer_name.as_deref(),
            Some("CN=Issuer CA")
        );
    }

    #[test]
    fn broken_items_say_why() {
        let mut no_uuid = full();
        no_uuid.as_object_mut().unwrap().remove("uuid");
        assert_eq!(parsed(no_uuid), Err("no uuid"));
        let mut no_state = full();
        no_state.as_object_mut().unwrap().remove("state");
        assert_eq!(parsed(no_state), Err("no state"));
        let mut no_status = full();
        no_status
            .as_object_mut()
            .unwrap()
            .remove("validationStatus");
        assert_eq!(parsed(no_status), Err("no validation status"));
        assert_eq!(parsed(json!("text")), Err("not a certificate"));
    }

    #[test]
    fn times_are_read_in_both_forms() {
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso("2026-01-01T12:00:00.250+02:00"),
            Some(1_767_261_600_250)
        );
        assert_eq!(
            parse_iso("2026-01-01T00:00:00-01:30"),
            Some(1_767_225_600_000 + 5_400_000)
        );
        assert_eq!(parse_iso("2026-01-01T00:00:00"), Some(1_767_225_600_000));
        assert_eq!(parse_iso("yesterday"), None);
        assert_eq!(parse_iso("2026-13-01T00:00:00Z"), None);
        assert_eq!(millis(&json!(1234)), Some(1234));
        assert_eq!(millis(&json!(null)), None);
    }

    #[test]
    fn a_page_request_has_the_paging_and_no_filter_without_text() {
        let request =
            Search::page(3, None).request(&client_for_tests(), &IlmUrl::for_tests("https://x"));
        let request = request.build().unwrap();
        assert_eq!(request.url().path(), "/api/v1/certificates");
        let body: Value =
            serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({ "filters": [], "itemsPerPage": 50, "pageNumber": 3 })
        );
        assert_eq!(Search::page(0, Some("  ")), Search::page(1, None));
    }

    #[test]
    fn a_search_text_filters_on_the_common_name() {
        let search = Search::page(1, Some(" web "));
        assert_eq!(
            search.filters,
            [json!({
                "fieldSource": "property",
                "fieldIdentifier": "COMMON_NAME",
                "condition": "CONTAINS",
                "value": "web"
            })]
        );
    }

    #[test]
    fn the_registered_search_filters_on_the_state_and_the_owner_in_one_page() {
        let request = Search::registered("ada")
            .request(&client_for_tests(), &IlmUrl::for_tests("https://x"))
            .build()
            .unwrap();
        let body: Value =
            serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "filters": [
                    {
                        "fieldSource": "property",
                        "fieldIdentifier": "CERTIFICATE_STATE",
                        "condition": "EQUALS",
                        "value": ["registered"]
                    },
                    {
                        "fieldSource": "property",
                        "fieldIdentifier": "OWNER",
                        "condition": "EQUALS",
                        "value": ["ada"]
                    }
                ],
                "itemsPerPage": 100,
                "pageNumber": 1
            })
        );
    }

    #[test]
    fn the_authority_of_the_ra_profile_is_read_and_an_old_cache_without_it_still_reads() {
        let mut item = full();
        item["raProfile"]["authorityInstanceUuid"] = json!("a-1");
        let certificate = parsed(item).unwrap();
        assert_eq!(
            certificate.ra_profile.unwrap().authority_uuid.as_deref(),
            Some("a-1")
        );
        assert_eq!(
            parsed(full()).unwrap().ra_profile.unwrap().authority_uuid,
            None
        );
        let old: RaProfile = serde_json::from_value(json!({ "uuid": "r", "name": "n" })).unwrap();
        assert_eq!(old.authority_uuid, None);
    }

    fn fingerprints(count: usize) -> Vec<Fingerprint> {
        (0..count)
            .map(|n| Fingerprint::of(&n.to_le_bytes()))
            .collect()
    }

    #[test]
    fn matching_sends_one_list_filter_in_lowercase_hex() {
        let prints = fingerprints(2);
        let searches = Search::matching(&prints);
        assert_eq!(searches.len(), 1);
        assert_eq!(searches[0].items_per_page, 2);
        assert_eq!(
            searches[0].filters,
            [json!({
                "fieldSource": "property",
                "fieldIdentifier": "FINGERPRINT",
                "condition": "EQUALS",
                "value": [search_text(&prints[0]), search_text(&prints[1])]
            })]
        );
        assert!(!search_text(&prints[0]).contains(':'));
        assert_eq!(
            search_text(&prints[0]),
            search_text(&prints[0]).to_lowercase()
        );
    }

    #[test]
    fn matching_is_chunked_and_empty_for_nothing() {
        assert!(Search::matching(&[]).is_empty());
        let sizes: Vec<u32> = Search::matching(&fingerprints(2001))
            .iter()
            .map(|search| search.items_per_page)
            .collect();
        assert_eq!(sizes, [1000, 1000, 1]);
    }

    async fn answer(response: ResponseTemplate) -> Result<CertificatePage, IlmError> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/certificates"))
            .and(body_json(
                json!({ "filters": [], "itemsPerPage": 50, "pageNumber": 1 }),
            ))
            .respond_with(response)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let response = Search::page(1, None)
            .request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();
        read_page(response).await
    }

    #[tokio::test]
    async fn a_page_is_read_and_broken_items_are_skipped() {
        let body = json!({
            "certificates": [full(), { "displayName": "no uuid" }, "junk"],
            "itemsPerPage": 50, "pageNumber": 1, "totalPages": 7, "totalItems": 321
        });
        let page = answer(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap();
        assert_eq!(page.certificates.len(), 1);
        assert_eq!(
            (page.page_number, page.total_pages, page.total_items),
            (1, 7, 321)
        );
        assert_eq!(page.skipped, 2);
    }

    #[tokio::test]
    async fn failures_are_told_apart() {
        assert_eq!(
            answer(ResponseTemplate::new(401)).await.unwrap_err(),
            IlmError::Unauthorized
        );
        assert_eq!(
            answer(ResponseTemplate::new(403)).await.unwrap_err(),
            IlmError::Unexpected(403)
        );
        assert_eq!(
            answer(ResponseTemplate::new(200).set_body_string("nope"))
                .await
                .unwrap_err(),
            IlmError::Malformed
        );
    }
}
