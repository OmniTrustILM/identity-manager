//! The Group Policy template declares exactly the policies the reader knows.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use im_core::policy::{Kind, POLICIES, PolicyValue, RawMap, to_layer};
use im_core::settings::Layer;
use roxmltree::{Document, Node};

const KEY: &str = r"Software\Policies\OmniTrustILM\IdentityManager";

fn template(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows");
    fs::read_to_string(path.join(file)).unwrap_or_else(|error| panic!("{file}: {error}"))
}

fn elements<'a, 'i>(node: Node<'a, 'i>, tag: &str) -> Vec<Node<'a, 'i>> {
    node.children()
        .filter(|child| child.is_element() && child.tag_name().name() == tag)
        .collect()
}

fn only<'a, 'i>(node: Node<'a, 'i>, tag: &str) -> Node<'a, 'i> {
    let found = elements(node, tag);
    assert_eq!(found.len(), 1, "expected one <{tag}> in {node:?}");
    found[0]
}

fn attribute<'a>(node: Node<'a, '_>, name: &str) -> &'a str {
    node.attribute(name)
        .unwrap_or_else(|| panic!("{node:?} has no {name}"))
}

/// The `$(prefix.id)` references among the attributes of every element below `root`.
fn references(root: Node, prefix: &str) -> BTreeSet<String> {
    let start = format!("$({prefix}.");
    root.descendants()
        .flat_map(|node| node.attributes())
        .filter_map(|attribute| attribute.value().strip_prefix(&start))
        .map(|rest| rest.trim_end_matches(')').to_string())
        .collect()
}

/// The ids of the elements `parent` holds, by the attribute that names each.
fn ids(parent: Node, tag: &str, attribute_name: &str) -> BTreeSet<String> {
    elements(parent, tag)
        .into_iter()
        .map(|node| attribute(node, attribute_name).to_string())
        .collect()
}

fn accepted(name: &str, value: PolicyValue) -> bool {
    let raw = RawMap::from([(name.to_string(), value)]);
    to_layer(&raw, "test") != Layer::default()
}

#[test]
fn the_reader_accepts_what_the_table_declares() {
    for (name, kind) in POLICIES {
        match kind {
            Kind::Bool => assert!(accepted(name, PolicyValue::Bool(true)), "{name}"),
            Kind::Int { min, max } => {
                assert!(accepted(name, PolicyValue::Int(min)), "{name} min");
                assert!(accepted(name, PolicyValue::Int(max)), "{name} max");
                assert!(!accepted(name, PolicyValue::Int(min - 1)), "{name} below");
                assert!(!accepted(name, PolicyValue::Int(max + 1)), "{name} above");
            }
            Kind::Text => {
                let text = PolicyValue::Text("https://ilm.example.com".into());
                assert!(accepted(name, text), "{name}");
            }
            Kind::Choice(values) => {
                for value in values {
                    assert!(
                        accepted(name, PolicyValue::Text(value.to_string())),
                        "{name} {value}"
                    );
                }
                assert!(
                    !accepted(name, PolicyValue::Text("unlisted".into())),
                    "{name}"
                );
            }
        }
    }
}

/// Every field of the layer is set by a policy, except the certificate the person last signed in with.
#[test]
fn every_policy_of_the_table_reaches_the_layer() {
    let raw: RawMap = POLICIES
        .iter()
        .map(|(name, kind)| {
            let value = match kind {
                Kind::Bool => PolicyValue::Bool(true),
                Kind::Int { min, .. } => PolicyValue::Int(*min),
                Kind::Text => PolicyValue::Text("https://ilm.example.com".into()),
                Kind::Choice(values) => PolicyValue::Text(values[0].to_string()),
            };
            (name.to_string(), value)
        })
        .collect();
    let Layer {
        start_at_login,
        automatic_updates,
        log_level,
        ilm_url,
        require_unlock,
        lock_after_idle,
        check_every,
        warn_days,
        automatic_renewal,
        sign_in_provider,
        sign_in_method,
        key_storages,
        default_key_storage,
        complete_prepared,
        request_profiles,
        sign_in_certificate_profile,
        sign_in_certificate,
    } = to_layer(&raw, "test");
    assert!(
        sign_in_certificate.is_none(),
        "only the person's layer holds it"
    );
    let set = [
        ("StartAtLogin", start_at_login.is_some()),
        ("AutomaticUpdates", automatic_updates.is_some()),
        ("LogLevel", log_level.is_some()),
        ("IlmUrl", ilm_url.is_some()),
        ("RequireUnlock", require_unlock.is_some()),
        ("LockAfterIdle", lock_after_idle.is_some()),
        ("CheckInterval", check_every.is_some()),
        ("ExpiryWarningDays", warn_days.is_some()),
        ("AutomaticRenewal", automatic_renewal.is_some()),
        ("SignInProvider", sign_in_provider.is_some()),
        ("SignInMethod", sign_in_method.is_some()),
        ("KeyStorages", key_storages.is_some()),
        ("DefaultKeyStorage", default_key_storage.is_some()),
        ("CompletePrepared", complete_prepared.is_some()),
        ("RequestProfiles", request_profiles.is_some()),
        (
            "SignInCertificateProfile",
            sign_in_certificate_profile.is_some(),
        ),
    ];
    let unset: Vec<_> = set
        .iter()
        .filter(|(_, set)| !set)
        .map(|(name, _)| name)
        .collect();
    assert!(unset.is_empty(), "the reader ignores {unset:?}");
    assert_eq!(
        set.len(),
        POLICIES.len(),
        "a layer field has no policy in the table"
    );
}

#[test]
fn the_template_declares_the_policies_of_the_reader() {
    let text = template("IdentityManager.admx");
    let admx = Document::parse(&text).unwrap();
    let policies = only(admx.root_element(), "policies");
    let declared = elements(policies, "policy");

    let names: Vec<_> = declared
        .iter()
        .map(|policy| attribute(*policy, "name"))
        .collect();
    let known: Vec<_> = POLICIES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names.iter().collect::<BTreeSet<_>>(),
        known.iter().collect::<BTreeSet<_>>(),
        "the template and the reader know different policies"
    );
    assert_eq!(names.len(), known.len(), "a policy is declared twice");

    for policy in declared {
        let name = attribute(policy, "name");
        let kind = POLICIES.iter().find(|(known, _)| *known == name).unwrap().1;
        assert_eq!(attribute(policy, "class"), "Both", "{name}");
        assert_eq!(attribute(policy, "key"), KEY, "{name}");
        check_kind(policy, name, kind);
    }
}

fn check_kind(policy: Node, name: &str, kind: Kind) {
    assert!(
        elements(policy, "enabledList").is_empty() && elements(policy, "disabledList").is_empty(),
        "{name} writes values elsewhere"
    );
    if kind == Kind::Bool {
        assert_eq!(attribute(policy, "valueName"), name, "{name}");
        let on = only(only(policy, "enabledValue"), "decimal");
        let off = only(only(policy, "disabledValue"), "decimal");
        assert_eq!(attribute(on, "value"), "1", "{name} on");
        assert_eq!(attribute(off, "value"), "0", "{name} off");
        assert!(elements(policy, "elements").is_empty(), "{name}");
        return;
    }
    assert!(policy.attribute("valueName").is_none(), "{name}");
    let mut children = only(policy, "elements").children().filter(Node::is_element);
    let element = children
        .next()
        .unwrap_or_else(|| panic!("{name} has no element"));
    assert!(
        children.next().is_none(),
        "{name} has more than one element"
    );
    assert_eq!(attribute(element, "id"), name);
    assert_eq!(attribute(element, "valueName"), name);
    assert_eq!(attribute(element, "required"), "true", "{name}");
    assert!(
        element.attribute("key").is_none(),
        "{name} writes elsewhere"
    );
    assert!(
        matches!(element.attribute("storeAsText"), None | Some("false" | "0")),
        "{name} is stored as text"
    );
    let tag = element.tag_name().name();
    match kind {
        Kind::Int { min, max } => {
            assert_eq!(tag, "decimal", "{name}");
            assert_eq!(attribute(element, "minValue"), min.to_string(), "{name}");
            assert_eq!(attribute(element, "maxValue"), max.to_string(), "{name}");
        }
        Kind::Text => assert_eq!(tag, "text", "{name}"),
        Kind::Choice(values) => {
            assert_eq!(tag, "enum", "{name}");
            let items: Vec<_> = elements(element, "item")
                .into_iter()
                .map(|item| {
                    only(only(item, "value"), "string")
                        .text()
                        .unwrap_or_default()
                })
                .collect();
            assert_eq!(items, values, "{name}");
        }
        Kind::Bool => unreachable!(),
    }
}

#[test]
fn every_reference_of_the_template_resolves() {
    let admx_text = template("IdentityManager.admx");
    let adml_text = template("en-US/IdentityManager.adml");
    let admx = Document::parse(&admx_text).unwrap();
    let adml = Document::parse(&adml_text).unwrap();
    let root = admx.root_element();
    let resources = only(adml.root_element(), "resources");

    let strings = ids(only(resources, "stringTable"), "string", "id");
    let missing: Vec<_> = references(root, "string")
        .difference(&strings)
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "strings missing from the ADML: {missing:?}"
    );

    let presentations = only(resources, "presentationTable");
    let missing: Vec<_> = references(root, "presentation")
        .difference(&ids(presentations, "presentation", "id"))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "presentations missing from the ADML: {missing:?}"
    );

    let categories = ids(only(root, "categories"), "category", "name");
    for policy in elements(only(root, "policies"), "policy") {
        let name = attribute(policy, "name");
        let parent = attribute(only(policy, "parentCategory"), "ref");
        assert!(
            categories.contains(parent),
            "{name}: unknown category {parent}"
        );
        check_presentation(policy, presentations);
    }
}

/// A policy with elements has a presentation that shows each of them, and no other.
fn check_presentation(policy: Node, presentations: Node) {
    let name = attribute(policy, "name");
    let Some(elements_node) = elements(policy, "elements").first().copied() else {
        assert!(policy.attribute("presentation").is_none(), "{name}");
        return;
    };
    let id = attribute(policy, "presentation")
        .strip_prefix("$(presentation.")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("{name}: presentation is not a reference"));
    let presentation = elements(presentations, "presentation")
        .into_iter()
        .find(|node| attribute(*node, "id") == id)
        .unwrap_or_else(|| panic!("{name}: no presentation {id}"));
    let shown: BTreeSet<_> = presentation
        .children()
        .filter(Node::is_element)
        .map(|node| attribute(node, "refId").to_string())
        .collect();
    let declared: BTreeSet<_> = elements_node
        .children()
        .filter(Node::is_element)
        .map(|node| attribute(node, "id").to_string())
        .collect();
    assert_eq!(shown, declared, "{name}: presentation and elements differ");
}
