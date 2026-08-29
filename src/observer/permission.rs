//! Classifies a Host's family and the permission grant it gave Beacon at
//! pairing time, from its `/serverinfo` XML.
//!
//! Contract (proposed to `HostImplementation` for `Jochona/jochona-host`,
//! see IRC log — this module implements the fallback the message spelled
//! out so Beacon has correct, non-stub behavior regardless of which side
//! lands first):
//!
//! - A top-level `<jochona_family>1</jochona_family>` tag identifies a
//!   Jochona Host. Its absence means the Host is stock Sunshine or Apollo.
//! - If a `<jochona_permission>` tag is present (Jochona Host only), its
//!   text is matched against the known observer-only token; anything else
//!   (including an unrecognized future value) is treated conservatively as
//!   broad permission rather than silently trusted.
//! - Absent a `<jochona_family>` tag entirely (stock Sunshine/Apollo has no
//!   narrower grant to offer), Beacon always records
//!   `BroadPermissionWarning` — this is surfaced explicitly to the
//!   operator at enrollment time, never silently accepted as
//!   observer-only.

use crate::domain::{HostFamily, ObserverPermission};

const OBSERVER_ONLY_TOKEN: &str = "observer_only";

pub struct Classification {
    pub host_family: HostFamily,
    pub observer_permission: ObserverPermission,
}

pub fn classify(serverinfo_xml: &str) -> anyhow::Result<Classification> {
    let doc = roxmltree::Document::parse(serverinfo_xml)?;
    let root = doc.root_element();

    let is_jochona = root
        .descendants()
        .any(|n| n.has_tag_name("jochona_family") && n.text() == Some("1"));

    if !is_jochona {
        // We cannot distinguish stock Sunshine from Apollo purely from
        // /serverinfo without a Host-specific tag either project may or may
        // not emit; both are treated identically for the warning (the
        // contract only requires *a* warning, not which non-Jochona fork it
        // is). GfeVersion/state text hints at Apollo vs vanilla Sunshine
        // builds but is not reliable enough to assert on.
        let is_apollo_like = root.descendants().any(|n| {
            n.has_tag_name("gfeversion")
                && n.text()
                    .map(|t| t.to_ascii_lowercase().contains("apollo"))
                    .unwrap_or(false)
        });
        return Ok(Classification {
            host_family: if is_apollo_like {
                HostFamily::Apollo
            } else {
                HostFamily::Sunshine
            },
            observer_permission: ObserverPermission::BroadPermissionWarning,
        });
    }

    let permission = root
        .descendants()
        .find(|n| n.has_tag_name("jochona_permission"))
        .and_then(|n| n.text())
        .unwrap_or("");

    Ok(Classification {
        host_family: HostFamily::Jochona,
        observer_permission: if permission == OBSERVER_ONLY_TOKEN {
            ObserverPermission::ObserverOnly
        } else {
            ObserverPermission::BroadPermissionWarning
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jochona_host_with_observer_only_permission_is_classified_correctly() {
        let xml = r#"<root status_code="200"><jochona_family>1</jochona_family><jochona_permission>observer_only</jochona_permission></root>"#;
        let c = classify(xml).unwrap();
        assert_eq!(c.host_family, HostFamily::Jochona);
        assert_eq!(c.observer_permission, ObserverPermission::ObserverOnly);
    }

    #[test]
    fn jochona_host_with_broad_permission_is_flagged() {
        let xml = r#"<root status_code="200"><jochona_family>1</jochona_family><jochona_permission>full_control</jochona_permission></root>"#;
        let c = classify(xml).unwrap();
        assert_eq!(c.host_family, HostFamily::Jochona);
        assert_eq!(
            c.observer_permission,
            ObserverPermission::BroadPermissionWarning
        );
    }

    #[test]
    fn non_jochona_host_always_warns() {
        let xml = r#"<root status_code="200"><hostname>my-pc</hostname></root>"#;
        let c = classify(xml).unwrap();
        assert_ne!(c.host_family, HostFamily::Jochona);
        assert_eq!(
            c.observer_permission,
            ObserverPermission::BroadPermissionWarning
        );
    }
}
