use std::collections::HashSet;

use xenia_peer_core::{M1DataDirection, M1Permission};

const ROUTE_INVENTORY: &str =
    include_str!("../../../docs/security/M1_ROUTE_INVENTORY_V0_1.toml");

#[test]
fn route_inventory_is_complete_for_the_declared_eight_lane_census() {
    let manifest: toml::Value =
        toml::from_str(ROUTE_INVENTORY).expect("M1 route inventory must be valid TOML");

    assert_eq!(
        manifest.get("schema").and_then(toml::Value::as_str),
        Some("xenia-m1-route-inventory-v1")
    );
    assert_eq!(
        manifest.get("version").and_then(toml::Value::as_integer),
        Some(1)
    );
    assert_eq!(
        manifest.get("status").and_then(toml::Value::as_str),
        Some("partial_source_census")
    );

    let reviewed_commit = manifest
        .get("reviewed_commit")
        .and_then(toml::Value::as_str)
        .expect("reviewed_commit is required");
    assert!(is_git_sha(reviewed_commit), "reviewed_commit must be a full Git SHA");

    let source_files = manifest
        .get("source_files")
        .and_then(toml::Value::as_table)
        .expect("source_files table is required");
    assert!(!source_files.is_empty());
    for (name, value) in source_files {
        let source_ref = value
            .as_str()
            .unwrap_or_else(|| panic!("source_files.{name} must be a string"));
        let (path, sha) = source_ref
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("source_files.{name} must be path@sha"));
        assert!(!path.is_empty(), "source_files.{name} path must not be empty");
        assert!(is_git_sha(sha), "source_files.{name} must use a full Git SHA");
    }

    let routes = manifest
        .get("routes")
        .and_then(toml::Value::as_array)
        .expect("routes array is required");
    assert_eq!(
        routes.len(),
        M1Permission::ALL.len(),
        "every M1 lane must have exactly one route"
    );

    let mut route_ids = HashSet::new();
    let mut action_ids = HashSet::new();
    let mut permission_names = HashSet::new();

    for permission in M1Permission::ALL {
        let permission_name = format!("{permission:?}");
        assert!(
            permission_names.insert(permission_name.clone()),
            "M1 permission names must be unique"
        );

        let route = routes
            .iter()
            .find(|route| {
                route.get("permission").and_then(toml::Value::as_str)
                    == Some(permission_name.as_str())
            })
            .unwrap_or_else(|| panic!("missing route for M1 permission {permission_name}"));

        let required_fields = [
            "id",
            "effect",
            "entrypoint",
            "source_api",
            "direction",
            "permission",
            "action_id",
            "resource",
            "source_preflight",
            "final_gate",
            "effect_owner",
            "transport_boundary",
            "coverage",
            "negative_bypass_controls",
            "maximum_evidence_claim",
        ];
        for field in required_fields {
            let value = route
                .get(field)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("route for {permission_name} is missing {field}"));
            assert!(
                !value.trim().is_empty(),
                "route for {permission_name} has an empty {field}"
            );
        }

        let id = route["id"].as_str().unwrap();
        assert!(route_ids.insert(id), "duplicate M1 route ID: {id}");

        let action_id = route["action_id"].as_str().unwrap();
        assert_eq!(
            action_id,
            permission.action_id(),
            "route action ID drifted for {permission_name}"
        );
        assert!(
            action_ids.insert(action_id),
            "duplicate M1 action ID: {action_id}"
        );

        let expected_direction = match permission.direction() {
            M1DataDirection::HostToViewer => "host_to_viewer",
            M1DataDirection::ViewerToHost => "viewer_to_host",
        };
        assert_eq!(
            route["direction"].as_str(),
            Some(expected_direction),
            "route direction drifted for {permission_name}"
        );

        assert_eq!(
            route["coverage"].as_str(),
            Some("source_reviewed"),
            "route coverage must remain explicitly source_reviewed"
        );
    }

    let unknown_routes = manifest
        .get("unknown_routes")
        .and_then(toml::Value::as_array)
        .expect("unknown_routes array is required");
    for route in unknown_routes {
        for field in ["id", "status", "description"] {
            let value = route
                .get(field)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("unknown route is missing {field}"));
            assert!(!value.trim().is_empty());
        }
    }

    let has_unimplemented_bypass_control = routes.iter().any(|route| {
        route
            .get("negative_bypass_controls")
            .and_then(toml::Value::as_str)
            == Some("not_yet_implemented")
    });
    if !unknown_routes.is_empty() || has_unimplemented_bypass_control {
        assert_eq!(
            manifest.get("completeness").and_then(toml::Value::as_str),
            Some("indeterminate"),
            "unknown routes or unimplemented bypass controls must prevent a complete claim"
        );
        let qualification = manifest
            .get("qualification")
            .and_then(toml::Value::as_array)
            .and_then(|entries| entries.first())
            .expect("qualification record is required");
        assert_eq!(
            qualification.get("result").and_then(toml::Value::as_str),
            Some("INDETERMINATE"),
            "incomplete route evidence must remain INDETERMINATE"
        );
    }
}

fn is_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
