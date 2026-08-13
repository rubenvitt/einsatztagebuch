use std::{collections::BTreeSet, fs, process::Command};
use toml::Value;

#[test]
fn workspace_declares_exact_planned_members_and_shared_dependencies() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(root.join("Cargo.lock").is_file());
    assert!(root.join("pnpm-lock.yaml").is_file());
    let root_manifest: Value = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let member_array = root_manifest["workspace"]["members"].as_array().unwrap();
    assert_eq!(
        member_array.len(),
        3,
        "workspace members must not be duplicated or omitted"
    );
    let members = member_array
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        members,
        BTreeSet::from(["tools/xtask", "tests/ea-system-tests", "crates/ea-types"])
    );
    let workspace_dependencies = root_manifest["workspace"]["dependencies"]
        .as_table()
        .unwrap();
    assert!(
        !workspace_dependencies.is_empty(),
        "workspace.dependencies must contain shared dependencies"
    );
    for member in ["tools/xtask", "tests/ea-system-tests", "crates/ea-types"] {
        let manifest: Value = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let mut member_dependency_references = 0;
        for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(dependencies) = manifest.get(table_name).and_then(Value::as_table) {
                for (name, dependency) in dependencies {
                    member_dependency_references += 1;
                    assert!(
                        workspace_dependencies.contains_key(name),
                        "{member} {table_name} dependency {name} is not shared at workspace scope"
                    );
                    assert_eq!(
                        dependency
                            .as_table()
                            .and_then(|spec| spec.get("workspace"))
                            .and_then(Value::as_bool),
                        Some(true),
                        "{member} {table_name} dependency {name} must use workspace = true"
                    );
                }
            }
        }
        if member != "crates/ea-types" {
            assert!(
                member_dependency_references > 0,
                "{member} must reference at least one shared workspace dependency"
            );
        }
    }
    assert!(
        Command::new("cargo")
            .args(["metadata", "--locked", "--no-deps"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
}
