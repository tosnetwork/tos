use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tos_health_core::edge_snapshot::EdgeCapabilities;
use tos_health_services::edge::{sample_cgroup, CgroupConfig, EdgeState};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tos-health-cgroup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn write(&self, relative: &str, value: &str) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn leaf_files(tree: &Tree, memory_current: u64) {
    tree.write("parent/leaf/memory.current", &format!("{memory_current}\n"));
    tree.write("parent/leaf/cpu.stat", "usage_usec 17\nuser_usec 9\nsystem_usec 8\n");
    tree.write("parent/leaf/memory.events", "low 0\nhigh 0\nmax 1\noom 2\noom_kill 0\n");
}

#[test]
fn effective_quota_uses_tightest_ancestor_and_keeps_pressure_sample() {
    let tree = Tree::new();
    tree.write("cgroup.controllers", "cpu memory\n");
    tree.write("parent/memory.max", "4294967296\n");
    tree.write("parent/cpu.max", "100000 100000\n");
    tree.write("parent/leaf/memory.max", "8589934592\n");
    tree.write("parent/leaf/cpu.max", "150000 100000\n");
    // Limit lowering/reclaim can leave current above the effective maximum.
    leaf_files(&tree, 5_000_000_000);
    let config = CgroupConfig::new(tree.0.clone(), PathBuf::from("parent/leaf")).unwrap();
    let value = sample_cgroup("v1", "boot:1:1", "edge-1", 1, &config).unwrap();
    assert_eq!(value.payload.memory_current_bytes.0, 5_000_000_000);
    assert_eq!(value.payload.memory_max_bytes.0, 4_294_967_296);
    assert_eq!(value.payload.cpu_quota_usec.0, 100_000);
    assert_eq!(value.payload.cpu_period_usec.0, 100_000);
}

#[test]
fn unlimited_parent_and_finite_child_resolve_to_child() {
    let tree = Tree::new();
    tree.write("cgroup.controllers", "cpu memory\n");
    tree.write("parent/memory.max", "max\n");
    tree.write("parent/cpu.max", "max 100000\n");
    tree.write("parent/leaf/memory.max", "1073741824\n");
    tree.write("parent/leaf/cpu.max", "25000 50000\n");
    leaf_files(&tree, 900_000_000);
    let config = CgroupConfig::new(tree.0.clone(), PathBuf::from("parent/leaf")).unwrap();
    let value = sample_cgroup("v1", "boot:1:1", "edge-1", 1, &config).unwrap();
    assert_eq!(value.payload.memory_max_bytes.0, 1_073_741_824);
    assert_eq!(value.payload.cpu_quota_usec.0, 25_000);
    assert_eq!(value.payload.cpu_period_usec.0, 50_000);
}

async fn cgroup_status(state: EdgeState) -> String {
    let response = tos_health_services::edge::router(state)
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/edge/capabilities")
                .header("authorization", format!("Bearer {}", "e".repeat(32)))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 32_768).await.unwrap();
    let value: EdgeCapabilities = serde_json::from_slice(&body).unwrap();
    value.validate("v1").unwrap();
    value.sources.into_iter().find(|source| source.source_id == "host_cgroup").unwrap().status
}

#[tokio::test]
async fn discovery_keeps_unsupported_and_invalid_profiles_distinct() {
    let tree = Tree::new();
    let proc_root = tree.0.join("proc");
    fs::create_dir_all(proc_root.join("42")).unwrap();
    fs::write(proc_root.join("42/cgroup"), "1:cpu:/legacy\n").unwrap();
    let unsupported = CgroupConfig::discover_from(&proc_root, tree.0.join("cg"), 42).unwrap_err();
    assert!(unsupported.contains("cgroup v2 unavailable"));

    fs::write(proc_root.join("42/cgroup"), "0::/node\n").unwrap();
    fs::create_dir_all(tree.0.join("cg/node")).unwrap();
    fs::write(tree.0.join("cg/cgroup.controllers"), "cpu memory\n").unwrap();
    fs::write(tree.0.join("cg/node/memory.max"), "max\n").unwrap();
    fs::write(tree.0.join("cg/node/cpu.max"), "max 100000\n").unwrap();
    let invalid = CgroupConfig::discover_from(&proc_root, tree.0.join("cg"), 42).unwrap_err();
    assert!(invalid.contains("effective memory quota unavailable"));

    let unsupported_state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    unsupported_state.record_cgroup_discovery_error(&unsupported).unwrap();
    let invalid_state = EdgeState::new("v1".into(), vec![b'e'; 32]);
    invalid_state.record_cgroup_discovery_error(&invalid).unwrap();
    assert_eq!(cgroup_status(unsupported_state).await, "unsupported");
    assert_eq!(cgroup_status(invalid_state).await, "error");
}

#[cfg(unix)]
#[test]
fn descendant_quota_symlink_and_zero_are_refused() {
    use std::os::unix::fs::symlink;
    let tree = Tree::new();
    tree.write("cgroup.controllers", "cpu memory\n");
    tree.write("outside", "100000 100000\n");
    tree.write("node/memory.max", "1024\n");
    symlink(tree.0.join("outside"), tree.0.join("node/cpu.max")).unwrap();
    let config = CgroupConfig::new(tree.0.clone(), PathBuf::from("node")).unwrap();
    assert!(sample_cgroup("v1", "boot:1:1", "edge-1", 1, &config)
        .unwrap_err()
        .contains("fixed regular file"));
    fs::remove_file(tree.0.join("node/cpu.max")).unwrap();
    tree.write("node/cpu.max", "0 100000\n");
    assert!(sample_cgroup("v1", "boot:1:1", "edge-1", 1, &config)
        .unwrap_err()
        .contains("invalid CPU quota"));
}
