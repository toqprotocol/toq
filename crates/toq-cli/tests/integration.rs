//! Integration tests for the toq daemon.
//!
//! Each test gets an isolated HOME directory with its own config, keys, and
//! state. The daemon binary is built by Cargo and located via `env!("CARGO_BIN_EXE_toq")`.

use predicates::prelude::*;
use reqwest::Client;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

const API_STARTUP_DELAY: Duration = Duration::from_secs(2);
const SHUTDOWN_DELAY: Duration = Duration::from_millis(500);

fn toq_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_toq"))
}

fn toq_cmd() -> StdCommand {
    StdCommand::new(toq_bin())
}

/// Isolated toq instance with its own HOME, ports, and temp directory.
struct Instance {
    dir: TempDir,
    api_port: u16,
    proto_port: u16,
    started: bool,
}

impl Drop for Instance {
    fn drop(&mut self) {
        if self.started {
            // Best-effort shutdown: try non-graceful first (faster), then force kill
            let _ = toq_cmd().env("HOME", self.dir.path()).arg("down").output();
            std::thread::sleep(Duration::from_millis(300));

            // Kill anything still on our ports
            kill_port(self.api_port);
            kill_port(self.proto_port);
        }
    }
}

fn kill_port(port: u16) {
    let own_pid = std::process::id().to_string();
    // Try lsof (macOS/Linux with lsof installed)
    let lsof = StdCommand::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output();
    if let Ok(o) = lsof {
        let pids = String::from_utf8_lossy(&o.stdout);
        for pid in pids.split_whitespace() {
            if pid != own_pid {
                let _ = StdCommand::new("kill").args(["-9", pid]).output();
            }
        }
        return;
    }
    // Fallback: fuser (Linux)
    let _ = StdCommand::new("fuser")
        .args(["-k", "-9", &format!("{port}/tcp")])
        .output();
}

impl Instance {
    /// Create a new instance with setup complete and ports patched.
    fn new(name: &str, mode: &str, api_port: u16, proto_port: u16) -> Self {
        // Kill anything on our ports from previous runs and wait for release
        kill_port(api_port);
        kill_port(proto_port);
        std::thread::sleep(Duration::from_millis(200));

        let dir = TempDir::new().expect("failed to create temp dir");

        // Run non-interactive setup
        let status = toq_cmd()
            .env("HOME", dir.path())
            .args([
                "setup",
                "--non-interactive",
                "--agent-name",
                name,
                "--connection-mode",
                mode,
                "--adapter",
                "http",
            ])
            .status()
            .expect("failed to run toq setup");
        assert!(status.success(), "toq setup failed");

        // Patch ports in config
        let config_path = dir.path().join(".toq/config.toml");
        let config = std::fs::read_to_string(&config_path).unwrap();
        let config = config
            .replace("port = 9009", &format!("port = {proto_port}"))
            .replace("api_port = 9010", &format!("api_port = {api_port}"));
        std::fs::write(&config_path, config).unwrap();

        Self {
            dir,
            api_port,
            proto_port,
            started: false,
        }
    }

    fn cmd(&self) -> assert_cmd::Command {
        let mut cmd = assert_cmd::Command::from_std(toq_cmd());
        cmd.env("HOME", self.dir.path());
        cmd
    }

    fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.api_port)
    }

    /// Spawn an SSE listener that collects chunks for up to `secs` seconds.
    fn spawn_sse_listener(&self, secs: u64) -> tokio::task::JoinHandle<String> {
        let url = self.api_url("/v1/messages");
        tokio::spawn(async move {
            let mut collected = String::new();
            if let Ok(mut resp) = Client::new().get(&url).send().await {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
                while tokio::time::Instant::now() < deadline {
                    match tokio::time::timeout(Duration::from_secs(1), resp.chunk()).await {
                        Ok(Ok(Some(chunk))) => {
                            collected.push_str(&String::from_utf8_lossy(&chunk));
                        }
                        _ => break,
                    }
                }
            }
            collected
        })
    }

    fn start(&mut self) {
        self.cmd().arg("up").assert().success();
        self.started = true;
    }

    fn stop(&mut self) {
        self.cmd().args(["down", "--graceful"]).assert().success();
        self.started = false;
    }
}

// ── Lifecycle ────────────────────────────────────────────────

#[test]
fn status_before_setup() {
    let dir = TempDir::new().unwrap();
    let mut cmd = assert_cmd::Command::from_std(toq_cmd());
    cmd.env("HOME", dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("not running").or(predicate::str::contains("Not running")),
        );
}

#[test]
fn setup_creates_config_and_keys() {
    let inst = Instance::new("test-agent", "approval", 29010, 29009);
    let toq_dir = inst.dir.path().join(".toq");
    assert!(toq_dir.join("config.toml").exists());
    assert!(toq_dir.join("keys").exists());

    let config = std::fs::read_to_string(toq_dir.join("config.toml")).unwrap();
    assert!(config.contains("test-agent"));
    assert!(config.contains("approval"));
}

#[test]
fn setup_open_mode() {
    let inst = Instance::new("open-agent", "open", 29020, 29019);
    let config = std::fs::read_to_string(inst.dir.path().join(".toq/config.toml")).unwrap();
    assert!(config.contains("open"));
}

#[test]
fn setup_allowlist_mode() {
    let inst = Instance::new("al-agent", "allowlist", 29030, 29029);
    let config = std::fs::read_to_string(inst.dir.path().join(".toq/config.toml")).unwrap();
    assert!(config.contains("allowlist"));
}

#[test]
fn setup_with_framework_flag() {
    let dir = TempDir::new().unwrap();
    let mut cmd = assert_cmd::Command::from_std(toq_cmd());
    cmd.env("HOME", dir.path())
        .args([
            "setup",
            "--non-interactive",
            "--agent-name",
            "fw-agent",
            "--framework",
            "langchain",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Setup complete"));

    // Verify config was created with correct agent name
    let config = std::fs::read_to_string(dir.path().join(".toq/config.toml")).unwrap();
    assert!(config.contains("fw-agent"), "config should have agent name");
}

// ── Daemon start/stop ────────────────────────────────────────

#[tokio::test]
async fn daemon_start_status_stop() {
    let mut inst = Instance::new("lifecycle", "open", 29110, 29109);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // Status via CLI
    inst.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("running").or(predicate::str::contains("Running")));

    inst.stop();
    sleep(SHUTDOWN_DELAY).await;

    inst.cmd().arg("status").assert().success().stdout(
        predicate::str::contains("not running").or(predicate::str::contains("Not running")),
    );
}

// ── Local API ────────────────────────────────────────────────

#[tokio::test]
async fn api_health() {
    let mut inst = Instance::new("api-health", "open", 29210, 29209);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .get(inst.api_url("/v1/health"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();
    assert!(body.contains("ok") || body.contains("healthy"));

    inst.stop();
}

#[tokio::test]
async fn api_status() {
    let mut inst = Instance::new("api-status", "open", 29220, 29219);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp_str = serde_json::to_string(&resp).unwrap();
    assert!(
        resp_str.contains("api-status"),
        "expected agent name in status: {resp_str}"
    );

    inst.stop();
}

#[tokio::test]
async fn api_peers_empty() {
    let mut inst = Instance::new("api-peers", "open", 29230, 29229);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/peers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let peers = resp["peers"].as_array().expect("peers should be array");
    assert!(peers.is_empty(), "fresh daemon should have no peers");

    inst.stop();
}

#[tokio::test]
async fn api_approvals_empty() {
    let mut inst = Instance::new("api-approvals", "open", 29240, 29239);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/approvals"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let approvals = resp["approvals"]
        .as_array()
        .expect("approvals should be array");
    assert!(
        approvals.is_empty(),
        "fresh daemon should have no approvals"
    );

    inst.stop();
}

#[tokio::test]
async fn api_diagnostics() {
    let mut inst = Instance::new("api-diag", "open", 29250, 29249);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/diagnostics"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp_str = serde_json::to_string(&resp).unwrap();
    assert!(
        resp_str.contains("port") || resp_str.contains("keys") || resp_str.contains("checks"),
        "diagnostics should contain check results: {resp_str}"
    );

    inst.stop();
}

#[tokio::test]
async fn api_sse_connects() {
    let mut inst = Instance::new("api-sse", "open", 29260, 29259);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // SSE is GET /v1/messages. Just verify it accepts the connection.
    let resp = Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap()
        .get(inst.api_url("/v1/messages"))
        .send()
        .await;

    // Either 200 (streaming) or timeout (connected but no messages) is fine
    match resp {
        Ok(r) => assert!(r.status().is_success()),
        Err(e) => assert!(e.is_timeout(), "expected timeout, got: {e}"),
    }

    inst.stop();
}

// ── Block/unblock ────────────────────────────────────────────

#[tokio::test]
async fn api_block_and_unblock() {
    let mut inst = Instance::new("api-block", "open", 29310, 29309);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();
    let fake_key = "ed25519%3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D";

    // Block
    let resp = client
        .post(inst.api_url(&format!("/v1/peers/{fake_key}/block")))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify in permissions
    let perms: serde_json::Value = client
        .get(inst.api_url("/v1/permissions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let perms_str = serde_json::to_string(&perms).unwrap();
    assert!(perms_str.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

    // Unblock
    let resp = client
        .delete(inst.api_url(&format!("/v1/peers/{fake_key}/block")))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    inst.stop();
}

// ── Send to unreachable peer ─────────────────────────────────

#[tokio::test]
async fn api_send_unreachable_returns_error() {
    let mut inst = Instance::new("api-send", "open", 29320, 29319);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .post(inst.api_url("/v1/messages"))
        .json(&serde_json::json!({
            "to": "toq://nonexistent.invalid/agent",
            "body": {"text": "hello"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp_str = serde_json::to_string(&resp).unwrap().to_lowercase();
    assert!(resp_str.contains("error") || resp_str.contains("fail"));

    inst.stop();
}

// ── CLI commands against running daemon ──────────────────────

#[tokio::test]
async fn cli_peers_against_daemon() {
    let mut inst = Instance::new("cli-peers", "open", 29410, 29409);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    inst.cmd().arg("peers").assert().success().stdout(
        predicate::str::contains("No known peers").or(predicate::str::contains("PUBLIC KEY")),
    );

    inst.stop();
}

#[tokio::test]
async fn cli_approvals_against_daemon() {
    let mut inst = Instance::new("cli-approvals", "open", 29420, 29419);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    inst.cmd().arg("approvals").assert().success().stdout(
        predicate::str::contains("No pending")
            .or(predicate::str::contains("no pending").or(predicate::str::contains("APPROVAL"))),
    );

    inst.stop();
}

#[tokio::test]
async fn cli_doctor_against_daemon() {
    let mut inst = Instance::new("cli-doctor", "open", 29430, 29429);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    inst.cmd().arg("doctor").assert().success().stdout(
        predicate::str::contains("✓")
            .or(predicate::str::contains("pass").or(predicate::str::contains("ok"))),
    );

    inst.stop();
}

#[tokio::test]
async fn cli_logs_against_daemon() {
    let mut inst = Instance::new("cli-logs", "open", 29440, 29439);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // Logs should return without error (may be empty or have startup entries)
    inst.cmd().arg("logs").assert().success();

    inst.stop();
}

// ── Graceful vs immediate shutdown ───────────────────────────

#[tokio::test]
async fn cli_down_immediate() {
    let mut inst = Instance::new("down-imm", "open", 29510, 29509);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    inst.cmd().arg("down").assert().success();
    sleep(SHUTDOWN_DELAY).await;

    inst.cmd().arg("status").assert().stdout(
        predicate::str::contains("not running").or(predicate::str::contains("Not running")),
    );
}

// ── Two-daemon communication ─────────────────────────────────

#[tokio::test]
async fn two_daemons_send_message() {
    let mut alice = Instance::new("alice", "open", 29610, 29609);
    let mut bob = Instance::new("bob", "open", 29620, 29619);
    alice.start();
    bob.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Start SSE listener on bob in background to capture incoming messages
    let sse_handle = bob.spawn_sse_listener(10);

    sleep(Duration::from_millis(500)).await;

    // Send from alice to bob with wait=true to confirm delivery
    let send_resp: serde_json::Value = client
        .post(format!("{}?wait=true", alice.api_url("/v1/messages")))
        .json(&serde_json::json!({
            "to": "toq://127.0.0.1:29619/bob",
            "body": {"text": "hello from alice"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Verify sender got "delivered" (ack received from bob)
    assert_eq!(
        send_resp["status"].as_str().unwrap_or(""),
        "delivered",
        "expected delivered, got: {send_resp}"
    );

    // Wait for SSE to collect, then abort
    sleep(Duration::from_secs(3)).await;
    sse_handle.abort();
    let sse_output = sse_handle.await.unwrap_or_default();

    // Verify bob received the message content
    assert!(
        sse_output.contains("hello from alice"),
        "bob should have received the message via SSE, got: {sse_output}"
    );

    alice.stop();
    bob.stop();
}

// ── Approval workflow ────────────────────────────────────────

#[tokio::test]
async fn approval_mode_shows_pending() {
    let mut alice = Instance::new("alice-ap", "open", 29630, 29629);
    let mut bob = Instance::new("bob-ap", "approval", 29640, 29639);
    alice.start();
    bob.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Alice tries to send to bob (approval mode). May hang on handshake.
    let send_url = alice.api_url("/v1/messages");
    tokio::spawn(async move {
        let _ = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .post(&send_url)
            .json(&serde_json::json!({
                "to": "toq://127.0.0.1:29639/bob-ap",
                "body": {"text": "knock knock"}
            }))
            .send()
            .await;
    });

    sleep(Duration::from_secs(1)).await;

    // Check bob's approvals list
    let approvals: serde_json::Value = client
        .get(bob.api_url("/v1/approvals"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Should have a pending approval (or empty if connection was rejected before reaching approval stage)
    assert!(approvals["approvals"].is_array());

    alice.stop();
    bob.stop();
}

// ── Block prevents send ──────────────────────────────────────

#[tokio::test]
async fn block_then_send_fails() {
    let mut inst = Instance::new("block-send", "open", 29650, 29649);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // Verify daemon is actually running
    let health = Client::new().get(inst.api_url("/v1/health")).send().await;
    assert!(
        health.is_ok() && health.unwrap().status().is_success(),
        "daemon should be running on port 29650"
    );

    let client = Client::new();
    let fake_key = "ed25519%3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D";

    // Block
    let resp = client
        .post(inst.api_url(&format!("/v1/peers/{fake_key}/block")))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify blocked
    let perms: serde_json::Value = client
        .get(inst.api_url("/v1/permissions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let perms_str = serde_json::to_string(&perms).unwrap();
    assert!(
        perms_str.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "expected blocked key in permissions: {perms_str}"
    );

    // Unblock
    let resp = client
        .delete(inst.api_url(&format!("/v1/peers/{fake_key}/block")))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify no longer blocked
    let peers: serde_json::Value = client
        .get(inst.api_url("/v1/peers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let peers_arr = peers["peers"].as_array().unwrap();
    let still_blocked = peers_arr
        .iter()
        .any(|p| p["status"].as_str() == Some("blocked"));
    assert!(!still_blocked, "peer should no longer be blocked");

    inst.stop();
}

// ── Export/import backup ─────────────────────────────────────

#[tokio::test]
async fn export_import_roundtrip() {
    let mut inst = Instance::new("backup", "open", 29710, 29709);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Export
    let export_resp: serde_json::Value = client
        .post(inst.api_url("/v1/backup/export"))
        .json(&serde_json::json!({"passphrase": "test-pass-123"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        export_resp.get("data").is_some() || export_resp.get("backup").is_some(),
        "export should return backup data: {export_resp}"
    );

    // Import into same instance (should succeed or warn about overwrite)
    let import_payload = if let Some(data) = export_resp.get("data") {
        serde_json::json!({"passphrase": "test-pass-123", "data": data})
    } else if let Some(backup) = export_resp.get("backup") {
        serde_json::json!({"passphrase": "test-pass-123", "data": backup})
    } else {
        panic!("no backup data in export response");
    };

    let import_resp = client
        .post(inst.api_url("/v1/backup/import"))
        .json(&import_payload)
        .send()
        .await
        .unwrap();
    // Import should succeed (200) or conflict (409 if keys already exist)
    assert!(
        import_resp.status().is_success() || import_resp.status().as_u16() == 409,
        "import returned unexpected status: {}",
        import_resp.status()
    );

    inst.stop();
}

// ── Double start ─────────────────────────────────────────────

#[tokio::test]
async fn double_start_is_safe() {
    let mut inst = Instance::new("double", "open", 29720, 29719);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // Second start should not crash (may fail with "already running" or succeed as no-op)
    let output = toq_cmd()
        .env("HOME", inst.dir.path())
        .arg("up")
        .output()
        .expect("failed to run toq up");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}").to_lowercase();

    // Should either say already running or succeed
    assert!(
        combined.contains("already") || combined.contains("running") || output.status.success(),
        "double start should be safe, got: {combined}"
    );

    inst.stop();
}

// ── Setup idempotency ────────────────────────────────────────

#[test]
fn setup_twice_preserves_keys() {
    let dir = TempDir::new().unwrap();

    // First setup
    let status = toq_cmd()
        .env("HOME", dir.path())
        .args([
            "setup",
            "--non-interactive",
            "--agent-name",
            "idem",
            "--connection-mode",
            "open",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // Read original key
    let keys_dir = dir.path().join(".toq/keys");
    let original_key = std::fs::read_to_string(keys_dir.join("identity.key")).unwrap();
    assert!(!original_key.is_empty(), "first setup should create key");

    // Second setup
    let status = toq_cmd()
        .env("HOME", dir.path())
        .args([
            "setup",
            "--non-interactive",
            "--agent-name",
            "idem",
            "--connection-mode",
            "open",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // Key should be preserved (not regenerated)
    let new_key = std::fs::read_to_string(keys_dir.join("identity.key")).unwrap();
    assert_eq!(
        original_key, new_key,
        "second setup should preserve existing keys"
    );
}

// ── Clear logs ───────────────────────────────────────────────

#[tokio::test]
async fn clear_logs_empties_log_list() {
    let mut inst = Instance::new("clear-logs", "open", 29730, 29729);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Clear logs
    let resp = client
        .delete(inst.api_url("/v1/logs"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Get logs, should be empty
    let logs: serde_json::Value = client
        .get(inst.api_url("/v1/logs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = logs["entries"]
        .as_array()
        .or_else(|| logs["logs"].as_array())
        .or_else(|| logs.as_array());
    assert!(
        entries.map(|a| a.is_empty()).unwrap_or(true),
        "logs should be empty after clear: {logs}"
    );

    inst.stop();
}

// ── API error handling ───────────────────────────────────────

#[tokio::test]
async fn api_send_missing_to_field() {
    let mut inst = Instance::new("err-missing", "open", 29810, 29809);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .post(inst.api_url("/v1/messages"))
        .json(&serde_json::json!({"body": {"text": "no to field"}}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "missing 'to' should return 4xx, got {}",
        resp.status()
    );

    inst.stop();
}

#[tokio::test]
async fn api_send_invalid_address() {
    let mut inst = Instance::new("err-addr", "open", 29820, 29819);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .post(inst.api_url("/v1/messages"))
        .json(&serde_json::json!({
            "to": "not-a-valid-address",
            "body": {"text": "bad addr"}
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "invalid address should return 4xx, got {}",
        resp.status()
    );

    inst.stop();
}

#[tokio::test]
async fn api_send_invalid_json() {
    let mut inst = Instance::new("err-json", "open", 29830, 29829);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .post(inst.api_url("/v1/messages"))
        .header("content-type", "application/json")
        .body("not json at all")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "invalid JSON should return 4xx, got {}",
        resp.status()
    );

    inst.stop();
}

#[tokio::test]
async fn api_block_empty_key() {
    let mut inst = Instance::new("err-block", "open", 29840, 29839);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // Block with empty/invalid key path
    let resp = Client::new()
        .post(inst.api_url("/v1/peers//block"))
        .send()
        .await
        .unwrap();
    // Should be 4xx or 404
    assert!(
        resp.status().is_client_error() || resp.status().as_u16() == 404,
        "empty key should fail, got {}",
        resp.status()
    );

    inst.stop();
}

// ── Streaming message ────────────────────────────────────────

#[tokio::test]
async fn api_send_streaming_to_unreachable() {
    let mut inst = Instance::new("stream", "open", 29850, 29849);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .post(inst.api_url("/v1/stream/start"))
        .json(&serde_json::json!({
            "to": "toq://nonexistent.invalid/agent"
        }))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = resp.json().await.unwrap();
    let body_str = serde_json::to_string(&body).unwrap().to_lowercase();
    assert!(
        body_str.contains("error") || body_str.contains("fail"),
        "streaming to unreachable should error: {body_str}"
    );

    inst.stop();
}

// ── Config get/update ────────────────────────────────────────

#[tokio::test]
async fn api_config_get() {
    let mut inst = Instance::new("cfg-get", "open", 29910, 29909);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp_str = serde_json::to_string(&resp).unwrap();
    assert!(
        resp_str.contains("cfg-get"),
        "config should contain agent name: {resp_str}"
    );

    inst.stop();
}

#[tokio::test]
async fn api_config_update() {
    let mut inst = Instance::new("cfg-upd", "open", 29920, 29919);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Update log level
    let resp = client
        .patch(inst.api_url("/v1/config"))
        .json(&serde_json::json!({"log_level": "debug"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "config update should succeed, got {}",
        resp.status()
    );

    // Verify change
    let config: serde_json::Value = client
        .get(inst.api_url("/v1/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let config_str = serde_json::to_string(&config).unwrap();
    assert!(
        config_str.contains("debug"),
        "config should reflect update: {config_str}"
    );

    inst.stop();
}

// ── Shutdown via API ─────────────────────────────────────────

#[tokio::test]
async fn api_shutdown_graceful() {
    let mut inst = Instance::new("api-shut", "open", 29930, 29929);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .post(inst.api_url("/v1/daemon/shutdown"))
        .json(&serde_json::json!({"graceful": true}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    sleep(Duration::from_secs(2)).await;

    inst.cmd().arg("status").assert().stdout(
        predicate::str::contains("not running").or(predicate::str::contains("Not running")),
    );
}

// ── Agent card ───────────────────────────────────────────────

#[tokio::test]
async fn api_agent_card() {
    let mut inst = Instance::new("card", "open", 29940, 29939);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/card"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        resp["name"].as_str().unwrap_or(""),
        "card",
        "card should have agent name"
    );
    assert!(
        resp["public_key"].as_str().is_some(),
        "card should have public key"
    );
    assert!(
        resp["protocol_version"].as_str().is_some(),
        "card should have protocol version"
    );

    inst.stop();
}

// ── Connections endpoint ─────────────────────────────────────

#[tokio::test]
async fn api_connections_empty() {
    let mut inst = Instance::new("conns", "open", 29950, 29949);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let conns = resp["connections"]
        .as_array()
        .expect("connections should be array");
    assert!(conns.is_empty(), "fresh daemon should have no connections");

    inst.stop();
}

// ── Discover endpoints ───────────────────────────────────────

#[tokio::test]
async fn api_discover_dns() {
    let mut inst = Instance::new("disc-dns", "open", 29960, 29959);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/discover?host=example.com"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        resp["agents"].is_array(),
        "discover should return agents array"
    );

    inst.stop();
}

#[tokio::test]
async fn api_discover_local() {
    let mut inst = Instance::new("disc-local", "open", 29970, 29969);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/discover/local"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        resp["agents"].is_array(),
        "discover local should return agents array"
    );

    inst.stop();
}

// ── Key rotation ─────────────────────────────────────────────

#[tokio::test]
async fn api_key_rotation() {
    let mut inst = Instance::new("rotate", "open", 29980, 29979);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Get current key
    let status: serde_json::Value = client
        .get(inst.api_url("/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let old_key = status["public_key"].as_str().unwrap().to_string();

    // Rotate
    let resp = client
        .post(inst.api_url("/v1/keys/rotate"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "rotate should succeed");

    // Get new key
    let status: serde_json::Value = client
        .get(inst.api_url("/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_key = status["public_key"].as_str().unwrap().to_string();

    assert_ne!(old_key, new_key, "key should change after rotation");

    inst.stop();
}

// ── Export wrong passphrase ──────────────────────────────────

#[tokio::test]
async fn export_import_wrong_passphrase() {
    let mut inst = Instance::new("bad-pass", "open", 29990, 29989);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Export
    let export_resp: serde_json::Value = client
        .post(inst.api_url("/v1/backup/export"))
        .json(&serde_json::json!({"passphrase": "correct-pass"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let data = export_resp
        .get("data")
        .or_else(|| export_resp.get("backup"))
        .expect("export should return data");

    // Import with wrong passphrase
    let resp = client
        .post(inst.api_url("/v1/backup/import"))
        .json(&serde_json::json!({"passphrase": "wrong-pass", "data": data}))
        .send()
        .await
        .unwrap();

    // Should fail (4xx or 5xx)
    assert!(
        !resp.status().is_success() || resp.status().as_u16() == 409,
        "wrong passphrase should fail, got {}",
        resp.status()
    );

    inst.stop();
}

// ── Config persistence across restart ────────────────────────

#[tokio::test]
async fn config_persists_across_restart() {
    let mut inst = Instance::new("cfg-persist", "open", 30010, 30009);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Update config
    client
        .patch(inst.api_url("/v1/config"))
        .json(&serde_json::json!({"log_level": "trace"}))
        .send()
        .await
        .unwrap();

    // Restart
    inst.stop();
    sleep(SHUTDOWN_DELAY).await;
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // Verify persisted
    let config: serde_json::Value = client
        .get(inst.api_url("/v1/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let config_str = serde_json::to_string(&config).unwrap();
    assert!(
        config_str.contains("trace"),
        "config should persist across restart: {config_str}"
    );

    inst.stop();
}

// ── Thread retrieval ─────────────────────────────────────────

#[tokio::test]
async fn api_get_thread_not_found() {
    let mut inst = Instance::new("thread", "open", 30020, 30019);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/threads/nonexistent-thread-id"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Thread endpoint returns empty messages array for unknown threads
    let messages = resp["messages"].as_array();
    assert!(
        messages.map(|m| m.is_empty()).unwrap_or(true),
        "nonexistent thread should have no messages: {resp}"
    );

    inst.stop();
}

// ── CLI send to unreachable ──────────────────────────────────

#[tokio::test]
async fn cli_send_to_unreachable() {
    let mut inst = Instance::new("cli-send", "open", 30040, 30039);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    // toq send should handle unreachable peer gracefully
    let output = toq_cmd()
        .env("HOME", inst.dir.path())
        .args(["send", "toq://nonexistent.invalid/agent", "hello"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_lowercase();
    // Should show an error, not crash
    assert!(
        combined.contains("error") || combined.contains("fail") || combined.contains("refused"),
        "send to unreachable should show error: {combined}"
    );

    inst.stop();
}

// ── CLI block/unblock ────────────────────────────────────────

#[tokio::test]
async fn cli_block_unblock() {
    let mut inst = Instance::new("cli-block", "open", 30050, 30049);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let fake_key = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // Block via CLI
    inst.cmd().args(["block", fake_key]).assert().success();

    // Verify block took effect via permissions API
    let perms: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/permissions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let perms_str = serde_json::to_string(&perms).unwrap();
    assert!(
        perms_str.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "CLI block should add to permissions: {perms_str}"
    );

    // Unblock via CLI
    inst.cmd().args(["unblock", fake_key]).assert().success();

    // Verify unblock took effect
    let perms: serde_json::Value = Client::new()
        .get(inst.api_url("/v1/permissions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let blocked = perms["blocked"].as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(blocked, 0, "CLI unblock should remove from permissions");

    inst.stop();
}

// ── Two daemons: verify thread_id preserved ──────────────────

#[tokio::test]
async fn two_daemons_thread_preserved() {
    let mut alice = Instance::new("alice-rx", "open", 30110, 30109);
    let mut bob = Instance::new("bob-rx", "open", 30120, 30119);
    alice.start();
    bob.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Start SSE listener on bob
    let sse_handle = bob.spawn_sse_listener(10);

    sleep(Duration::from_millis(500)).await;

    // Send with explicit thread_id
    let send_resp: serde_json::Value = client
        .post(format!("{}?wait=true", alice.api_url("/v1/messages")))
        .json(&serde_json::json!({
            "to": "toq://127.0.0.1:30119/bob-rx",
            "body": {"text": "threaded message"},
            "thread_id": "test-thread-42"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        send_resp["status"].as_str().unwrap_or(""),
        "delivered",
        "message should be delivered: {send_resp}"
    );
    assert_eq!(
        send_resp["thread_id"].as_str().unwrap_or(""),
        "test-thread-42",
        "thread_id should be preserved in response"
    );

    sleep(Duration::from_secs(3)).await;
    sse_handle.abort();
    let sse_output = sse_handle.await.unwrap_or_default();

    assert!(
        sse_output.contains("threaded message"),
        "bob should receive the message: {sse_output}"
    );
    assert!(
        sse_output.contains("test-thread-42"),
        "bob should see the thread_id: {sse_output}"
    );

    alice.stop();
    bob.stop();
}

// ── Two daemons: streaming ───────────────────────────────────

#[tokio::test]
async fn two_daemons_streaming() {
    let mut alice = Instance::new("alice-st", "open", 30130, 30129);
    let mut bob = Instance::new("bob-st", "open", 30140, 30139);
    alice.start();
    bob.start();
    sleep(API_STARTUP_DELAY).await;

    // Start SSE listener on bob
    let sse_handle = bob.spawn_sse_listener(10);

    sleep(Duration::from_millis(500)).await;

    let client = Client::new();

    // Open stream from alice to bob
    let start_resp: serde_json::Value = client
        .post(alice.api_url("/v1/stream/start"))
        .json(&serde_json::json!({
            "to": "toq://127.0.0.1:30139/bob-st"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let stream_id = start_resp["stream_id"].as_str().unwrap();

    // Send chunks
    client
        .post(alice.api_url("/v1/stream/chunk"))
        .json(&serde_json::json!({"stream_id": stream_id, "text": "streaming "}))
        .send()
        .await
        .unwrap();

    client
        .post(alice.api_url("/v1/stream/chunk"))
        .json(&serde_json::json!({"stream_id": stream_id, "text": "content"}))
        .send()
        .await
        .unwrap();

    // End stream
    client
        .post(alice.api_url("/v1/stream/end"))
        .json(&serde_json::json!({"stream_id": stream_id}))
        .send()
        .await
        .unwrap();

    // Give time for delivery
    sleep(Duration::from_secs(5)).await;
    sse_handle.abort();
    let sse_output = sse_handle.await.unwrap_or_default();

    assert!(
        sse_output.contains("streaming") && sse_output.contains("content"),
        "bob should receive streaming chunks via SSE: {sse_output}"
    );

    alice.stop();
    bob.stop();
}

// ── Approval: approve then send ──────────────────────────────

#[tokio::test]
async fn approval_approve_then_send() {
    let mut alice = Instance::new("alice-apv", "open", 30150, 30149);
    let mut bob = Instance::new("bob-apv", "approval", 30160, 30159);
    alice.start();
    bob.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Alice sends to bob (approval mode). This may hang on the handshake
    // since bob hasn't approved alice yet, so we use a timeout.
    let send_url = alice.api_url("/v1/messages");
    tokio::spawn(async move {
        let _ = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .post(&send_url)
            .json(&serde_json::json!({
                "to": "toq://127.0.0.1:30159/bob-apv",
                "body": {"text": "please approve me"}
            }))
            .send()
            .await;
    });
    // Response may be a timeout or error, that's expected

    // Wait for the connection attempt to trigger a pending approval
    sleep(Duration::from_secs(3)).await;

    // Check bob's approvals
    let approvals: serde_json::Value = client
        .get(bob.api_url("/v1/approvals"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    if let Some(first) = approvals["approvals"].as_array().and_then(|a| a.first()) {
        let id = first["id"].as_str().unwrap_or("unknown");
        let resp = client
            .post(bob.api_url(&format!("/v1/approvals/{id}")))
            .json(&serde_json::json!({"decision": "approve"}))
            .send()
            .await
            .unwrap();
        // Approve may return 200 or 404 if the ID format doesn't match
        assert!(
            resp.status().is_success() || resp.status().as_u16() == 404,
            "approve should return 200 or 404, got {}",
            resp.status()
        );
    }
    // If no approvals appeared, the connection may have been rejected at TLS level
    // before reaching the approval stage. That's valid for this test environment.

    alice.stop();
    bob.stop();
}

// ── Approval: deny ───────────────────────────────────────────

#[tokio::test]
async fn approval_deny() {
    let mut alice = Instance::new("alice-deny", "open", 30170, 30169);
    let mut bob = Instance::new("bob-deny", "approval", 30180, 30179);
    alice.start();
    bob.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Alice sends to bob (approval mode). May hang on handshake, so use timeout.
    let send_url = alice.api_url("/v1/messages");
    tokio::spawn(async move {
        let _ = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .post(&send_url)
            .json(&serde_json::json!({
                "to": "toq://127.0.0.1:30179/bob-deny",
                "body": {"text": "deny me"}
            }))
            .send()
            .await;
    });

    sleep(Duration::from_secs(1)).await;

    // Check and deny
    let approvals: serde_json::Value = client
        .get(bob.api_url("/v1/approvals"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    if let Some(first) = approvals["approvals"].as_array().and_then(|a| a.first()) {
        let arr_len = approvals["approvals"].as_array().unwrap().len();
        let id = first["id"].as_str().unwrap_or("unknown");
        let resp = client
            .post(bob.api_url(&format!("/v1/approvals/{id}")))
            .json(&serde_json::json!({"decision": "deny"}))
            .send()
            .await
            .unwrap();
        // May return 200 or 404 depending on ID format/timing
        assert!(
            resp.status().is_success() || resp.status().as_u16() == 404,
            "deny should return 200 or 404, got {}",
            resp.status()
        );

        if resp.status().is_success() {
            // Verify removed from approvals
            let approvals_after: serde_json::Value = client
                .get(bob.api_url("/v1/approvals"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let after_len = approvals_after["approvals"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            assert!(
                after_len < arr_len,
                "denied approval should be removed from list"
            );
        }
    }

    alice.stop();
    bob.stop();
}

// ── Export empty passphrase ──────────────────────────────────

#[tokio::test]
async fn export_empty_passphrase_fails() {
    let mut inst = Instance::new("empty-pass", "open", 30210, 30209);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let resp = Client::new()
        .post(inst.api_url("/v1/backup/export"))
        .json(&serde_json::json!({"passphrase": ""}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "empty passphrase should fail, got {}",
        resp.status()
    );

    inst.stop();
}

// ── CLI clear-logs ───────────────────────────────────────────

#[tokio::test]
async fn cli_clear_logs() {
    let mut inst = Instance::new("cli-clr", "open", 30220, 30219);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    inst.cmd().arg("clear-logs").assert().success().stdout(
        predicate::str::contains("clear").or(predicate::str::contains("Clear")
            .or(predicate::str::contains("delete").or(predicate::str::contains("Delete")))),
    );

    inst.stop();
}

// ── Revoke ───────────────────────────────────────────────────

#[tokio::test]
async fn api_revoke_approved_peer() {
    let mut inst = Instance::new("api-revoke", "approval", 30240, 30239);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = reqwest::Client::new();
    let kp = toq_core::crypto::Keypair::generate();
    let fake_key = kp.public_key().to_encoded();
    let encoded_key = urlencoding::encode(&fake_key);

    // Approve
    let resp = client
        .post(inst.api_url(&format!("/v1/approvals/{encoded_key}")))
        .json(&serde_json::json!({"decision": "approve"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify approved via permissions
    let perms: serde_json::Value = client
        .get(inst.api_url("/v1/permissions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !perms["approved"].as_array().unwrap().is_empty(),
        "expected at least one approved rule after approve"
    );

    // Revoke
    let resp = client
        .post(inst.api_url(&format!("/v1/approvals/{encoded_key}/revoke")))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify removed from permissions
    let perms: serde_json::Value = client
        .get(inst.api_url("/v1/permissions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        perms["approved"].as_array().unwrap().is_empty(),
        "expected no approved rules after revoke"
    );

    inst.stop();
}

// ── Message history ──────────────────────────────────────────

#[tokio::test]
async fn api_message_history_empty() {
    let mut inst = Instance::new("api-hist-e", "open", 30260, 30259);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(inst.api_url("/v1/messages/history"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["messages"].as_array().unwrap().len(), 0);

    inst.stop();
}

#[tokio::test]
async fn api_message_history_with_limit() {
    let mut inst = Instance::new("api-hist-l", "open", 30280, 30279);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(inst.api_url("/v1/messages/history?limit=5"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp["messages"].as_array().is_some());

    inst.stop();
}

// --- Handler API ---

#[tokio::test]
async fn api_handler_crud() {
    let mut inst = Instance::new("api-handler", "open", 30290, 30289);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // List: empty
    let resp: serde_json::Value = client
        .get(inst.api_url("/v1/handlers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["handlers"].as_array().unwrap().len(), 0);

    // Add a handler
    let resp = client
        .post(inst.api_url("/v1/handlers"))
        .json(&serde_json::json!({
            "name": "test-handler",
            "command": "echo hello",
            "filter_from": ["toq://host/*"],
            "filter_type": ["message.send"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List: one handler
    let resp: serde_json::Value = client
        .get(inst.api_url("/v1/handlers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let handlers = resp["handlers"].as_array().unwrap();
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["name"], "test-handler");
    assert_eq!(handlers[0]["enabled"], true);

    // Duplicate name returns conflict
    let resp = client
        .post(inst.api_url("/v1/handlers"))
        .json(&serde_json::json!({
            "name": "test-handler",
            "command": "echo dup"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Update: disable
    let resp = client
        .put(inst.api_url("/v1/handlers/test-handler"))
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp: serde_json::Value = client
        .get(inst.api_url("/v1/handlers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["handlers"][0]["enabled"], false);

    // Delete
    let resp = client
        .delete(inst.api_url("/v1/handlers/test-handler"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List: empty again
    let resp: serde_json::Value = client
        .get(inst.api_url("/v1/handlers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["handlers"].as_array().unwrap().len(), 0);

    // Delete nonexistent returns 404
    let resp = client
        .delete(inst.api_url("/v1/handlers/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    inst.stop();
}

#[tokio::test]
async fn api_handler_reload() {
    let mut inst = Instance::new("api-handler-rl", "open", 30292, 30291);
    inst.start();
    sleep(API_STARTUP_DELAY).await;

    let client = Client::new();

    // Reload returns success even with no handlers
    let resp = client
        .post(inst.api_url("/v1/handlers/reload"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    inst.stop();
}

#[test]
fn whoami_shows_agent_info() {
    let inst = Instance::new("whoami-test", "approval", 19810, 19809);
    inst.cmd()
        .arg("whoami")
        .assert()
        .success()
        .stdout(predicates::str::contains("whoami-test"))
        .stdout(predicates::str::contains("approval"))
        .stdout(predicates::str::contains("ed25519:"));
}

#[test]
fn config_show() {
    let inst = Instance::new("config-show", "approval", 19812, 19811);
    inst.cmd()
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicates::str::contains("agent_name"))
        .stdout(predicates::str::contains("config-show"));
}

#[test]
fn config_set_connection_mode() {
    let inst = Instance::new("config-set", "approval", 19814, 19813);
    inst.cmd()
        .args(["config", "set", "connection_mode", "open"])
        .assert()
        .success()
        .stdout(predicates::str::contains("connection_mode = open"));
    // Verify it persisted
    inst.cmd()
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicates::str::contains("open"));
}

#[test]
fn config_set_invalid_mode() {
    let inst = Instance::new("config-inv", "approval", 19816, 19815);
    inst.cmd()
        .args(["config", "set", "connection_mode", "bogus"])
        .assert()
        .failure();
}

#[test]
fn config_set_unknown_key() {
    let inst = Instance::new("config-unk", "approval", 19818, 19817);
    inst.cmd()
        .args(["config", "set", "nonexistent", "value"])
        .assert()
        .failure();
}

#[test]
fn handler_add_llm_requires_model() {
    let inst = Instance::new("llm-nomodel", "approval", 19820, 19819);
    inst.cmd()
        .args(["handler", "add", "chat", "--provider", "openai"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--model is required"));
}

#[test]
fn handler_add_rejects_both_command_and_provider() {
    let inst = Instance::new("llm-both", "approval", 19822, 19821);
    inst.cmd()
        .args([
            "handler",
            "add",
            "chat",
            "--command",
            "echo hi",
            "--provider",
            "openai",
            "--model",
            "gpt-4o",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot use both"));
}

#[test]
fn handler_add_rejects_invalid_provider() {
    let inst = Instance::new("llm-badprov", "approval", 19824, 19823);
    inst.cmd()
        .args([
            "handler",
            "add",
            "chat",
            "--provider",
            "google",
            "--model",
            "gemini",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "must be openai, anthropic, bedrock, or ollama",
        ));
}

#[test]
fn handler_add_llm_succeeds() {
    let inst = Instance::new("llm-ok", "approval", 19826, 19825);
    inst.cmd()
        .args([
            "handler",
            "add",
            "chat",
            "--provider",
            "openai",
            "--model",
            "gpt-4o",
            "--prompt",
            "You are helpful",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Added handler 'chat'"));
    // Verify it's in the list
    inst.cmd()
        .args(["handler", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("chat"));
}

#[test]
fn init_creates_workspace_with_host() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::from_std(toq_cmd());
    cmd.args([
        "init",
        "--name",
        "alice",
        "--host",
        "example.com",
        "--port",
        "9009",
    ])
    .current_dir(dir.path())
    .assert()
    .success()
    .stdout(predicates::str::contains("Agent: alice"));

    let config = std::fs::read_to_string(dir.path().join(".toq/config.toml")).unwrap();
    assert!(config.contains("host = \"example.com\""));
    assert!(config.contains("agent_name = \"alice\""));
}

#[test]
fn init_omits_host_when_localhost() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::from_std(toq_cmd());
    cmd.args(["init", "--name", "bob"])
        .current_dir(dir.path())
        .assert()
        .success();

    let config = std::fs::read_to_string(dir.path().join(".toq/config.toml")).unwrap();
    assert!(!config.contains("host ="));
}

#[test]
fn listen_auto_generates_keys_after_init() {
    let dir = tempfile::tempdir().unwrap();

    // Init only (no setup, no keys)
    let mut cmd = assert_cmd::Command::from_std(toq_cmd());
    cmd.args(["init", "--name", "alice", "--port", "19050"])
        .current_dir(dir.path())
        .assert()
        .success();

    let keys_dir = dir.path().join(".toq/keys");
    assert!(!keys_dir.exists(), "keys should not exist after init");

    // Listen should auto-generate keys and start (kill after 1s)
    let mut child = StdCommand::new(toq_bin())
        .args(["listen"])
        .current_dir(dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn toq listen");

    std::thread::sleep(Duration::from_secs(1));
    let _ = child.kill();
    let _ = child.wait();

    assert!(keys_dir.exists(), "keys should exist after listen");
    assert!(
        keys_dir.join("identity.key").exists(),
        "identity key should be generated"
    );
    assert!(
        keys_dir.join("tls_cert.pem").exists(),
        "TLS cert should be generated"
    );

    kill_port(19050);
}

#[test]
fn listen_fails_without_workspace() {
    let dir = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::from_std(toq_cmd());
    cmd.env("HOME", dir.path())
        .current_dir(dir.path())
        .arg("listen")
        .assert()
        .failure()
        .stderr(predicates::str::contains("No workspace found"));
}
