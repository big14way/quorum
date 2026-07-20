//! Load the built components through the REAL ZeroClaw host adapter — the
//! same wasmtime runtime, WIT bindings, config injection, and fuel limits a
//! production daemon runs. Per the upstream authoring guide this is the
//! strongest pre-distribution signal short of a live host.
//!
//! Prerequisite: build the components first —
//!   (cd plugins/<name> && cargo build --target wasm32-wasip2 --release)

use std::collections::HashMap;
use std::path::PathBuf;

use zeroclaw_api::tool::Tool;
use zeroclaw_plugins::component::PluginLimits;
use zeroclaw_plugins::wasm_tool::WasmTool;
use zeroclaw_plugins::PluginPermission;

fn wasm_path(plugin: &str, file: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../plugins/{plugin}/target/wasm32-wasip2/release/{file}"
    ));
    assert!(
        p.exists(),
        "component not built: {} — run (cd plugins/{plugin} && cargo build --target wasm32-wasip2 --release)",
        p.display()
    );
    p
}

fn host_default_limits() -> PluginLimits {
    // Mirrors zeroclaw-config PluginLimitsConfig::default().
    PluginLimits {
        call_fuel: 1_000_000_000,
        max_memory_bytes: 256 * 1024 * 1024,
        max_table_elements: 100_000,
        max_instances: 64,
    }
}

/// The operator's config exactly as the host stores it: a flat string map.
fn propose_config() -> HashMap<String, String> {
    HashMap::from([
        ("rpc_url".into(), "https://example.invalid".into()),
        (
            "multisig".into(),
            "F65MT4J3kSRdyPMehKvuUvHmpCktrH9Q8n7J8dsHit68".into(),
        ),
        (
            "creator_pubkey".into(),
            "DpcyqkendyzQd6yvDyHt9BEpUp2EnmXbEFUnpqAXpFAZ".into(),
        ),
        ("vault_index".into(), "0".into()),
        (
            "mints".into(),
            r#"[{"mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","symbol":"USDC","decimals":6,"per_proposal_cap":"500"}]"#.into(),
        ),
        (
            "recipients".into(),
            r#"{"ana":"F65MT4J3kSRdyPMehKvuUvHmpCktrH9Q8n7J8dsHit68"}"#.into(),
        ),
    ])
}

#[test]
fn real_host_probes_squads_propose_metadata() {
    let tool = WasmTool::from_wasm(
        wasm_path("squads-propose", "squads_propose.wasm"),
        vec![PluginPermission::HttpClient, PluginPermission::ConfigRead],
        "fallback-name".into(),
        "fallback-desc".into(),
        propose_config(),
        host_default_limits(),
    );
    // If the probe fell back, the WIT ABI is broken — fail loudly.
    assert_eq!(tool.name(), "squads_propose", "metadata probe fell back");
    assert!(tool.description().contains("holds no keys"));
    let schema = tool.parameters_schema();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(required, ["recipient", "amount", "token"]);
}

#[tokio::test]
async fn real_host_policy_refusal_smuggled_address() {
    let tool = WasmTool::from_wasm(
        wasm_path("squads-propose", "squads_propose.wasm"),
        vec![PluginPermission::HttpClient, PluginPermission::ConfigRead],
        "squads-propose".into(),
        String::new(),
        propose_config(),
        host_default_limits(),
    );
    // The classic injection: a raw base58 address instead of a book name.
    let result = tool
        .execute(serde_json::json!({
            "recipient": "DpcyqkendyzQd6yvDyHt9BEpUp2EnmXbEFUnpqAXpFAZ",
            "amount": "150",
            "token": "USDC"
        }))
        .await
        .expect("execute must not trap");
    assert!(!result.success);
    let err = result.error.expect("refusal carries a reason");
    assert!(err.contains("address book"), "unexpected refusal: {err}");
}

#[tokio::test]
async fn real_host_refuses_without_config_permission() {
    // Same call, but the manifest permission set lacks config_read: the host
    // strips the config, and the plugin must fail closed.
    let tool = WasmTool::from_wasm(
        wasm_path("squads-propose", "squads_propose.wasm"),
        vec![PluginPermission::HttpClient],
        "squads-propose".into(),
        String::new(),
        propose_config(),
        host_default_limits(),
    );
    let result = tool
        .execute(serde_json::json!({
            "recipient": "ana", "amount": "150", "token": "USDC"
        }))
        .await
        .expect("execute must not trap");
    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("config"), "unexpected refusal: {err}");
}

#[tokio::test]
async fn real_host_tx_xray_decodes_offline() {
    use quorum_core::message::{compile_legacy_message, unsigned_tx_base64};
    use quorum_core::pubkey::Pubkey;
    use quorum_core::spl::memo_ix;

    // Build a small unsigned transaction with the published core, then have
    // the component decode it through the host with simulate=false: a full
    // happy-path execute with zero network and zero config.
    let payer = Pubkey([6u8; 32]);
    let msg = compile_legacy_message(&payer, &[memo_ix("inv-88")], &[7u8; 32]).unwrap();
    let tx = unsigned_tx_base64(&msg);

    let tool = WasmTool::from_wasm(
        wasm_path("tx-xray", "tx_xray.wasm"),
        vec![PluginPermission::HttpClient, PluginPermission::ConfigRead],
        "tx-xray".into(),
        String::new(),
        HashMap::new(),
        host_default_limits(),
    );
    let result = tool
        .execute(serde_json::json!({
            "unsigned_tx_base64": tx,
            "simulate": false
        }))
        .await
        .expect("execute must not trap");
    assert!(result.success, "decode failed: {:?}", result.error);
    let output = result.output.to_string();
    assert!(
        output.contains("Memo"),
        "receipt missing memo line: {output}"
    );
}
