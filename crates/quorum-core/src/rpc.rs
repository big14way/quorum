//! Transport-agnostic JSON-RPC access. The core never opens a socket: it
//! talks through this trait. The wasm shim implements it over waki
//! (blocking wasi:http, TLS host-side); host tests implement it with MockRpc
//! and canned fixtures, so `cargo test` runs with no network and no wasm
//! toolchain, exactly as the bounty requires.

use base64::Engine;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

pub trait Rpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

/// getAccountInfo with base64 encoding. Ok(None) when the account is absent.
pub fn get_account_base64(rpc: &dyn Rpc, address: &str) -> Result<Option<Vec<u8>>, String> {
    let res = rpc.call(
        "getAccountInfo",
        json!([address, {"encoding": "base64", "commitment": "confirmed"}]),
    )?;
    let value = res.get("value").cloned().unwrap_or(Value::Null);
    if value.is_null() {
        return Ok(None);
    }
    let data_b64 = value
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|s| s.as_str())
        .ok_or("malformed getAccountInfo response")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| format!("account data base64: {e}"))?;
    Ok(Some(bytes))
}

/// getMultipleAccounts with base64 encoding; None per missing account.
pub fn get_multiple_accounts_base64(
    rpc: &dyn Rpc,
    addresses: &[String],
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let res = rpc.call(
        "getMultipleAccounts",
        json!([addresses, {"encoding": "base64", "commitment": "confirmed"}]),
    )?;
    let arr = res
        .get("value")
        .and_then(|v| v.as_array())
        .ok_or("malformed getMultipleAccounts response")?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        if item.is_null() {
            out.push(None);
            continue;
        }
        let data_b64 = item
            .get("data")
            .and_then(|d| d.get(0))
            .and_then(|s| s.as_str())
            .ok_or("malformed account entry")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| format!("account data base64: {e}"))?;
        out.push(Some(bytes));
    }
    Ok(out)
}

/// getLatestBlockhash, decoded from base58 to raw 32 bytes.
pub fn get_latest_blockhash(rpc: &dyn Rpc) -> Result<[u8; 32], String> {
    let res = rpc.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
    let bh = res
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(|s| s.as_str())
        .ok_or("malformed getLatestBlockhash response")?;
    let bytes = bs58::decode(bh)
        .into_vec()
        .map_err(|e| format!("blockhash base58: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "blockhash is not 32 bytes".into())
}

/// simulateTransaction over a base64 payload with signature verification off
/// and the blockhash replaced, so unsigned proposals simulate cleanly.
pub fn simulate_transaction_base64(rpc: &dyn Rpc, tx_b64: &str) -> Result<Value, String> {
    rpc.call(
        "simulateTransaction",
        json!([tx_b64, {
            "encoding": "base64",
            "sigVerify": false,
            "replaceRecentBlockhash": true,
            "commitment": "confirmed"
        }]),
    )
}

/// Deterministic mock: a FIFO queue of canned results per method. A call for
/// a method with an empty queue is a test failure by construction, which
/// keeps fixtures honest about exactly how many RPC calls the core makes.
#[derive(Default)]
pub struct MockRpc {
    queues: RefCell<HashMap<String, VecDeque<Result<Value, String>>>>,
    pub log: RefCell<Vec<String>>,
}

impl MockRpc {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&self, method: &str, result: Result<Value, String>) {
        self.queues
            .borrow_mut()
            .entry(method.to_string())
            .or_default()
            .push_back(result);
    }
    pub fn push_ok(&self, method: &str, value: Value) {
        self.push(method, Ok(value));
    }
}

impl Rpc for MockRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.log.borrow_mut().push(format!("{method} {params}"));
        self.queues
            .borrow_mut()
            .get_mut(method)
            .and_then(|q| q.pop_front())
            .unwrap_or_else(|| Err(format!("mock: unexpected call to {method}")))
    }
}
