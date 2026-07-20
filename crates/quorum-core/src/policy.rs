//! The policy layer every money-shaped argument passes through before any
//! bytes are built. Design rule: the model speaks in names and intents, the
//! plugin speaks in verified addresses and base units. Everything here fails
//! closed: missing config is an error, an unknown mint is an error, a raw
//! base58 recipient is an error even when it is a perfectly valid address,
//! and a breached cap is an error with the cap in the message.

use crate::pubkey::Pubkey;
use crate::spl::{parse_ui_amount, TOKEN22_PROGRAM, TOKEN_PROGRAM};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct MintRule {
    pub mint: Pubkey,
    pub symbol: String,
    pub decimals: u8,
    /// Cap in base units, parsed from the config's decimal string.
    pub cap_base_units: u64,
    pub token_2022: bool,
}

impl MintRule {
    pub fn token_program(&self) -> Pubkey {
        if self.token_2022 {
            TOKEN22_PROGRAM
        } else {
            TOKEN_PROGRAM
        }
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub mints: Vec<MintRule>,
    /// name -> verified address
    pub recipients: BTreeMap<String, Pubkey>,
    pub max_memo_len: usize,
}

fn str_field<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("config missing required field '{key}' in {ctx}"))
}

/// The ZeroClaw host stores per-plugin config as a flat string-to-string map
/// (`plugins.entries[].config: HashMap<String, String>`), so structured values
/// arrive inside `__config` as JSON encoded in a string. Accept both shapes:
/// the host's JSON-in-a-string and a native array/object. A string that fails
/// to parse as JSON is a loud error, never a missing-key fallback.
fn structured_field(cfg: &Value, key: &str) -> Result<Option<Value>, String> {
    match cfg.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => serde_json::from_str(s)
            .map(Some)
            .map_err(|e| format!("config '{key}' is a string but not valid JSON: {e}")),
        Some(v) => Ok(Some(v.clone())),
    }
}

/// Accept a config integer either natively or as a decimal string (the host's
/// flat map makes every value a string). Present-but-malformed is an error.
pub fn u64_field(cfg: &Value, key: &str) -> Result<Option<u64>, String> {
    match cfg.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            .map(Some)
            .ok_or_else(|| format!("config '{key}' must be a non-negative integer")),
    }
}

/// Accept a config boolean either natively or as the string "true"/"false".
/// A present-but-malformed value is an error, not a silent default.
pub fn bool_field(cfg: &Value, key: &str) -> Result<Option<bool>, String> {
    match cfg.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(Value::String(s)) => match s.trim() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(format!("config '{key}' must be true or false")),
        },
        Some(_) => Err(format!("config '{key}' must be a boolean")),
    }
}

/// Largest mint decimals we support. 10^18 is the practical ceiling for SPL
/// mints and keeps every 10^decimals computation inside u64/u128.
pub const MAX_DECIMALS: u8 = 18;

/// A character that must never survive into model context or an on-chain
/// memo: C0/C1 controls plus the invisible and bidirectional-formatting code
/// points (zero-width spaces, bidi overrides/isolates, line/paragraph
/// separators, BOM) that can hide or reorder text a human is meant to read.
fn is_display_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}'   // zero-width space/joiner + LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{2028}' | '\u{2029}' // line / paragraph separators
            | '\u{FEFF}') // BOM / zero-width no-break space
}

/// Collect characters until adding the next one would exceed `max_bytes`,
/// respecting UTF-8 boundaries. Caps by byte length because the memo and any
/// receipt line are emitted as bytes, and a multi-byte character budget must
/// be counted in bytes, not chars.
fn take_bytes(chars: impl Iterator<Item = char>, max_bytes: usize) -> String {
    let mut out = String::new();
    for c in chars {
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

impl Policy {
    /// Build from the plugin's injected `__config` section. Every required
    /// piece must be present and well formed or this returns Err.
    pub fn from_config(cfg: &Value) -> Result<Policy, String> {
        let mints_owned = structured_field(cfg, "mints")?;
        let mints_v = mints_owned
            .as_ref()
            .and_then(|m| m.as_array())
            .ok_or("config missing 'mints' allowlist: refusing to operate without one")?;
        if mints_v.is_empty() {
            return Err("config 'mints' allowlist is empty: refusing to operate".into());
        }
        let mut mints = Vec::with_capacity(mints_v.len());
        for (i, m) in mints_v.iter().enumerate() {
            let ctx = format!("mints[{i}]");
            let mint = Pubkey::from_base58(str_field(m, "mint", &ctx)?)
                .map_err(|e| format!("{ctx}.mint: {e}"))?;
            let symbol = str_field(m, "symbol", &ctx)?.to_string();
            let decimals = m
                .get("decimals")
                .and_then(|d| {
                    d.as_u64()
                        .or_else(|| d.as_str().and_then(|s| s.trim().parse().ok()))
                })
                .and_then(|d| u8::try_from(d).ok())
                .ok_or_else(|| format!("{ctx} missing valid 'decimals'"))?;
            // Bound decimals so 10^decimals stays representable in the amount
            // math and the receipt formatter (real SPL mints are <= ~9); this
            // fails closed on an absurd config rather than overflowing later.
            if decimals > MAX_DECIMALS {
                return Err(format!(
                    "{ctx}.decimals {decimals} exceeds the supported maximum of {MAX_DECIMALS}"
                ));
            }
            let cap_str = str_field(m, "per_proposal_cap", &ctx)?;
            let cap_base_units = parse_ui_amount(cap_str, decimals)
                .map_err(|e| format!("{ctx}.per_proposal_cap: {e}"))?;
            // token_2022 arrives as a string in the host's flat config; parse
            // bool-or-string and refuse a malformed value rather than silently
            // treating a Token-2022 mint as a legacy Token mint.
            let token_2022 = bool_field(m, "token_2022")?.unwrap_or(false);
            mints.push(MintRule {
                mint,
                symbol,
                decimals,
                cap_base_units,
                token_2022,
            });
        }
        let rec_owned = structured_field(cfg, "recipients")?;
        let rec_v = rec_owned
            .as_ref()
            .and_then(|r| r.as_object())
            .ok_or("config missing 'recipients' address book: refusing to operate without one")?;
        if rec_v.is_empty() {
            return Err("config 'recipients' address book is empty: refusing to operate".into());
        }
        let mut recipients = BTreeMap::new();
        for (name, addr) in rec_v {
            let addr = addr
                .as_str()
                .ok_or_else(|| format!("recipients.{name} must be a string address"))?;
            let pk = Pubkey::from_base58(addr).map_err(|e| format!("recipients.{name}: {e}"))?;
            recipients.insert(name.to_lowercase(), pk);
        }
        let max_memo_len = u64_field(cfg, "max_memo_len")?
            .map(|v| v as usize)
            .unwrap_or(96);
        Ok(Policy {
            mints,
            recipients,
            max_memo_len,
        })
    }

    /// Look up a mint by symbol (case insensitive) or exact address, but only
    /// within the allowlist. Anything else is refused.
    pub fn resolve_mint(&self, symbol_or_address: &str) -> Result<&MintRule, String> {
        let q = symbol_or_address.trim();
        if let Some(r) = self.mints.iter().find(|r| r.symbol.eq_ignore_ascii_case(q)) {
            return Ok(r);
        }
        if let Ok(pk) = Pubkey::from_base58(q) {
            if let Some(r) = self.mints.iter().find(|r| r.mint == pk) {
                return Ok(r);
            }
            return Err(format!(
                "mint {} is not on the allowlist; add it to config to enable it",
                pk.short()
            ));
        }
        Err(format!("unknown token '{q}': not on the mint allowlist"))
    }

    /// Resolve a recipient strictly through the address book. A raw base58
    /// address is rejected on purpose, even when valid: models mistype and
    /// hallucinate addresses, and injected text loves to smuggle them. The
    /// operator adds recipients to config once; the model only ever names
    /// them.
    pub fn resolve_recipient(&self, name: &str) -> Result<Pubkey, String> {
        let q = name.trim().to_lowercase();
        if let Some(pk) = self.recipients.get(&q) {
            return Ok(*pk);
        }
        if Pubkey::from_base58(name.trim()).is_ok() {
            return Err(
                "raw addresses are not accepted; add this recipient to the address book in \
                 config and refer to them by name"
                    .into(),
            );
        }
        let known: Vec<&str> = self.recipients.keys().map(|s| s.as_str()).collect();
        Err(format!(
            "unknown recipient '{}'; known recipients: {}",
            name.trim(),
            known.join(", ")
        ))
    }

    /// Enforce the per-proposal cap for a mint. Returns base units.
    pub fn check_amount(&self, rule: &MintRule, ui_amount: &str) -> Result<u64, String> {
        let amount = parse_ui_amount(ui_amount, rule.decimals)?;
        if amount > rule.cap_base_units {
            return Err(format!(
                "amount exceeds the per proposal cap for {} ({} base units > cap {})",
                rule.symbol, amount, rule.cap_base_units
            ));
        }
        Ok(amount)
    }

    /// Memos are byte-length-capped and stripped of control and invisible /
    /// bidirectional characters, so a memo can never be a payload nor exceed
    /// its byte budget. `max_memo_len` is a byte budget.
    pub fn sanitize_memo(&self, memo: Option<&str>) -> Option<String> {
        memo.map(|m| {
            take_bytes(
                m.chars().filter(|c| !is_display_unsafe(*c)),
                self.max_memo_len,
            )
        })
        .filter(|s: &String| !s.is_empty())
    }
}

/// Strip and byte-length-cap any string that originated on-chain (token
/// names, symbols, memos in history) before it is allowed anywhere near model
/// context. On-chain data is attacker-controlled input: control characters
/// and invisible / bidirectional formatting code points are removed, and the
/// result is capped in bytes.
pub fn sanitize_untrusted(s: &str, max: usize) -> String {
    take_bytes(s.chars().filter(|c| !is_display_unsafe(*c)), max)
}
