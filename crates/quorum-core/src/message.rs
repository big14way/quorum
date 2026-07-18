//! Legacy Solana message compilation and unsigned transaction serialization.
//!
//! The outer transaction (the one a human signs in their wallet) is built as a
//! legacy message for maximum wallet compatibility. Signatures are zero-filled
//! placeholders; the wallet replaces them at signing time.

use crate::pubkey::Pubkey;
use base64::Engine;

#[derive(Clone, Debug)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn writable(pubkey: Pubkey, is_signer: bool) -> Self {
        Self { pubkey, is_signer, is_writable: true }
    }
    pub fn readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self { pubkey, is_signer, is_writable: false }
    }
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Solana compact-u16 length encoding.
pub fn shortvec_len(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

/// Read a compact-u16 length. Returns (value, bytes consumed).
pub fn shortvec_read(buf: &[u8]) -> Result<(usize, usize), String> {
    let mut n: usize = 0;
    let mut shift = 0u32;
    for (i, b) in buf.iter().enumerate().take(3) {
        n |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Ok((n, i + 1));
        }
        shift += 7;
    }
    Err("shortvec length overrun".into())
}

struct KeyEntry {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

/// Merge account metas across instructions, force the payer to the front as a
/// writable signer, append program ids as readonly non-signers, then order as
/// the runtime expects: writable signers, readonly signers, writable
/// non-signers, readonly non-signers.
fn collect_keys(payer: &Pubkey, ixs: &[Instruction]) -> Vec<KeyEntry> {
    let mut entries: Vec<KeyEntry> = vec![KeyEntry {
        pubkey: *payer,
        is_signer: true,
        is_writable: true,
    }];
    let mut upsert = |pk: Pubkey, signer: bool, writable: bool| {
        if let Some(e) = entries.iter_mut().find(|e| e.pubkey == pk) {
            e.is_signer |= signer;
            e.is_writable |= writable;
        } else {
            entries.push(KeyEntry { pubkey: pk, is_signer: signer, is_writable: writable });
        }
    };
    for ix in ixs {
        for m in &ix.accounts {
            upsert(m.pubkey, m.is_signer, m.is_writable);
        }
    }
    for ix in ixs {
        upsert(ix.program_id, false, false);
    }
    let mut ordered: Vec<KeyEntry> = Vec::with_capacity(entries.len());
    let payer_entry = entries.remove(0);
    ordered.push(payer_entry);
    for pass in 0..4 {
        for e in &entries {
            let keep = match pass {
                0 => e.is_signer && e.is_writable,
                1 => e.is_signer && !e.is_writable,
                2 => !e.is_signer && e.is_writable,
                _ => !e.is_signer && !e.is_writable,
            };
            if keep {
                ordered.push(KeyEntry {
                    pubkey: e.pubkey,
                    is_signer: e.is_signer,
                    is_writable: e.is_writable,
                });
            }
        }
    }
    ordered
}

/// Serialized legacy message plus its header, for callers that need counts.
pub struct CompiledMessage {
    pub bytes: Vec<u8>,
    pub num_required_signatures: u8,
    pub account_keys: Vec<Pubkey>,
}

pub fn compile_legacy_message(
    payer: &Pubkey,
    ixs: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Result<CompiledMessage, String> {
    let keys = collect_keys(payer, ixs);
    if keys.len() > 255 {
        return Err("too many account keys".into());
    }
    let num_required_signatures = keys.iter().filter(|k| k.is_signer).count() as u8;
    let num_readonly_signed = keys.iter().filter(|k| k.is_signer && !k.is_writable).count() as u8;
    let num_readonly_unsigned = keys.iter().filter(|k| !k.is_signer && !k.is_writable).count() as u8;

    let index_of = |pk: &Pubkey| -> Result<u8, String> {
        keys.iter()
            .position(|k| &k.pubkey == pk)
            .map(|i| i as u8)
            .ok_or_else(|| format!("unindexed key {pk}"))
    };

    let mut out = Vec::with_capacity(256);
    out.push(num_required_signatures);
    out.push(num_readonly_signed);
    out.push(num_readonly_unsigned);
    shortvec_len(keys.len(), &mut out);
    for k in &keys {
        out.extend_from_slice(&k.pubkey.0);
    }
    out.extend_from_slice(recent_blockhash);
    shortvec_len(ixs.len(), &mut out);
    for ix in ixs {
        out.push(index_of(&ix.program_id)?);
        shortvec_len(ix.accounts.len(), &mut out);
        for m in &ix.accounts {
            out.push(index_of(&m.pubkey)?);
        }
        shortvec_len(ix.data.len(), &mut out);
        out.extend_from_slice(&ix.data);
    }
    Ok(CompiledMessage {
        bytes: out,
        num_required_signatures,
        account_keys: keys.into_iter().map(|k| k.pubkey).collect(),
    })
}

/// Wrap a compiled message as an unsigned transaction: a shortvec of
/// zero-filled 64-byte signature slots followed by the message bytes.
pub fn unsigned_tx_base64(msg: &CompiledMessage) -> String {
    let n = msg.num_required_signatures as usize;
    let mut out = Vec::with_capacity(1 + n * 64 + msg.bytes.len());
    shortvec_len(n, &mut out);
    out.extend(std::iter::repeat(0u8).take(n * 64));
    out.extend_from_slice(&msg.bytes);
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// A parsed legacy message, for the xray decoder.
pub struct ParsedMessage {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<ParsedInstruction>,
}

pub struct ParsedInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

/// Parse an unsigned or signed base64 transaction. Versioned (v0) payloads are
/// detected by the high bit of the first message byte and rejected with a
/// clear error; the proposer suite emits legacy messages only.
pub fn parse_tx_base64(b64: &str) -> Result<ParsedMessage, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("invalid base64: {e}"))?;
    let (nsigs, mut pos) = shortvec_read(&raw)?;
    pos += nsigs * 64;
    if raw.len() < pos + 3 {
        return Err("truncated transaction".into());
    }
    if raw[pos] & 0x80 != 0 {
        return Err("versioned (v0) message: not supported by this decoder yet".into());
    }
    let num_required_signatures = raw[pos];
    let num_readonly_signed = raw[pos + 1];
    let num_readonly_unsigned = raw[pos + 2];
    pos += 3;
    let (nkeys, used) = shortvec_read(&raw[pos..])?;
    pos += used;
    let mut account_keys = Vec::with_capacity(nkeys);
    for _ in 0..nkeys {
        if raw.len() < pos + 32 {
            return Err("truncated account keys".into());
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw[pos..pos + 32]);
        account_keys.push(Pubkey(b));
        pos += 32;
    }
    if raw.len() < pos + 32 {
        return Err("truncated blockhash".into());
    }
    let mut recent_blockhash = [0u8; 32];
    recent_blockhash.copy_from_slice(&raw[pos..pos + 32]);
    pos += 32;
    let (nixs, used) = shortvec_read(&raw[pos..])?;
    pos += used;
    let mut instructions = Vec::with_capacity(nixs);
    for _ in 0..nixs {
        if raw.len() < pos + 1 {
            return Err("truncated instruction".into());
        }
        let pidx = raw[pos] as usize;
        pos += 1;
        let (nacc, used) = shortvec_read(&raw[pos..])?;
        pos += used;
        let mut accounts = Vec::with_capacity(nacc);
        for _ in 0..nacc {
            let i = *raw.get(pos).ok_or("truncated account index")? as usize;
            accounts.push(
                *account_keys
                    .get(i)
                    .ok_or("account index out of range")?,
            );
            pos += 1;
        }
        let (dlen, used) = shortvec_read(&raw[pos..])?;
        pos += used;
        if raw.len() < pos + dlen {
            return Err("truncated instruction data".into());
        }
        let data = raw[pos..pos + dlen].to_vec();
        pos += dlen;
        let program_id = *account_keys
            .get(pidx)
            .ok_or("program index out of range")?;
        instructions.push(ParsedInstruction { program_id, accounts, data });
    }
    Ok(ParsedMessage {
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        account_keys,
        recent_blockhash,
        instructions,
    })
}
