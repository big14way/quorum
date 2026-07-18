//! SPL Token, Token-2022, associated token accounts, memo, and system
//! transfers. Amounts are parsed from decimal strings with exact integer
//! math; floats never touch money in this crate.

use crate::message::{AccountMeta, Instruction};
use crate::pubkey::{find_program_address, Pubkey};
use crate::squads::SYSTEM_PROGRAM;

/// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
pub const TOKEN_PROGRAM: Pubkey = Pubkey([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133,
    237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);
/// TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
pub const TOKEN22_PROGRAM: Pubkey = Pubkey([
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
]);
/// ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
pub const ATA_PROGRAM: Pubkey = Pubkey([
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
]);
/// MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
pub const MEMO_PROGRAM: Pubkey = Pubkey([
    5, 74, 83, 90, 153, 41, 33, 6, 77, 36, 232, 113, 96, 218, 56, 124, 124, 53, 181, 221, 188,
    146, 187, 129, 228, 31, 168, 64, 65, 5, 68, 141,
]);

/// Associated token account address for (owner, mint) under a token program.
pub fn derive_ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    find_program_address(&[&owner.0, &token_program.0, &mint.0], &ATA_PROGRAM).0
}

/// SPL Token TransferChecked (instruction tag 12): amount u64 LE + decimals.
pub fn transfer_checked_ix(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::writable(*source, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::writable(*destination, false),
            AccountMeta::readonly(*authority, true),
        ],
        data,
    }
}

/// Associated Token Program CreateIdempotent (instruction tag 1).
pub fn create_ata_idempotent_ix(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata = derive_ata(owner, mint, token_program);
    Instruction {
        program_id: ATA_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*payer, true),
            AccountMeta::writable(ata, false),
            AccountMeta::readonly(*owner, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
            AccountMeta::readonly(*token_program, false),
        ],
        data: vec![1u8],
    }
}

/// SPL Memo: utf8 payload, no accounts required.
pub fn memo_ix(text: &str) -> Instruction {
    Instruction {
        program_id: MEMO_PROGRAM,
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}

/// System program Transfer (enum index 2 as u32 LE) + lamports u64 LE.
pub fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*from, true),
            AccountMeta::writable(*to, false),
        ],
        data,
    }
}

/// Parse a decimal string like "12.5" into base units for a mint with the
/// given decimals. Exact integer math, fail closed on anything malformed,
/// negative, oversized, or with excess fractional digits.
pub fn parse_ui_amount(s: &str, decimals: u8) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty amount".into());
    }
    if s.starts_with('-') || s.starts_with('+') {
        return Err("amount must be a plain positive decimal".into());
    }
    let mut parts = s.splitn(2, '.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if int_part.is_empty() && frac_part.is_empty() {
        return Err("malformed amount".into());
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err("amount must contain only digits and one decimal point".into());
    }
    if frac_part.len() > decimals as usize {
        return Err(format!(
            "too many decimal places: mint has {decimals} decimals"
        ));
    }
    let scale: u128 = 10u128.pow(decimals as u32);
    let int_val: u128 = if int_part.is_empty() {
        0
    } else {
        int_part.parse::<u128>().map_err(|_| "amount too large")?
    };
    let mut frac_val: u128 = if frac_part.is_empty() {
        0
    } else {
        frac_part.parse::<u128>().map_err(|_| "amount too large")?
    };
    frac_val *= 10u128.pow((decimals as usize - frac_part.len()) as u32);
    let total = int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or("amount overflow")?;
    if total == 0 {
        return Err("amount must be greater than zero".into());
    }
    u64::try_from(total).map_err(|_| "amount exceeds u64 range".into())
}

/// Format base units back to a trimmed decimal string for receipts.
pub fn format_base_amount(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let scale = 10u64.pow(decimals as u32);
    let int_part = amount / scale;
    let frac_part = amount % scale;
    if frac_part == 0 {
        int_part.to_string()
    } else {
        let frac = format!("{:0width$}", frac_part, width = decimals as usize);
        let frac = frac.trim_end_matches('0');
        format!("{int_part}.{frac}")
    }
}
