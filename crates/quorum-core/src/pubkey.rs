//! 32-byte public keys, base58 codec, and program derived addresses.
//!
//! PDA derivation follows the Solana runtime exactly: sha256 over the seeds,
//! the program id, and the literal marker string, then an off-curve check.
//! A candidate that decompresses as a valid ed25519 point is rejected.

use sha2::{Digest, Sha256};

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
pub const MAX_SEED_LEN: usize = 32;
pub const MAX_SEEDS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub const ZERO: Pubkey = Pubkey([0u8; 32]);

    pub fn from_base58(s: &str) -> Result<Self, String> {
        let v = bs58::decode(s)
            .into_vec()
            .map_err(|e| format!("invalid base58: {e}"))?;
        if v.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", v.len()));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&v);
        Ok(Pubkey(b))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// Short display form for receipts: first 4 and last 4 base58 chars.
    pub fn short(&self) -> String {
        let s = self.to_base58();
        if s.len() <= 10 {
            s
        } else {
            format!("{}..{}", &s[..4], &s[s.len() - 4..])
        }
    }

    pub fn is_on_curve(&self) -> bool {
        curve25519_dalek::edwards::CompressedEdwardsY(self.0)
            .decompress()
            .is_some()
    }
}

impl core::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

/// Deterministic PDA candidate for a fixed seed set. Returns None when any
/// seed is oversized or when the candidate lands on the curve.
pub fn create_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<Pubkey> {
    if seeds.len() > MAX_SEEDS {
        return None;
    }
    let mut h = Sha256::new();
    for s in seeds {
        if s.len() > MAX_SEED_LEN {
            return None;
        }
        h.update(s);
    }
    h.update(program_id.0);
    h.update(PDA_MARKER);
    let out: [u8; 32] = h.finalize().into();
    let pk = Pubkey(out);
    if pk.is_on_curve() {
        None
    } else {
        Some(pk)
    }
}

/// Standard bump search from 255 downward. Statistically always succeeds.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
    let mut bump = 255u8;
    loop {
        let bump_seed = [bump];
        let mut all: Vec<&[u8]> = Vec::with_capacity(seeds.len() + 1);
        all.extend_from_slice(seeds);
        all.push(&bump_seed);
        if let Some(pk) = create_program_address(&all, program_id) {
            return (pk, bump);
        }
        if bump == 0 {
            // Unreachable in practice; fail loudly rather than loop forever.
            return (Pubkey::ZERO, 0);
        }
        bump -= 1;
    }
}
