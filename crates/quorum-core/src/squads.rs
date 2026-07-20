//! Squads v4 encoding and decoding, matched byte for byte to the program
//! source at Squads-Protocol/v4 (programs/squads_multisig_program).
//!
//! Facts vendored from source, not guessed:
//!   seeds:      SEED_PREFIX = b"multisig", SEED_MULTISIG = b"multisig",
//!               SEED_TRANSACTION = b"transaction", SEED_PROPOSAL = b"proposal",
//!               SEED_VAULT = b"vault"
//!   multisig:   ["multisig", "multisig", create_key]
//!   vault:      ["multisig", multisig, "vault", vault_index_u8_le]
//!   tx:         ["multisig", multisig, "transaction", index_u64_le]
//!   proposal:   ["multisig", multisig, "transaction", index_u64_le, "proposal"]
//!   args:       VaultTransactionCreateArgs { vault_index: u8, ephemeral_signers: u8,
//!               transaction_message: Vec<u8>, memo: Option<String> }
//!               ProposalCreateArgs { transaction_index: u64, draft: bool }
//!   wire:       TransactionMessage { num_signers: u8, num_writable_signers: u8,
//!               num_writable_non_signers: u8, account_keys: SmallVec<u8, Pubkey>,
//!               instructions: SmallVec<u8, CompiledInstruction>,
//!               address_table_lookups: SmallVec<u8, Lookup> }
//!               CompiledInstruction { program_id_index: u8,
//!               account_indexes: SmallVec<u8, u8>, data: SmallVec<u16, u8> }
//!   perms:      Initiate = 1, Vote = 2, Execute = 4

use crate::message::{AccountMeta, Instruction};
use crate::pubkey::{find_program_address, Pubkey};

/// SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf
pub const SQUADS_PROGRAM: Pubkey = Pubkey([
    6, 129, 196, 206, 71, 226, 35, 104, 184, 177, 85, 94, 200, 135, 175, 9, 46, 252, 126, 251, 182,
    108, 163, 245, 47, 191, 104, 212, 172, 156, 183, 168,
]);
/// System program: 32 zero bytes.
pub const SYSTEM_PROGRAM: Pubkey = Pubkey([0u8; 32]);

pub const SEED_PREFIX: &[u8] = b"multisig";
pub const SEED_MULTISIG: &[u8] = b"multisig";
pub const SEED_TRANSACTION: &[u8] = b"transaction";
pub const SEED_PROPOSAL: &[u8] = b"proposal";
pub const SEED_VAULT: &[u8] = b"vault";

/// Anchor instruction discriminators: sha256("global:<name>")[..8].
pub const DISC_VAULT_TRANSACTION_CREATE: [u8; 8] = [48, 250, 78, 168, 208, 226, 218, 211];
pub const DISC_PROPOSAL_CREATE: [u8; 8] = [220, 60, 73, 224, 30, 108, 79, 159];
pub const DISC_PROPOSAL_APPROVE: [u8; 8] = [144, 37, 164, 136, 188, 216, 42, 248];
pub const DISC_SPENDING_LIMIT_USE: [u8; 8] = [16, 57, 130, 127, 193, 20, 155, 134];

/// Anchor account discriminators: sha256("account:<Name>")[..8].
pub const ACCT_MULTISIG: [u8; 8] = [224, 116, 121, 186, 68, 161, 79, 236];
pub const ACCT_PROPOSAL: [u8; 8] = [26, 94, 189, 187, 116, 136, 53, 33];

pub const PERM_INITIATE: u8 = 1;
pub const PERM_VOTE: u8 = 2;
pub const PERM_EXECUTE: u8 = 4;

// PDAs

pub fn multisig_pda(create_key: &Pubkey) -> (Pubkey, u8) {
    find_program_address(
        &[SEED_PREFIX, SEED_MULTISIG, &create_key.0],
        &SQUADS_PROGRAM,
    )
}

pub fn vault_pda(multisig: &Pubkey, vault_index: u8) -> (Pubkey, u8) {
    find_program_address(
        &[
            SEED_PREFIX,
            &multisig.0,
            SEED_VAULT,
            &vault_index.to_le_bytes(),
        ],
        &SQUADS_PROGRAM,
    )
}

pub fn transaction_pda(multisig: &Pubkey, transaction_index: u64) -> (Pubkey, u8) {
    find_program_address(
        &[
            SEED_PREFIX,
            &multisig.0,
            SEED_TRANSACTION,
            &transaction_index.to_le_bytes(),
        ],
        &SQUADS_PROGRAM,
    )
}

pub fn proposal_pda(multisig: &Pubkey, transaction_index: u64) -> (Pubkey, u8) {
    find_program_address(
        &[
            SEED_PREFIX,
            &multisig.0,
            SEED_TRANSACTION,
            &transaction_index.to_le_bytes(),
            SEED_PROPOSAL,
        ],
        &SQUADS_PROGRAM,
    )
}

// TransactionMessage wire format

fn small_vec_u8_len(len: usize, out: &mut Vec<u8>) -> Result<(), String> {
    let l = u8::try_from(len).map_err(|_| "small vec u8 overflow")?;
    out.push(l);
    Ok(())
}

fn small_vec_u16_len(len: usize, out: &mut Vec<u8>) -> Result<(), String> {
    let l = u16::try_from(len).map_err(|_| "small vec u16 overflow")?;
    out.extend_from_slice(&l.to_le_bytes());
    Ok(())
}

/// Compile a list of inner instructions into the Squads TransactionMessage
/// wire bytes. `vault` is the sole signing authority of the inner message;
/// the program signs for it via CPI with the vault seeds at execution time.
///
/// Key ordering mirrors the runtime convention the program indexes against:
/// writable signers, readonly signers, writable non-signers, readonly
/// non-signers, with program ids as readonly non-signers.
pub fn compile_transaction_message(vault: &Pubkey, ixs: &[Instruction]) -> Result<Vec<u8>, String> {
    struct Entry {
        pk: Pubkey,
        signer: bool,
        writable: bool,
    }
    let mut entries: Vec<Entry> = vec![Entry {
        pk: *vault,
        signer: true,
        writable: false,
    }];
    {
        let mut upsert = |pk: Pubkey, signer: bool, writable: bool| {
            if let Some(e) = entries.iter_mut().find(|e| e.pk == pk) {
                e.signer |= signer;
                e.writable |= writable;
            } else {
                entries.push(Entry {
                    pk,
                    signer,
                    writable,
                });
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
    }
    let mut ordered: Vec<&Entry> = Vec::with_capacity(entries.len());
    for pass in 0..4 {
        for e in &entries {
            let keep = match pass {
                0 => e.signer && e.writable,
                1 => e.signer && !e.writable,
                2 => !e.signer && e.writable,
                _ => !e.signer && !e.writable,
            };
            if keep {
                ordered.push(e);
            }
        }
    }
    let num_signers = ordered.iter().filter(|e| e.signer).count();
    let num_writable_signers = ordered.iter().filter(|e| e.signer && e.writable).count();
    let num_writable_non_signers = ordered.iter().filter(|e| !e.signer && e.writable).count();
    let index_of = |pk: &Pubkey| -> Result<u8, String> {
        ordered
            .iter()
            .position(|e| &e.pk == pk)
            .map(|i| i as u8)
            .ok_or_else(|| format!("unindexed inner key {pk}"))
    };

    let mut out = Vec::with_capacity(128);
    out.push(u8::try_from(num_signers).map_err(|_| "too many signers")?);
    out.push(u8::try_from(num_writable_signers).map_err(|_| "too many writable signers")?);
    out.push(u8::try_from(num_writable_non_signers).map_err(|_| "too many writable accounts")?);
    small_vec_u8_len(ordered.len(), &mut out)?;
    for e in &ordered {
        out.extend_from_slice(&e.pk.0);
    }
    small_vec_u8_len(ixs.len(), &mut out)?;
    for ix in ixs {
        out.push(index_of(&ix.program_id)?);
        small_vec_u8_len(ix.accounts.len(), &mut out)?;
        for m in &ix.accounts {
            out.push(index_of(&m.pubkey)?);
        }
        small_vec_u16_len(ix.data.len(), &mut out)?;
        out.extend_from_slice(&ix.data);
    }
    // address_table_lookups: none.
    small_vec_u8_len(0, &mut out)?;
    Ok(out)
}

// Borsh arg encoding helpers (little endian throughout).

fn borsh_vec_u8(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn borsh_option_string(s: &Option<String>, out: &mut Vec<u8>) {
    match s {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
        }
    }
}

/// Build the vault_transaction_create instruction. Account order from source:
/// multisig (writable), transaction PDA (writable), creator (signer),
/// rent_payer (signer, writable), system_program.
pub fn vault_transaction_create_ix(
    multisig: &Pubkey,
    transaction: &Pubkey,
    creator: &Pubkey,
    rent_payer: &Pubkey,
    vault_index: u8,
    ephemeral_signers: u8,
    transaction_message: &[u8],
    memo: Option<String>,
) -> Instruction {
    let mut data = Vec::with_capacity(16 + transaction_message.len());
    data.extend_from_slice(&DISC_VAULT_TRANSACTION_CREATE);
    data.push(vault_index);
    data.push(ephemeral_signers);
    borsh_vec_u8(transaction_message, &mut data);
    borsh_option_string(&memo, &mut data);
    Instruction {
        program_id: SQUADS_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*multisig, false),
            AccountMeta::writable(*transaction, false),
            AccountMeta::readonly(*creator, true),
            AccountMeta::writable(*rent_payer, true),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
        ],
        data,
    }
}

/// Build the proposal_create instruction. Account order from source:
/// multisig (readonly), proposal PDA (writable), creator (signer),
/// rent_payer (signer, writable), system_program.
pub fn proposal_create_ix(
    multisig: &Pubkey,
    proposal: &Pubkey,
    creator: &Pubkey,
    rent_payer: &Pubkey,
    transaction_index: u64,
    draft: bool,
) -> Instruction {
    let mut data = Vec::with_capacity(18);
    data.extend_from_slice(&DISC_PROPOSAL_CREATE);
    data.extend_from_slice(&transaction_index.to_le_bytes());
    data.push(u8::from(draft));
    Instruction {
        program_id: SQUADS_PROGRAM,
        accounts: vec![
            AccountMeta::readonly(*multisig, false),
            AccountMeta::writable(*proposal, false),
            AccountMeta::readonly(*creator, true),
            AccountMeta::writable(*rent_payer, true),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
        ],
        data,
    }
}

// Account decoders

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        // Overflow-safe: `self.pos + n` would wrap a 32-bit usize on the
        // wasm32 target and defeat the bounds check, so a length field like
        // 0xFFFFFFFF from an untrusted transaction would slip through and
        // panic on the slice (a hard wasm trap). Compare against the
        // remaining bytes instead, which cannot overflow.
        if n > self.buf.len() - self.pos {
            return Err("truncated account data".into());
        }
        let end = self.pos + n;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn pubkey(&mut self) -> Result<Pubkey, String> {
        let s = self.take(32)?;
        let mut b = [0u8; 32];
        b.copy_from_slice(s);
        Ok(Pubkey(b))
    }
    fn vec_pubkey(&mut self) -> Result<Vec<Pubkey>, String> {
        let n = self.u32()? as usize;
        if n > 4096 {
            return Err("unreasonable vec length".into());
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.pubkey()?);
        }
        Ok(v)
    }
}

#[derive(Clone, Debug)]
pub struct Member {
    pub key: Pubkey,
    pub permissions: u8,
}

#[derive(Clone, Debug)]
pub struct MultisigState {
    pub create_key: Pubkey,
    pub config_authority: Pubkey,
    pub threshold: u16,
    pub time_lock: u32,
    pub transaction_index: u64,
    pub stale_transaction_index: u64,
    pub rent_collector: Option<Pubkey>,
    pub bump: u8,
    pub members: Vec<Member>,
}

pub fn decode_multisig(data: &[u8]) -> Result<MultisigState, String> {
    let mut r = Reader::new(data);
    if r.take(8)? != ACCT_MULTISIG {
        return Err("not a Squads Multisig account".into());
    }
    let create_key = r.pubkey()?;
    let config_authority = r.pubkey()?;
    let threshold = r.u16()?;
    let time_lock = r.u32()?;
    let transaction_index = r.u64()?;
    let stale_transaction_index = r.u64()?;
    let rent_collector = match r.u8()? {
        0 => None,
        1 => Some(r.pubkey()?),
        _ => return Err("bad option tag".into()),
    };
    let bump = r.u8()?;
    let n = r.u32()? as usize;
    if n > 256 {
        return Err("unreasonable member count".into());
    }
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        let key = r.pubkey()?;
        let permissions = r.u8()?;
        members.push(Member { key, permissions });
    }
    Ok(MultisigState {
        create_key,
        config_authority,
        threshold,
        time_lock,
        transaction_index,
        stale_transaction_index,
        rent_collector,
        bump,
        members,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Draft(i64),
    Active(i64),
    Rejected(i64),
    Approved(i64),
    Executing,
    Executed(i64),
    Cancelled(i64),
}

impl ProposalStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ProposalStatus::Draft(_) => "Draft",
            ProposalStatus::Active(_) => "Active",
            ProposalStatus::Rejected(_) => "Rejected",
            ProposalStatus::Approved(_) => "Approved",
            ProposalStatus::Executing => "Executing",
            ProposalStatus::Executed(_) => "Executed",
            ProposalStatus::Cancelled(_) => "Cancelled",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProposalState {
    pub multisig: Pubkey,
    pub transaction_index: u64,
    pub status: ProposalStatus,
    pub bump: u8,
    pub approved: Vec<Pubkey>,
    pub rejected: Vec<Pubkey>,
    pub cancelled: Vec<Pubkey>,
}

pub fn decode_proposal(data: &[u8]) -> Result<ProposalState, String> {
    let mut r = Reader::new(data);
    if r.take(8)? != ACCT_PROPOSAL {
        return Err("not a Squads Proposal account".into());
    }
    let multisig = r.pubkey()?;
    let transaction_index = r.u64()?;
    let status = match r.u8()? {
        0 => ProposalStatus::Draft(r.i64()?),
        1 => ProposalStatus::Active(r.i64()?),
        2 => ProposalStatus::Rejected(r.i64()?),
        3 => ProposalStatus::Approved(r.i64()?),
        4 => ProposalStatus::Executing,
        5 => ProposalStatus::Executed(r.i64()?),
        6 => ProposalStatus::Cancelled(r.i64()?),
        _ => return Err("unknown proposal status".into()),
    };
    let bump = r.u8()?;
    let approved = r.vec_pubkey()?;
    let rejected = r.vec_pubkey()?;
    let cancelled = r.vec_pubkey()?;
    Ok(ProposalState {
        multisig,
        transaction_index,
        status,
        bump,
        approved,
        rejected,
        cancelled,
    })
}

/// Encode a Multisig account body for tests and fixtures.
pub fn encode_multisig_for_test(m: &MultisigState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ACCT_MULTISIG);
    out.extend_from_slice(&m.create_key.0);
    out.extend_from_slice(&m.config_authority.0);
    out.extend_from_slice(&m.threshold.to_le_bytes());
    out.extend_from_slice(&m.time_lock.to_le_bytes());
    out.extend_from_slice(&m.transaction_index.to_le_bytes());
    out.extend_from_slice(&m.stale_transaction_index.to_le_bytes());
    match &m.rent_collector {
        None => out.push(0),
        Some(p) => {
            out.push(1);
            out.extend_from_slice(&p.0);
        }
    }
    out.push(m.bump);
    out.extend_from_slice(&(m.members.len() as u32).to_le_bytes());
    for mem in &m.members {
        out.extend_from_slice(&mem.key.0);
        out.push(mem.permissions);
    }
    out
}

/// Encode a Proposal account body for tests and fixtures.
pub fn encode_proposal_for_test(p: &ProposalState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ACCT_PROPOSAL);
    out.extend_from_slice(&p.multisig.0);
    out.extend_from_slice(&p.transaction_index.to_le_bytes());
    match &p.status {
        ProposalStatus::Draft(t) => {
            out.push(0);
            out.extend_from_slice(&t.to_le_bytes());
        }
        ProposalStatus::Active(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_le_bytes());
        }
        ProposalStatus::Rejected(t) => {
            out.push(2);
            out.extend_from_slice(&t.to_le_bytes());
        }
        ProposalStatus::Approved(t) => {
            out.push(3);
            out.extend_from_slice(&t.to_le_bytes());
        }
        ProposalStatus::Executing => out.push(4),
        ProposalStatus::Executed(t) => {
            out.push(5);
            out.extend_from_slice(&t.to_le_bytes());
        }
        ProposalStatus::Cancelled(t) => {
            out.push(6);
            out.extend_from_slice(&t.to_le_bytes());
        }
    }
    out.push(p.bump);
    let vecpk = |v: &Vec<Pubkey>, out: &mut Vec<u8>| {
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        for k in v {
            out.extend_from_slice(&k.0);
        }
    };
    vecpk(&p.approved, &mut out);
    vecpk(&p.rejected, &mut out);
    vecpk(&p.cancelled, &mut out);
    out
}

// Inner message decoding, for tx-xray.

#[derive(Clone, Debug)]
pub struct InnerInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct InnerMessage {
    pub num_signers: u8,
    pub num_writable_signers: u8,
    pub num_writable_non_signers: u8,
    pub account_keys: Vec<Pubkey>,
    pub instructions: Vec<InnerInstruction>,
    pub lookups: u8,
}

/// Decode the Squads TransactionMessage wire bytes back into keys and
/// instructions, the mirror of `compile_transaction_message`.
pub fn decode_transaction_message(bytes: &[u8]) -> Result<InnerMessage, String> {
    let mut r = Reader::new(bytes);
    let num_signers = r.u8()?;
    let num_writable_signers = r.u8()?;
    let num_writable_non_signers = r.u8()?;
    let nkeys = r.u8()? as usize;
    let mut account_keys = Vec::with_capacity(nkeys);
    for _ in 0..nkeys {
        account_keys.push(r.pubkey()?);
    }
    let nixs = r.u8()? as usize;
    let mut instructions = Vec::with_capacity(nixs);
    for _ in 0..nixs {
        let pidx = r.u8()? as usize;
        let nacc = r.u8()? as usize;
        let mut accounts = Vec::with_capacity(nacc);
        for _ in 0..nacc {
            let i = r.u8()? as usize;
            accounts.push(
                *account_keys
                    .get(i)
                    .ok_or("inner account index out of range")?,
            );
        }
        let dlen = r.u16()? as usize;
        let data = r.take(dlen)?.to_vec();
        let program_id = *account_keys
            .get(pidx)
            .ok_or("inner program index out of range")?;
        instructions.push(InnerInstruction {
            program_id,
            accounts,
            data,
        });
    }
    let lookups = r.u8()?;
    Ok(InnerMessage {
        num_signers,
        num_writable_signers,
        num_writable_non_signers,
        account_keys,
        instructions,
        lookups,
    })
}

/// Split a vault_transaction_create instruction's data back into
/// (vault_index, transaction_message bytes, memo).
pub fn decode_vault_transaction_create_args(
    data: &[u8],
) -> Result<(u8, Vec<u8>, Option<String>), String> {
    if data.len() < 8 || data[..8] != DISC_VAULT_TRANSACTION_CREATE {
        return Err("not vault_transaction_create data".into());
    }
    let mut r = Reader::new(&data[8..]);
    let vault_index = r.u8()?;
    let _ephemeral = r.u8()?;
    let mlen = r.u32()? as usize;
    let message = r.take(mlen)?.to_vec();
    let memo = match r.u8()? {
        0 => None,
        1 => {
            let slen = r.u32()? as usize;
            let raw = r.take(slen)?;
            Some(String::from_utf8_lossy(raw).into_owned())
        }
        _ => return Err("bad memo option tag".into()),
    };
    Ok((vault_index, message, memo))
}
