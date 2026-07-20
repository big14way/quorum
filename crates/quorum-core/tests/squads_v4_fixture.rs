//! The single highest-value test in the project: pin the encoders to a REAL
//! Squads v4 proposal produced by the official `@sqds/multisig` client — the
//! same library the Squads app runs — captured live from devnet.
//!
//! The fixture (tests/fixtures/squads_v4_proposal.json) holds the base64 of a
//! transaction that ran VaultTransactionCreate + ProposalCreate against the
//! Squads v4 program (SQDS4ep…) on a real 2-of-3 multisig. This test re-derives
//! every derivable byte with our own encoders and asserts exact equality:
//! discriminators, borsh args, account ordering, and both PDAs. It is fully
//! offline and runs in every plain `cargo test`.
//!
//! To refresh or move to mainnet: generate a proposal (scratch gen.mjs, or the
//! app), then fetch the transaction base64 (tools/fetch-fixture.py) and replace
//! the fixture. A v0 message would fail the parse loudly — a real signal, since
//! squads-propose emits legacy messages and tx-xray rejects v0 by design.

use quorum_core::message::parse_tx_base64;
use quorum_core::pubkey::Pubkey;
use quorum_core::squads::{
    decode_transaction_message, decode_vault_transaction_create_args, proposal_create_ix,
    proposal_pda, transaction_pda, vault_transaction_create_ix, DISC_PROPOSAL_CREATE,
    DISC_VAULT_TRANSACTION_CREATE, SQUADS_PROGRAM,
};

#[test]
fn squads_v4_proposal_fixture_pins_encoders() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/squads_v4_proposal.json"
    );
    let raw =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("fixture missing at {path}: {e}"));
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture is not JSON");
    let tx_b64 = fixture["tx_base64"]
        .as_str()
        .expect("fixture missing tx_base64");
    let multisig = Pubkey::from_base58(
        fixture["multisig"]
            .as_str()
            .expect("fixture missing multisig"),
    )
    .expect("fixture multisig not base58");

    let parsed = parse_tx_base64(tx_b64)
        .expect("captured tx did not parse as a legacy message; if it is v0, record that here");

    let vtc = parsed
        .instructions
        .iter()
        .find(|ix| {
            ix.program_id == SQUADS_PROGRAM && ix.data.starts_with(&DISC_VAULT_TRANSACTION_CREATE)
        })
        .expect("no vault_transaction_create instruction in captured tx");
    let pc = parsed
        .instructions
        .iter()
        .find(|ix| ix.program_id == SQUADS_PROGRAM && ix.data.starts_with(&DISC_PROPOSAL_CREATE))
        .expect("no proposal_create instruction in captured tx");

    // The app's inner transaction message must decode with our SmallVec
    // reader: this validates the wire format against bytes we did not write.
    let (vault_index, message, memo) =
        decode_vault_transaction_create_args(&vtc.data).expect("vtc args decode");
    decode_transaction_message(&message).expect("inner transaction message decode");

    // The proposal index is the u64 after the discriminator.
    let index = u64::from_le_bytes(pc.data[8..16].try_into().unwrap());

    // PDAs must reproduce from (multisig, index) alone.
    let (expected_tx_pda, _) = transaction_pda(&multisig, index);
    let (expected_prop_pda, _) = proposal_pda(&multisig, index);
    assert_eq!(vtc.accounts[0], multisig, "vtc account 0 is the multisig");
    assert_eq!(vtc.accounts[1], expected_tx_pda, "transaction PDA");
    assert_eq!(pc.accounts[0], multisig, "pc account 0 is the multisig");
    assert_eq!(pc.accounts[1], expected_prop_pda, "proposal PDA");

    // Re-encode both instructions with our builders from decoded inputs and
    // captured account keys; every byte must match the app's bytes.
    let creator = vtc.accounts[2];
    let rent_payer = vtc.accounts[3];
    let ours = vault_transaction_create_ix(
        &multisig,
        &vtc.accounts[1],
        &creator,
        &rent_payer,
        vault_index,
        0,
        &message,
        memo,
    );
    assert_eq!(ours.data, vtc.data, "vault_transaction_create data bytes");
    let our_keys: Vec<Pubkey> = ours.accounts.iter().map(|m| m.pubkey).collect();
    assert_eq!(our_keys, vtc.accounts, "vault_transaction_create accounts");

    // The app may create the proposal live (draft = false) — read the flag
    // from the captured bytes so the assertion is byte-driven, not assumed.
    let draft = pc.data[16] == 1;
    let ours_pc = proposal_create_ix(
        &multisig,
        &pc.accounts[1],
        &pc.accounts[2],
        &pc.accounts[3],
        index,
        draft,
    );
    assert_eq!(ours_pc.data, pc.data, "proposal_create data bytes");
    let our_pc_keys: Vec<Pubkey> = ours_pc.accounts.iter().map(|m| m.pubkey).collect();
    assert_eq!(our_pc_keys, pc.accounts, "proposal_create accounts");
}
