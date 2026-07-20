# Quorum

A Squads v4 native treasury desk for ZeroClaw agents. The agent is a
proposer, never a spender.

Three WIT tool plugins on one shared pure Rust core:

| Component | Tier | One line |
| --- | --- | --- |
| `squads-propose` | T1 | Draft multisig payment proposals as unsigned transactions: address book recipients, mint allowlist, per proposal caps. Holds no keys. |
| `squads-watch` | T0 | Treasury heartbeat for SOP schedules: pending proposals, approval counts, outcomes since a cursor. |
| `tx-xray` | T0 | Decode and simulate any unsigned transaction into a truthful capped receipt. Approve what it does, not what the agent says. |

## The thesis

Every agent payments design eventually asks one question: how do you let an
untrusted text generator direct money? Session keys answer it with caps the
model can try to talk around. Durable nonces answer it by keeping fragile
transactions alive longer. Quorum answers it structurally: the model can only
file proposals into a Squads v4 multisig, where M of N humans approve on
their phones and the program executes with a fresh blockhash whenever they
are ready.

That single design choice collapses the two hardest problems in this bounty
at once. Prompt injection cannot spend, because proposing is not spending and
the agent's key (in the hardened mode) carries the Initiate permission only,
which the Squads program itself prevents from voting or executing. And
blockhash expiry in approval queues disappears, because the proposal is the
durable object. Durable nonces treat the symptom; proposals remove the
disease.

`tx-xray` closes the remaining gap: humans should not approve based on the
agent's own description of its work. The receipt members read is derived
from the transaction bytes and an RPC simulation, so a proposal that claims
to be a refund and is actually a delegate approval gets flagged before
anyone taps approve.

## Fail closed, everywhere

- No mint allowlist or address book in config: the proposer refuses to run.
- Raw base58 recipients: rejected even when valid, with zero network calls.
- Amount over the per proposal cap: rejected with the cap in the message.
- Unknown program in a transaction under inspection: flagged, never guessed.
- Missing config, malformed args, undecodable accounts: structured refusals.
- Every receipt hard capped near 200 tokens; truncation is loud.

The tests enforce these as behavior, not intentions: policy rejections are
asserted to make zero RPC calls, and the happy path is verified by re-parsing
the produced transaction and checking Squads instruction bytes, PDAs, and
the embedded amount.

## Engineering notes

`quorum-core` (published on crates.io as `quorum-squads-core`; the plain name
was taken by an unrelated project) is a from scratch, wasm32-wasip2 friendly
Solana substrate: no
solana-sdk, no async runtime. Base58, sha256 PDAs with a real ed25519
off-curve check, compact-u16 legacy message compilation, the Squads v4
SmallVec TransactionMessage wire format, Anchor discriminators, borsh
account decoders, SPL and Token-2022 instruction builders, exact integer
amount parsing, a transport trait with a deterministic mock, and receipt
shaping.

Ground truth was vendored, not guessed. Instruction argument structs,
account orders, PDA seeds, and the SmallVec length encoding were read out of
the Squads v4 program source. Discriminators are re-derived in the test suite
from a real sha256 of the Squads v4 instruction and account names; base58
constants and PDA vectors match an independent pure Python implementation
(sha256 plus a from scratch ed25519 decompression check), so the Rust is
verified against something it did not produce. The final proof is a fixture
test that pins the encoders byte-for-byte against a real Squads v4 proposal —
`VaultTransactionCreate` + `ProposalCreate` — produced on chain by the
official `@sqds/multisig` client (the library the Squads app itself runs) and
captured from devnet. It runs offline in every `cargo test`.

## Roadmap: the only honest T2

Squads v4 ships on chain SpendingLimits: per key, per mint, per period
allowances enforced by the program itself. An agent key granted only a
SpendingLimit can autonomously pay up to the limit and is stopped by the
chain, not by plugin code an injected model might route around. That is the
next component, and it is the only T2 design we know of where the cap
survives total model compromise.

## License

MIT
