# Draft PR body — zeroclaw-labs/zeroclaw-plugins

Open from `big14way/zeroclaw-plugins:feat/quorum-squads-suite` → `zeroclaw-labs/zeroclaw-plugins:main`, as a **draft**.
Do not open until quorum-squads-core 0.1.0 is on crates.io and per-plugin
Cargo.locks are committed (CI builds with `--locked`).

---

Title: `feat(plugins): Quorum — a Squads v4 treasury suite (squads-propose, squads-watch, tx-xray)`

## What this adds

Three tool plugins that turn a ZeroClaw agent into a treasury desk that
**proposes and never spends**. Instead of giving the model keys plus caps it
can talk its way around, the agent files proposals into a Squads v4 multisig;
M-of-N humans approve on their phones and the program executes with a fresh
blockhash whenever they're ready. Prompt injection cannot spend, because
proposing is not spending; approval-queue blockhash expiry disappears, because
the proposal is the durable object.

| Plugin | Tier | One line |
| --- | --- | --- |
| `squads-propose` | T1 | Draft multisig payment proposals as unsigned transactions: address-book recipients, mint allowlist, per-proposal caps. Holds no keys. |
| `squads-watch` | T0 | Treasury heartbeat for SOP schedules: pending proposals, approval counts, outcomes since a cursor. |
| `tx-xray` | T0 | Decode + simulate any unsigned transaction into a truthful capped receipt. Approve what it does, not what the agent says. |

All three follow the `redact-text` layout: pure host-testable core, thin
`#[cfg(target_family = "wasm")]` shim, structured logging via `log-record`,
standalone `[workspace]` crates. The shared Solana/Squads substrate
(base58, PDAs with real ed25519 off-curve checks, legacy message compilation,
Squads v4 SmallVec wire format, borsh account decoders, SPL/Token-2022
builders) is published as
[`quorum-squads-core`](https://crates.io/crates/quorum-squads-core) — no
solana-sdk, no async runtime, wasm32-wasip2 friendly, usable by any future
Solana plugin here.

## Permissions

- `squads-propose`, `squads-watch`: `http_client` (JSON-RPC to the configured
  endpoint) + `config_read`. Nothing else.
- `tx-xray`: same two; with `simulate=false` it decodes purely and needs no
  network at all.
- No plugin holds, receives, or requests key material. In hardened mode the
  operator gives the agent's creator key the Squads **Initiate-only**
  permission, so even total key theft yields spam proposals at worst.

## Validation

- Host tests: `cargo test --locked` green in all three plugins + the core
  (50 tests, no network; policy rejections asserted to make zero RPC calls;
  the happy path re-parses the produced transaction and checks Squads
  instruction bytes, PDAs, and the embedded amount).
- `cargo build --locked --target wasm32-wasip2 --release` clean for all three;
  components export exactly `zeroclaw:plugin/{plugin-info,tool}@0.1.0`
  (verified with wasm-tools) against the vendored `wit/v0`.
- `tools/build-registry.py --check-metadata` passes: three
  `pending unpublished source` entries, no drift.
- Ground truth: Anchor discriminators are re-derived in-test from a real
  sha256 of the Squads v4 instruction/account names (`global:…` / `account:…`);
  base58 constants and PDA vectors match an independent pure-Python
  implementation. A fixture test pins the encoders byte-for-byte against a
  real `VaultTransactionCreate` + `ProposalCreate` transaction produced on
  chain by the official `@sqds/multisig` client (the library the Squads app
  runs), captured from devnet — it runs offline in every `cargo test`.
- Adversarial hardening: the suite passed a multi-agent audit (find →
  independent verify) covering the Squads/SPL wire encoding, the fail-closed
  policy, wasm trap-safety on untrusted input, and receipt integrity; the
  shared core is `quorum-squads-core` 0.1.1. Untrusted transactions cannot
  trap the decoder, every authority-moving or unknown token instruction is
  flagged, and hazard flags are rendered before any truncation.

## Rollback

Delete `plugins/squads-propose`, `plugins/squads-watch`, `plugins/tx-xray`.
No host changes, no wit changes, no tool/script changes; registry entries are
generated. Nothing else in the repo references these directories.

## Question for maintainers

Happy to split this into three PRs (one per plugin) if you prefer reviewing
them independently — they share only the crates.io core dependency. Kept as
one because the suite is designed and tested as a unit.
