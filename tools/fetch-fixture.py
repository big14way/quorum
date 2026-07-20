#!/usr/bin/env python3
"""Capture a Squads app proposal-creation transaction as a test fixture.

Usage:
    python3 tools/fetch-fixture.py <signature> [rpc_url]

Fetches the transaction (base64) via getTransaction and writes
crates/quorum-core/tests/fixtures/mainnet_proposal.json. Pure stdlib.
"""

import json
import pathlib
import sys
import urllib.request

def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    signature = sys.argv[1]
    rpc_url = sys.argv[2] if len(sys.argv) > 2 else "https://api.mainnet-beta.solana.com"

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [signature, {
            "encoding": "base64",
            "maxSupportedTransactionVersion": 0,
            "commitment": "confirmed",
        }],
    }).encode()
    req = urllib.request.Request(
        rpc_url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        reply = json.load(resp)

    result = reply.get("result")
    if not result:
        sys.exit(f"transaction not found: {reply.get('error')}")
    tx_b64, enc = result["transaction"]
    assert enc == "base64", enc
    version = result.get("version", "legacy")

    # The multisig is account 0 of the vault_transaction_create instruction;
    # rather than decode here, record what the operator knows and let the
    # Rust test assert the rest.
    multisig = input("multisig address (from the Squads app): ").strip()

    out = {
        "signature": signature,
        "rpc_url": rpc_url,
        "tx_version": version,
        "tx_base64": tx_b64,
        "multisig": multisig,
        "slot": result.get("slot"),
    }
    dest = pathlib.Path(__file__).resolve().parent.parent / \
        "crates/quorum-core/tests/fixtures/mainnet_proposal.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {dest} (tx version: {version})")
    if version != "legacy":
        print("NOTE: transaction is v0 — the fixture test will fail loudly; "
              "record the finding in PLAN.md before changing any code.")

if __name__ == "__main__":
    main()
