import * as multisig from "@sqds/multisig";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionMessage,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import fs from "node:fs";

const { Permissions } = multisig.types;
const RPC = "https://api.devnet.solana.com";
const connection = new Connection(RPC, "confirmed");

function loadOrCreate(path) {
  if (fs.existsSync(path)) {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(path))));
  }
  const kp = Keypair.generate();
  fs.writeFileSync(path, JSON.stringify(Array.from(kp.secretKey)));
  return kp;
}

async function airdropTo(pubkey, sol) {
  for (let i = 0; i < 5; i++) {
    try {
      const sig = await connection.requestAirdrop(pubkey, sol * LAMPORTS_PER_SOL);
      await connection.confirmTransaction(sig, "confirmed");
      return;
    } catch (e) {
      console.log(`  airdrop attempt ${i + 1} failed: ${e.message}; retrying`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  throw new Error("airdrop failed after retries");
}

const creator = loadOrCreate("creator.json");
const createKey = loadOrCreate("createKey.json");
const member2 = loadOrCreate("member2.json");
const member3 = loadOrCreate("member3.json");

console.log("creator:", creator.publicKey.toBase58());

const NEEDED = 0.15 * LAMPORTS_PER_SOL;
let bal = await connection.getBalance(creator.publicKey);
console.log("creator balance:", bal / LAMPORTS_PER_SOL, "SOL");
if (bal < NEEDED) {
  console.log("insufficient balance; trying airdrop (may be rate-limited)...");
  try {
    await airdropTo(creator.publicKey, 1);
  } catch (e) {
    console.log("  airdrop unavailable:", e.message);
  }
  bal = await connection.getBalance(creator.publicKey);
  console.log("creator balance now:", bal / LAMPORTS_PER_SOL, "SOL");
  if (bal < NEEDED) {
    console.error(
      `\nNeed ~0.15 devnet SOL. Fund ${creator.publicKey.toBase58()} and re-run.`
    );
    process.exit(2);
  }
}

const [multisigPda] = multisig.getMultisigPda({ createKey: createKey.publicKey });
console.log("multisig PDA:", multisigPda.toBase58());

// Create the 2-of-3 multisig if it does not exist yet.
const existing = await connection.getAccountInfo(multisigPda);
if (!existing) {
  const programConfigPda = multisig.getProgramConfigPda({})[0];
  const programConfig =
    await multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda);
  const sig = await multisig.rpc.multisigCreateV2({
    connection,
    createKey,
    creator,
    multisigPda,
    configAuthority: null,
    timeLock: 0,
    threshold: 2,
    members: [
      { key: creator.publicKey, permissions: Permissions.all() },
      { key: member2.publicKey, permissions: Permissions.all() },
      { key: member3.publicKey, permissions: Permissions.all() },
    ],
    rentCollector: null,
    treasury: programConfig.treasury,
    sendOptions: { skipPreflight: false },
  });
  await connection.confirmTransaction(sig, "confirmed");
  console.log("multisig created:", sig);
} else {
  console.log("multisig already exists, reusing");
}

// Fund vault 0 so the inner transfer has lamports to move.
const [vaultPda] = multisig.getVaultPda({ multisigPda, index: 0 });
console.log("vault PDA:", vaultPda.toBase58());
const vaultBal = await connection.getBalance(vaultPda);
if (vaultBal < 0.02 * LAMPORTS_PER_SOL) {
  const fund = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: creator.publicKey,
      toPubkey: vaultPda,
      lamports: 0.05 * LAMPORTS_PER_SOL,
    })
  );
  const fs2 = await sendAndConfirmTransaction(connection, fund, [creator]);
  console.log("funded vault:", fs2);
}

// Next transaction index.
const msAccount = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
const transactionIndex = BigInt(Number(msAccount.transactionIndex)) + 1n;
console.log("transactionIndex:", transactionIndex.toString());

// Inner message the vault will run after quorum: a tiny SOL transfer.
const innerMessage = new TransactionMessage({
  payerKey: vaultPda,
  recentBlockhash: (await connection.getLatestBlockhash()).blockhash,
  instructions: [
    SystemProgram.transfer({
      fromPubkey: vaultPda,
      toPubkey: creator.publicKey,
      lamports: 0.001 * LAMPORTS_PER_SOL,
    }),
  ],
});

// Build ONE legacy transaction with vaultTransactionCreate + proposalCreate,
// mirroring what the app batches, so both instructions land in one signature.
const createTxIx = multisig.instructions.vaultTransactionCreate({
  multisigPda,
  transactionIndex,
  creator: creator.publicKey,
  vaultIndex: 0,
  ephemeralSigners: 0,
  transactionMessage: innerMessage,
  memo: "quorum-fixture",
});
const createPropIx = multisig.instructions.proposalCreate({
  multisigPda,
  transactionIndex,
  creator: creator.publicKey,
});

const tx = new Transaction().add(createTxIx, createPropIx);
tx.feePayer = creator.publicKey;
tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
const sig = await sendAndConfirmTransaction(connection, tx, [creator], {
  commitment: "confirmed",
});
console.log("\n=== FIXTURE TRANSACTION ===");
console.log("signature:", sig);
console.log("multisig:", multisigPda.toBase58());
console.log("transactionIndex:", transactionIndex.toString());
