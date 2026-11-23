# Really Good Tondi protocol on Tondi v10

A transfer has three relevant objects. The state commitment binds the next asset operation and its blinded successor. A recursive receipt can authenticate the evolution of a single allocation. The recipient-encrypted capsule supplies the private materials needed to recover the asset from an archive.

## Commit and publish

The successor opening contains the Note output index, its Auth script hash and a random blinding value. The operation commits to their seal token before the body TxID is known. Output zero of the native transaction carries the domain-separated operation digest in its unique RGT Facet, key `0x5254`. The signed body determines the final outpoint. The receiver checks the exact committed spend and its successful outcome in a certified checkpoint. An owner can spend the native Note without creating a valid RGT successor. This closes the seal and burns that allocation. RGT wallets enforce asset continuation through client-side validation. This adapts RGK’s continuation and lineage ideas to native Tondi Notes. [RGK protocol](https://github.com/RGK-Protocol/RGK)

## Encrypt and recover

The recipient derives separate view and Schnorr spend keys from an English BIP39 mnemonic with an empty passphrase, or from a 32–64-byte raw seed. HKDF-SHA256 binds both keys to the genesis. The public descriptor contains the network, genesis, view public key and native Note Auth. This version uses a stable receiving Auth for each seed and genesis. Repeated payments are linkable. Transaction timing, capsule sizes and the public RGT Facet are visible.

The sender uses fresh ephemeral secp256k1 ECDH, HKDF-SHA256 and AES-256-GCM. The authenticated frame includes its version, compressed ephemeral key and nonce. The key derivation binds the frame, genesis, network, recipient view key and spending Auth. The full-history plaintext contains the strict predecessor history and the private invoice, including the successor opening. In the compact profile the first field contains a verified predecessor receipt, its current cell and its issuing terms. The sender publishes the ciphertext in the native Data validation check of the transfer itself. Rebuilding the final operation uses the actual certified envelope and avoids a self-reference through its TxID.

The restoring wallet samples the archive’s certified tip, verifies the genesis, checkpoint pin, quorum certificates, committee changes and committed bodies, and replays each batch with the parent consensus implementation. It tries the view key on candidate capsules. For each authenticated capsule it checks the asset history or predecessor proof, exact published spend, contract semantics and expected successor. It exports the private state and native draft input for each Note that remains live at the authenticated tip.

Cold recovery currently needs a complete archive from genesis and a sufficiently recent independently acquired checkpoint. An archive can withhold data or report an old tip. Tondi observers can prune execution bodies and rotate the snapshot anchor. A wallet restoring from seed needs a provider with full retention, even if the wallet has a recent trusted checkpoint. The provider determines retention and fees. [Tondi observer storage and full retention](https://github.com/Tondi-Foundation/Tondi/blob/2960f9bb8d2b42d63ca5d79a5ac44191511af4a8/docs/STORAGE_STEADY_STATE.md)

## Proof formats

| Format | Contents and verifier |
| --- | --- |
| `.rgt` | Strict private history. Its file magic is `RGTNOTE!` and both the outer file and inner stream require RGT format version 1. |
| `.rgtproof` | `RGTV10\0\x01`, little-endian u32 history length, strict history, then JSON checkpoint evidence. The reader limits the complete package to 64 MiB. |
| `.rgtstate` | A verified succinct receipt and the private data that open its current cell. A wallet can plan a compact payment directly from this file. |
| `.rgtstep` | A prior `.rgtstate`, the invoice and the single successor transaction body. Archive recovery authenticates its publication and checks the step locally. A local prover folds it before the next compact transfer. |
| On-chain capsule | `RGTCAP\0\x01`, 33-byte ephemeral public key, 12-byte nonce, ciphertext and 16-byte tag. Tondi’s transaction limit is 524,288 bytes for the entire transaction. |
| `.rgtzk` | `RGTZKP\0\x01`, little-endian u32 sealed-receipt length, RISC Zero succinct receipt, then the private current opening and certified terminal delivery material. Treat this package as recipient data. |

The recursive guest validates the issuance codex and then verifies a predecessor receipt from the same pinned image at every transfer. Each step checks the asset operation and codex, the previous cell and its consumed outpoint, preservation of the entire cell value, the unique operation commitment and the destination Note. The 64-byte public journal binds the verifier image and a digest of the network, genesis, contract, operation, Note and cell. The offline verifier checks the receipt with development mode disabled and binds the opening to independently supplied invoice terms. It authenticates the exact successful terminal envelope against the supplied genesis and checkpoint. The native ledger enforces that each consumed outpoint was created on that chain. [RISC Zero proof composition](https://dev.risczero.com/api/zkvm/composition)

The recursive profile covers one destructible cell per step and unsigned articles, with no immutable inputs or outputs. Splits, merges and multiple asset cells need additional relations. The checkpoint header prefix and terminal body are separate from the recursive receipt and may grow. A delivery proof certifies historical receipt. The recovery scan also checks current spendability.
