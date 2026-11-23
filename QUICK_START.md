# Tondi v10 wallet workflow

Build the CLI from the workspace root with the sibling v10 checkout in `../Tondi`.

```sh
cargo +1.95.0 build --bin rgt
target/debug/rgt --help
python3 scripts/v10_transfer_local.py target/v10-run
```

The upper-level wallet commands support an unsigned RGT issuer with `issue` and `transfer` methods and a schema-defined owned allocation. Use `--amount 100` for the default numeric state or `--state NAME --value JSON` to specify a strict value. The local run generates such a contract, derives recipient keys from two fresh seeds and exercises the commands below.

1. Create a whole-allocation issuer with `rgt create-issuer --output asset.issuer`, or supply an issuer with the same methods. Use `rgt issue` with the issuer file, funding outpoint, Note Auth, amount and output filename. Keep the printed RGT articles ID with the invoice. For localnet use `--testnet`.
2. Have the recipient run `rgt receiver --genesis genesis.json --output receiver.json` with their seed on stdin. Create the private payment JSON using `rgt invoice --articles ID --input TXID:INDEX --vout INDEX --receiver receiver.json --amount N --output payment.json`. Use `rgt plan` with the current history, native draft and payment file. It encrypts the predecessor history and payment to the receiver and emits an unsigned native PSTT. The draft must consume the source and pay the requested Auth at the selected output index. Output zero must have enough native value to hold the RGT Facet.
3. Review the native PSTT. Run `rgt sign unsigned.pstt --output signed.pstt` with the hex secret key on standard input, then `rgt finalize signed.pstt --genesis genesis.json --clock clock.json --output tx.hex`. Use the target decision’s native clock context.
4. Run `rgt export-history` with the same source, payment JSON and the signed envelope. This resolves the planned successor to the actual TxID. Run `rgt submit tx.hex --rpc URL` and wait for a certified successful outcome.
5. Run `rgt pack` with the receiver history, HTTP RPC, genesis manifest, trusted checkpoint and articles ID. Deliver the resulting `.rgtproof` file.
6. Run `rgt verify` against independently selected invoice terms, genesis and checkpoint. Use `--save-history` to export the validated RGT history for the recipient's next transfer.

The private payment file binds the articles ID to the native `input` outpoint (`transactionId` and `index`), the successor `vout`, its public receiving descriptor, a fresh random 32-byte `blinding` value and the allocation’s state name and value. Hashes use native hex. Reuse that payment file between planning and exporting the same transfer.

For an artifact from the local run, the following offline command uses the recorded fixture invoice. A deployed wallet obtains its expected terms and a recent checkpoint through its own trusted channel.

```sh
cd target/v10-run
invoice=deliveries.json
../debug/rgt verify hop-1.rgtproof --genesis genesis.json \
    --checkpoint "0:$(jq -r .genesis "$invoice")" --articles "$(jq -r .articles "$invoice")" \
    --outpoint "$(jq -r '.deliveries[0].outpoint' "$invoice")" \
    --auth "$(jq -r '.deliveries[0].auth' "$invoice")" --amount 100
```

For other RGT codices, `rgt prepare` embeds an already constructed RGT Opid in a native draft. Wallet integrations can use `rgt_core::note` with the generic RGT contract and persistence APIs.

## Restore from a seed

Supply the original genesis, a trusted checkpoint, an archive endpoint and a fresh output path. Feed the seed or mnemonic from your wallet’s secret input.

```sh
rgt recover --genesis genesis.json --checkpoint "$PIN" --rpc "$ARCHIVE" --output restored < seed.private
```

Each live entry in `restored/wallet.json` contains an RGT history filename, the allocation and the exact native `draftInput`. Use that history as the source for `rgt plan` and the recovered input in the native draft. Sign with `rgt sign unsigned.pstt --seed-genesis genesis.json --output signed.pstt < seed.private`. Treat the snapshot as private wallet data.

## Send from a recursive receipt

Verify the certified `.rgtzk` delivery with your chain pin and invoice terms. Add `--save-state received.rgtstate` to `rgt-proof verify`. Supply this file as the source to `rgt plan`; the rest of the signing and submit workflow is the same. The Data check contains the encrypted predecessor receipt, the current cell and issuing terms, and the new recipient’s invoice and opening.

A clean wallet restores this delivery with `rgt recover`. The wallet manifest identifies a `.rgtstep` file for the recovered allocation. This contains the prior proof and one certified transition. Fold it into a new spendable state locally.

```sh
rgt-proof fold recovered.rgtstep --program "$GUEST" --prover "$R0VM" --output current.rgtstate
rgt plan current.rgtstate --payment next-payment.json --draft next-draft.json --output unsigned.pstt
```

To produce an independently verifiable offline delivery, use `rgt-proof certify current.rgtstate --envelope transfer.hex --genesis genesis.json --checkpoint "$PIN" --articles "$ARTICLES" --rpc "$ARCHIVE" --output transfer.rgtzk`. Each recipient can verify this package with the node offline.
