# Really Good Tondi (RGT)

RGT transfers client-validated assets on Tondi v10 Notes. A sender commits to a successor allocation in the transaction’s RGT Facet and encrypts the information needed to recover it to the recipient’s view key. A wallet can scan an archive, authenticate and replay its checkpoint bodies, recover its live allocations and sign a new transfer with its seed. [Protocol and trust model](TONDI_MIGRATION.md)

## Reproduce a transfer and recovery

Place the Tondi v10 source in `../Tondi` and run the following against a new output directory. The runner creates its own single-validator ordinary-v10 ledger and deletes the temporary keys and node database when it finishes.

```sh
python3 scripts/v10_transfer_local.py target/rgt-run
```

The runner issues 100 units, pays Bob, restores Bob in an empty directory, spends the restored allocation to Carol, and restores Carol. It checks that Bob’s spent Note disappears and that an unrelated seed finds no assets. It stops the node before verifying both deliveries. [Wallet commands](QUICK_START.md)

## Measured sizes

These are bytes from a two-hop local run. Each transfer consumed one Note and created one successor. The independently supplied genesis manifest was 21,876 bytes.

| Delivery | Certified checkpoint | Encrypted capsule on chain | Signed envelope | Private history | Certified full-history package | Package gzip |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Alice → Bob | 4 | 1,560 | 1,896 | 3,066 | 14,686 | 7,789 |
| Bob → Carol | 8 | 3,774 | 4,110 | 7,494 | 37,751 | 19,591 |

The capsule is already included in the envelope. This archive profile stores the full predecessor history, including earlier signed envelopes. Its size increases with successive transfers and is bounded by the native transaction limit. The offline package also carries certified headers and the bodies containing the relevant transfers. Timing and other traffic change the measured package size.

### Recursive delivery and compact capsules

The recursive guest proves issuance and verifies the preceding receipt at each whole-allocation transfer. An offline recipient checks the pinned guest, opens the proven cell, checks the invoice and verifies the terminal transaction against Tondi finality. A wallet can send onward with just this state and the recovered native Note. [Recursive proof build and verification](WORKSPACE_SETUP.md#recursive-proof)

| Same delivery as above | Succinct receipt | Certified recursive package | Package gzip |
| --- | ---: | ---: | ---: |
| Alice → Bob | 278,738 | 300,265 | 255,363 |
| Bob → Carol, reusing Bob’s receipt | 278,738 | 318,522 | 258,557 |

These short histories cost less to deliver in full. The second recursive step verified the preceding receipt and used 4,194,304 guest cycles across four segments. Local CPU proving took 703 seconds with another prover running. Both deliveries verify offline. The first transfer’s wallet snapshot was 226,593 bytes. Snapshots use fixed-width encoding for proof words. The delivery files above use variable-length encoding.

The archived capsule carries the *predecessor* proof and the new recipient’s private payment terms. The wallet locates the current transaction in the authenticated archive and folds that one transfer into a new proof. This avoids embedding a proof of a transaction inside its own body. The complete delivery package also carries the terminal transaction and checkpoint evidence. Its size depends on the transaction and on the distance from genesis.

In a separate run on the updated parent, Bob used a 226,592-byte snapshot to pay Carol. His signed transaction was 227,636 bytes, including a 227,300-byte encrypted capsule. Carol recovered the allocation from an empty wallet at checkpoint 8. Her local recovery file was 682,379 bytes. It contains the predecessor snapshot and the current transaction body. This step used 56,114,463 guest cycles across 58 segments.
