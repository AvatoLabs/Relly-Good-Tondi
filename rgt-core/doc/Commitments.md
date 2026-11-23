# RGT commitments on Tondi v10

A private transfer history, a recipient snapshot and an archived transaction refer to the same allocation through three commitments.

| Commitment | Input | Where it is checked |
| --- | --- | --- |
| Note seal token | A one-byte flag indicating whether the TxID is known, the TxID when present, the four-byte little-endian output index, the 32-byte Auth script hash and the 32-byte blinding. The token is the first 30 bytes of the Tondi domain-separated BLAKE3 digest using `RGT/Tondi-v10/note-seal/v1`. | The asset cell contains the token. The wallet checks the opening against the destination Note and resolves the final outpoint from the published transaction. |
| Operation anchor | The 32-byte asset operation ID, hashed with Tondi's `RGT/Tondi-v10/operation/v1` domain. | Exactly one RGT Facet with key `0x5254` must carry that digest on output zero. The witness also checks that an input consumes the previous Note. |
| Recursive journal | The 32-byte pinned guest image ID followed by a 32-byte SHA-256 digest binding genesis, network, contract, operation ID, TxID, successor opening and cell. | The guest verifies the preceding journal at each transfer. The recipient opens the terminal journal, verifies the receipt and checks the certified delivery against the invoice. |

The seal token allows the sender to commit to a successor before its transaction has a TxID. The private opening lets the recipient check the commitment after publication. The encrypted capsule carries that opening in the same transaction. [Protocol and formats](../../TONDI_MIGRATION.md)

The host implements seal and Facet bindings in [the Note verifier](../src/note.rs). The [recursive relation](../../rgt-lineage/src/lib.rs) implements the same bindings with the guest's native Tondi body reader.
