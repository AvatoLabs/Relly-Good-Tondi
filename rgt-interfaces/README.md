# RGT Interfaces for Tondi

This crate contains the standard RGT contract interface types used by
RGT.

## Interfaces

- `fungible.rs`: fungible asset values such as `Amount` and `Precision`.
- `nft.rs`: NFT media and ownership types.
- `por.rs`: proof-of-reserves metadata.
- `names.rs`: tickers, asset names, and descriptions.
- `types.rs`: Strict Type library construction.

The interfaces are chain-neutral at the contract layer, but RGT
workflows use native Note outpoints. Proof-of-reserves pointers use the same strict NoteSeal type as the core verifier. See the [wallet quick start](../QUICK_START.md).

## Example Types

```rust
use rgt_interfaces::{Amount, AssetName, Details, Precision, Ticker};

let precision = Precision::CentiMicro;
let amount = Amount::with_precision(1_000_000, precision);
let (integer, fractional) = amount.split(precision);

let ticker = Ticker::from("USDT");
let name = AssetName::from("Tondi USD");
let details = Details::from("USD-denominated asset issued on RGT");
```

## Validation

```bash
cargo test -p rgt-interfaces --features serde
cargo run -p rgt-interfaces --bin rgt-interfaces-stl --features stl
```
