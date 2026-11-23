# Workspace setup

The root lockfile and Rust toolchain pin the wallet build. Clone Tondi beside this checkout, keeping the directory name `Tondi`. The v10 workspace crates require Rust 1.95 and Python 3 for Telegraph code generation. The node also requires the native toolchain documented in the sibling repository. The two-hop cold recovery test passed against parent revision `2960f9bb`. The reference proof samples use `4e8663a4`. [Tested Tondi v10 source](https://github.com/Tondi-Foundation/Tondi/tree/2960f9bb8d2b42d63ca5d79a5ac44191511af4a8)

```sh
cargo +1.95.0 build --bin rgt
cargo +1.95.0 test --workspace --all-targets --all-features
python3 scripts/v10_transfer_local.py target/v10-run
```

The runner builds the sibling `tondid` by default. Set `TONDID` to an already built matching executable to reuse it. The output directory must be new. See the [wallet workflow](QUICK_START.md) for invoice and package details.

Build the wallet container from the repository root using the sibling v10 checkout as a named build context.

```sh
docker buildx build --build-context tondi=../Tondi -f rgt/Dockerfile .
```

## Workspace conventions

Use local path dependencies for internal crates. Keep runtime workflow documentation and scripts in English. Exercise the local v10 transfer before merging wallet, resolver or publication changes. Keep generated node state and ad hoc measurement outputs outside version control.

## Recursive proof

Use RISC Zero SDK and local `r0vm` 3.1.0. The pinned guest was built with the RISC Zero Rust toolchain `rustc 1.97.0-dev (e638c6cfe)` and the guest lockfile. The guest build uses Bash and Python 3. It remaps source paths and pins Cargo’s path-dependent Rust crate disambiguators for the locked compilation units. A separate checkout reproduced the same ELF byte for byte. Set `RGT_RISC0_TOOLCHAIN` to its installation prefix if it is not registered as the `risc0` rustup toolchain.

```sh
scripts/build_rgt_guest.sh
cargo build --locked -p rgt-proof
guest=target/rgt-guest/riscv32im-risc0-zkvm-elf/release/rgt-step
test "$(target/debug/rgt-proof image "$guest")" = "$(cat rgt/src/recursive-image-id)"
python3 scripts/prove_rgt_deliveries.py target/rgt-run --program "$guest" --prover "$(command -v r0vm)"
```

The local prover takes private witnesses. The second delivery reuses the first succinct receipt. The verifier only needs `rgt-proof verify`, the recipient package and independent invoice and chain terms. The public image identifier is pinned in the verifier binary.

`rgt-proof prove` and `rgt-proof fold` accept `--work-dir DIR` for long CPU runs. Choose a private local directory. It holds private witness traces for one exact execution and a verified receipt for each completed prefix. Running the same command again reopens those traces and verifies the saved receipts before continuing. The directory can be deleted once the final receipt verifies.

To exercise compact on-chain recovery, pass `--compact-program "$guest" --prover "$(command -v r0vm)"` to `scripts/v10_transfer_local.py` with a new output directory. It pays Bob using the full-history profile, exports his proven state, sends a compact encrypted capsule to Carol and folds Carol’s recovered transfer so she can pay the third recipient. The private test node pauses while proofs are produced.
