#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo"
toolchain=${RGT_RISC0_TOOLCHAIN:-$(rustc +risc0 --print sysroot)}
export RUSTC="$toolchain/bin/rustc"
revision=$("$RUSTC" -vV | sed -n 's/^commit-hash: //p')
[[ "$revision" = e638c6cfea1eff5fbbb24a27e60538e3760d21b8 ]] || { echo "Install the pinned RISC Zero Rust toolchain (e638c6cfe)." >&2; exit 1; }
export RUSTC_WRAPPER="$repo/rgt-proof/guest/rustc.py"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$repo/target/rgt-guest"}
export RUSTFLAGS="--cfg getrandom_backend=\"custom\" -C link-arg=-Ttext=0x00200800 -C passes=lower-atomic -C panic=abort --remap-path-prefix=$repo=/rgt --remap-path-prefix=$(dirname "$repo")/Tondi=/tondi --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$toolchain=/rust"
"$toolchain/bin/cargo" build --locked --manifest-path rgt-proof/guest/Cargo.toml --release --target riscv32im-risc0-zkvm-elf
