#!/usr/bin/env python3
"""Prove each measured whole-allocation delivery and verify it offline."""
import argparse
import gzip
import json
from pathlib import Path
import struct
import subprocess
import tempfile


def corrupt_seal(receipt):
    """Change the low bit of a seal word while preserving its pinned bincode encoding."""
    result = bytearray(receipt)
    if result[0] != 1:
        raise ValueError("expected the succinct receipt variant")
    widths = {251: 2, 252: 4, 253: 8, 254: 16}
    position = 2 + widths.get(result[1], 0)  # variant, then the seal vector length
    if result[position] in widths:
        position += 1
    elif result[position] == 250:
        result[position] = 248
        return result
    result[position] ^= 1
    return result


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("artifacts", type=Path)
parser.add_argument("--program", required=True, type=Path)
parser.add_argument("--prover", default="r0vm")
parser.add_argument("--cli", default="target/debug/rgt-proof")
args = parser.parse_args()
root = args.artifacts
run = json.loads((root / "deliveries.json").read_text())
chain = ["--genesis", str(root / "genesis.json"), "--checkpoint", "0:" + run["genesis"],
         "--articles", run["articles"]]
previous = []
for hop, invoice in enumerate(run["deliveries"], start=1):
    output = root / f"hop-{hop}.rgtzk"
    if not output.exists():
        subprocess.run([args.cli, "prove", root / f"hop-{hop}.rgtproof", *chain,
                        "--program", args.program, "--prover", args.prover,
                        "--output", output, *previous], check=True)
    verify = [args.cli, "verify", output, *chain, "--outpoint", invoice["outpoint"],
              "--auth", invoice["auth"], "--amount"]
    subprocess.run([*verify, str(run["amount"])], check=True)
    mismatch = subprocess.run([*verify, str(run["amount"] + 1)], capture_output=True)
    if mismatch.returncode != 1 or b"wrong or locked allocation" not in mismatch.stderr:
        raise RuntimeError(f"incorrect amount did not trigger the invoice check: {mismatch.stderr!r}")
    encoded = output.read_bytes()
    size, = struct.unpack_from("<I", encoded, 8)
    print(f"hop={hop} receipt={size} certified-package={len(encoded)} "
          f"gzip={len(gzip.compress(encoded, mtime=0))} bytes", flush=True)
    prefix = encoded[:12 + size]
    fields = encoded[12 + size:]
    with tempfile.TemporaryDirectory(prefix="rgt-invalid-proof-") as tmp:
        invalid = Path(tmp) / "corrupt-seal.rgtzk"
        invalid.write_bytes(encoded[:12] + corrupt_seal(encoded[12:12 + size]) + fields)
        result = subprocess.run([*verify[:2], invalid, *verify[3:], str(run["amount"])], capture_output=True)
        if result.returncode != 1 or b"verification indicates proof is invalid" not in result.stderr:
            raise RuntimeError(f"altered seal did not fail cryptographic verification: {result.stderr!r}")
        for case in ("opening", "missing-body", "missing-votes"):
            meta = json.loads(fields)
            if case == "opening":
                meta["frontier"]["opening"]["blinding"][0] ^= 1
            elif case == "missing-body":
                meta["evidence"]["bodies"].clear()
            else:
                meta["evidence"]["extensions"][-1]["votes"].clear()
            invalid = Path(tmp) / (case + ".rgtzk")
            invalid.write_bytes(prefix + json.dumps(meta).encode())
            result = subprocess.run([*verify[:2], invalid, *verify[3:], str(run["amount"])], capture_output=True)
            if result.returncode != 1:
                raise RuntimeError(f"{case} did not fail closed: {result.returncode}")
    previous = ["--previous", output]
