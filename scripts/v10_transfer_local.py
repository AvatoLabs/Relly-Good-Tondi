#!/usr/bin/env python3
"""Measure two certified RGT deliveries on a fresh, single-validator ordinary-v10 chain."""
import argparse
import gzip
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
TONDI = ROOT.parent / "Tondi"
LOCAL = build_opener(ProxyHandler({}))


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def must_reject(args, reason):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 1 or reason not in result.stderr:
        raise AssertionError(f"expected verifier rejection '{reason}', got {result.returncode}: {result.stderr}")


def reject_missing_archive_body(rgt, package, genesis, pin, seed, output):
    raw = package.read_bytes()
    evidence = json.loads(raw[12 + int.from_bytes(raw[8:12], "little"):])
    extension = evidence["extensions"][0]
    tip = extension["headers"][-1]["commitIndex"]

    class PrunedArchive(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/v1/status":
                value = {"genesis": pin.split(":")[1], "certifiedThrough": str(tip)}
            elif self.path.startswith("/v1/checkpoint-proof?"):
                value = extension
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(value).encode())

        def log_message(self, *_):
            pass

    with HTTPServer(("127.0.0.1", 0), PrunedArchive) as archive:
        server = Thread(target=archive.serve_forever, daemon=True)
        server.start()
        try:
            rpc = f"http://127.0.0.1:{archive.server_port}"
            result = subprocess.run([rgt, "recover", "--genesis", genesis, "--checkpoint", pin,
                                     "--rpc", rpc, "--output", output], input=seed, capture_output=True)
            assert result.returncode == 1 and b"incomplete archive" in result.stderr and not output.exists()
        finally:
            archive.shutdown()
            server.join()


def binary(repo, args, name):
    cargo = ["cargo", "+1.95.0"]
    run(cargo + ["build", "--locked", *args], cwd=repo)
    metadata = run(cargo + ["metadata", "--no-deps", "--format-version", "1"],
                   cwd=repo, capture_output=True).stdout
    return Path(json.loads(metadata)["target_directory"]) / "debug" / name


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def rpc(url, data=None):
    body = None if data is None else json.dumps(data).encode()
    with LOCAL.open(Request(url, data=body, headers={"Content-Type": "application/json"}), timeout=5) as res:
        return json.load(res)


def wait(node, probe):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if node.poll() is not None:
            raise RuntimeError("validator stopped, see validator.log")
        try:
            if value := probe():
                return value
        except HTTPError as err:
            if err.code not in (404, 503):
                raise RuntimeError(f"HTTP {err.code}: {err.read(4096).decode()}") from err
        except URLError:
            pass
        time.sleep(0.15)
    raise TimeoutError("local validator did not certify the requested data within 60 seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory for public verification artifacts")
    parser.add_argument("--compact-program", type=Path, help="prove the first delivery and send onward using compact capsules")
    parser.add_argument("--prover", default="r0vm", help="local RISC Zero prover executable")
    args = parser.parse_args()
    tondid = os.environ.get("TONDID") or binary(TONDI, ["-p", "tondid"], "tondid")
    rgt = binary(ROOT, ["--bin", "rgt"], "rgt")
    fixture = binary(ROOT, ["-p", "rgt-runtime", "--example", "local_transfer"], "examples/local_transfer")
    proof = binary(ROOT, ["--bin", "rgt-proof"], "rgt-proof") if args.compact_program else None
    prover = ["--program", args.compact_program, "--prover", args.prover] if proof else []
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    endpoint = f"http://127.0.0.1:{port()}"
    with tempfile.TemporaryDirectory(prefix="rgt-v10-node-") as temp:
        private = Path(temp) / "chain"
        run([tondid, "init", private, "--profile", "ordinary-v10", "--rpc-address", endpoint,
             "--consensus-address", f"/ip4/127.0.0.1/tcp/{port()}"])
        genesis = out / "genesis.json"
        shutil.copy(private / "genesis.json", genesis)
        keys = private / "private-keys.md"
        seed = json.loads(keys.read_text().split("```json\n")[1].split("\n```")[0])["wallet_seed"]
        bob = run([fixture, "--new-mnemonic"], capture_output=True).stdout.strip()
        assert len(bob.split()) == 24
        carol = os.urandom(32).hex().encode()
        dan = os.urandom(32).hex().encode()
        recipients = [Path(temp) / "bob.receiver", Path(temp) / "carol.receiver", Path(temp) / "dan.receiver"]
        for key, descriptor in zip([bob, carol, dan], recipients):
            run([rgt, "receiver", "--genesis", genesis, "--output", descriptor], input=key)
        pin = "0:" + json.loads(recipients[0].read_bytes())["genesis"]
        base = ["--genesis", genesis, "--checkpoint", pin]
        snapshot = Path(temp) / "recovered-bob"
        def recover(key, dest):
            run([rgt, "recover", *base, "--rpc", endpoint, "--output", dest], input=key)
            return json.loads((dest / "wallet.json").read_bytes())
        deliveries = []
        checks = []
        recursive_checks = []
        with (out / "validator.log").open("w") as log:
            node = subprocess.Popen([tondid, "run", "--genesis", genesis, "--keys", keys, "--data", private / "data",
                                     "--listen", endpoint.split("//")[1]], stdout=log, stderr=subprocess.STDOUT)
            try:
                wait(node, lambda: rpc(endpoint + "/v1/status"))
                source = None
                for hop, key in enumerate([seed.encode(), bob] + ([carol] if proof else []), start=1):
                    sender = [None, snapshot, Path(temp) / "recovered-carol"][hop-1]
                    extra = ([sender, source, str(hop)] if source else [sender]) if sender else []
                    run([fixture, out, rgt, recipients[hop-1], *extra], input=key)
                    delivery = json.loads((out / f"delivery-{hop}.json").read_bytes())
                    deliveries.append(delivery)
                    options = [*base, "--articles", delivery["articles"]]
                    envelope = out / f"hop-{hop}.hex"
                    def submit():
                        result = subprocess.run([rgt, "submit", envelope, "--rpc", endpoint], capture_output=True, text=True)
                        if result.returncode and "503" in result.stderr:
                            return False
                        result.check_returncode()
                        return True
                    wait(node, submit)
                    receipt_url = f'{endpoint}/v1/receipts/{delivery["txid"]}?witness={delivery["witness"]}'
                    def confirmed():
                        receipt = rpc(receipt_url)
                        if receipt.get("execution") == "rejected":
                            raise RuntimeError(f"validator rejected hop {hop}")
                        return receipt.get("header") if receipt.get("execution") == "succeeded" else None
                    header = wait(node, confirmed)
                    height = int(header["commitIndex"])
                    wait(node, lambda: rpc(f"{endpoint}/v1/checkpoints?after={height-1}&limit=1"))
                    bundle = out / f"hop-{hop}.rgtproof"
                    history = out / f"hop-{hop}.rgt"
                    if not proof or hop == 1:
                        run([rgt, "pack", history, *options, "--rpc", endpoint, "--output", bundle])
                        check = [rgt, "verify", bundle, *options, "--outpoint", delivery["outpoint"],
                                 "--auth", delivery["auth"], "--amount", "100"]
                        checks.append(check)
                        raw = bundle.read_bytes()
                        print(f"hop={hop} checkpoint={height} envelope={delivery['envelopeBytes']} "
                              f"history={history.stat().st_size} package={len(raw)} gzip={len(gzip.compress(raw,mtime=0))} bytes",
                              flush=True)
                    dest = [snapshot, Path(temp) / "recovered-carol", Path(temp) / "recovered-dan"][hop-1]
                    wallet = recover([bob, carol, dan][hop-1], dest)
                    assert len(wallet["assets"]) == 1 and wallet["invalidCapsules"] == 0
                    recovered = dest / wallet["assets"][0]["history"]
                    ext = "rgtstep" if proof and hop > 1 else "rgt"
                    assert recovered.read_bytes() == (out / f"hop-{hop}.{ext}").read_bytes()
                    if proof and hop < 3:
                        # The prover is offline. Freeze this private fixture ledger while proving.
                        certified = out / f"hop-{hop}.rgtzk"
                        node.send_signal(signal.SIGSTOP)
                        try:
                            source = out / f"hop-{hop}.rgtstate"
                            if hop == 1:
                                run([proof, "prove", bundle, *options, *prover, "--output", certified])
                                run([proof, "verify", certified, *options, "--outpoint", delivery["outpoint"],
                                     "--auth", delivery["auth"], "--amount", "100", "--save-state", source])
                            else:
                                run([proof, "fold", recovered, *prover, "--output", source])
                        finally:
                            node.send_signal(signal.SIGCONT)
                        if hop > 1:
                            run([proof, "certify", source, *options, "--envelope", envelope,
                                 "--rpc", endpoint, "--output", certified])
                        recursive_checks.append([proof, "verify", certified, *options, "--outpoint",
                                                 delivery["outpoint"], "--auth", delivery["auth"], "--amount", "100"])
                    print(f"hop={hop} archived capsule={delivery['capsuleBytes']} bytes, recovered from seed", flush=True)
                assert not recover(bob, Path(temp) / "spent-bob")["assets"]
                assert not recover(os.urandom(32).hex().encode(), Path(temp) / "other-wallet")["assets"]
                incomplete = Path(temp) / "unverified-wallet"
                rejected = subprocess.run([rgt, "recover", "--genesis", genesis, "--checkpoint", "0:" + "0"*64,
                                           "--rpc", endpoint, "--output", incomplete], input=bob, capture_output=True)
                assert rejected.returncode == 1 and b"checkpoint" in rejected.stderr and not incomplete.exists()
                (out / "deliveries.json").write_text(json.dumps({"genesis":pin[2:], "articles":deliveries[0]["articles"],
                    "amount":100,"deliveries":deliveries}, indent=2))
            finally:
                node.terminate()
                try:
                    node.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()
        for check in recursive_checks:
            run(check)
        reject_missing_archive_body(rgt, out / "hop-1.rgtproof", genesis, pin, bob, Path(temp) / "pruned-wallet")
        # Old commands and the former container header must fail closed.
        old_cli = subprocess.run([rgt, "v10", "--help"], capture_output=True)
        if old_cli.returncode != 2:
            raise AssertionError("obsolete CLI dispatch is active")
        previous = bytearray((out / "hop-1.rgtproof").read_bytes())
        previous[12:22] = b"RGBCNSGN" + bytes(2)
        old_file = Path(temp) / "old-format.rgtproof"
        old_file.write_bytes(previous)
        must_reject([*checks[0][:2], old_file, *checks[0][3:]], "invalid RGT file header")
        for hop, check in enumerate(checks, start=1):
            exported = Path(temp) / f"received-{hop}.rgt"
            run([*check, "--save-history", exported])
            if exported.read_bytes() != (out / f"hop-{hop}.rgt").read_bytes():
                raise AssertionError("forwardable RGT history changed during verification")
        # Reject an otherwise valid certificate delivered against different invoice terms.
        must_reject([*checks[-1][:-1], "101"], "history does not deliver")
        # Remove spend evidence or a quorum signature from a previously valid file.
        package = Path(checks[-1][2]).read_bytes()
        split = 12 + int.from_bytes(package[8:12], "little")
        for case in ("missing-body", "missing-votes"):
            evidence = json.loads(package[split:])
            if case == "missing-body":
                evidence["bodies"].pop()
            else:
                evidence["extensions"][-1]["votes"].clear()
            bad = Path(temp) / f"{case}.rgtproof"
            bad.write_bytes(package[:split] + json.dumps(evidence).encode())
            check = [*checks[-1][:2], bad, *checks[-1][3:]]
            must_reject(check, "missing certified spend" if case == "missing-body" else "below quorum")


if __name__ == "__main__":
    main()
