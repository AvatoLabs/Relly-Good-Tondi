#!/usr/bin/env python3
"""Give the locked guest's local path dependencies reproducible Rust symbol names."""
import json
import os
from pathlib import Path
import sys

compiler, *args = sys.argv[1:]
if "--crate-name" in args and "CARGO_PKG_NAME" in os.environ:
    crate = args[args.index("--crate-name") + 1]
    target = "guest" if "--target" in args else "host"
    features = ",".join(sorted(a for a in args if a.startswith("feature=")))
    unit = "/".join([os.environ["CARGO_PKG_NAME"], os.environ["CARGO_PKG_VERSION"], crate, target, features])
    pinned = json.loads(Path(__file__).with_name("rustc-units.json").read_text())
    if unit in pinned:
        for index, arg in enumerate(args):
            if arg.startswith("metadata="):
                args[index] = "metadata=" + pinned[unit]
                break
os.execv(compiler, [compiler, *args])
