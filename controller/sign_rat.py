#!/usr/bin/env python3
"""Sign a RAT manifest with the ed25519 signing key.

Produces `<rat>.sig` alongside the input. The signature is over the raw
file bytes (no re-serialization) so it matches whatever `sha256sum
<rat>` would report. The controller's inotify watcher will observe the
new `.sig` and reload atomically.

Usage:
    python3 controller/sign_rat.py controller/rat.json
    python3 controller/sign_rat.py controller/rat.json --priv /tmp/k.key
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("rat", type=Path, help="path to rat.json")
    ap.add_argument("--priv", type=Path,
                    default=Path.home() / ".ota_shield" / "rat_signing.key",
                    help="private-key path (default: ~/.ota_shield/rat_signing.key)")
    ap.add_argument("--out", type=Path, default=None,
                    help="output signature path (default: <rat>.sig)")
    args = ap.parse_args()

    if not args.rat.exists():
        print(f"ERROR: {args.rat} does not exist", file=sys.stderr)
        return 1
    if not args.priv.exists():
        print(f"ERROR: signing key {args.priv} does not exist. "
              f"Run `python3 controller/gen_rat_key.py` first.",
              file=sys.stderr)
        return 1

    try:
        from nacl.signing import SigningKey  # type: ignore
    except ImportError:
        print("ERROR: pynacl is not installed. Run: pip install pynacl",
              file=sys.stderr)
        return 2

    raw_key = args.priv.read_bytes()
    if len(raw_key) != 32:
        print(f"ERROR: signing key {args.priv} is {len(raw_key)} bytes; "
              f"expected a raw 32-byte ed25519 seed.", file=sys.stderr)
        return 1
    signing_key = SigningKey(raw_key)

    message = args.rat.read_bytes()
    signed = signing_key.sign(message)
    # .signature is the raw 64-byte ed25519 signature; .message is the
    # original bytes. We write the signature only; the controller reads
    # it and verifies against the on-disk rat.json.
    sig_bytes = signed.signature

    out_path = args.out or args.rat.with_suffix(args.rat.suffix + ".sig")
    out_path.write_bytes(sig_bytes)
    print(f"Wrote {out_path} ({len(sig_bytes)} bytes, ed25519)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
