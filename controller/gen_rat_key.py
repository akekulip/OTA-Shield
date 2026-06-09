#!/usr/bin/env python3
"""One-shot helper: generate an ed25519 keypair for RAT signing.

Writes the PRIVATE key to  ~/.ota_shield/rat_signing.key  (mode 0600)
Writes the PUBLIC  key to  controller/rat.pub                  (mode 0644)

Run this exactly once per deployment. The private key must NEVER be
committed. `.gitignore` at the repo root excludes `controller/rat.pub`
only if you add it there; the public key is safe to commit.

Usage:
    python3 controller/gen_rat_key.py                   # default paths
    python3 controller/gen_rat_key.py --force           # overwrite existing
    python3 controller/gen_rat_key.py --pub custom.pub --priv /tmp/k.key
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--priv", type=Path,
                    default=Path.home() / ".ota_shield" / "rat_signing.key",
                    help="private-key path (default: ~/.ota_shield/rat_signing.key)")
    ap.add_argument("--pub", type=Path,
                    default=Path(__file__).parent / "rat.pub",
                    help="public-key path (default: controller/rat.pub)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing files")
    args = ap.parse_args()

    try:
        from nacl.signing import SigningKey  # type: ignore
    except ImportError:
        print("ERROR: pynacl is not installed. Run: pip install pynacl",
              file=sys.stderr)
        return 2

    if args.priv.exists() and not args.force:
        print(f"ERROR: {args.priv} already exists. Use --force to overwrite.",
              file=sys.stderr)
        print("  (Overwriting an active signing key invalidates every "
              "existing rat.json.sig in the fleet.)", file=sys.stderr)
        return 1
    if args.pub.exists() and not args.force:
        print(f"ERROR: {args.pub} already exists. Use --force to overwrite.",
              file=sys.stderr)
        return 1

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    args.priv.parent.mkdir(parents=True, exist_ok=True)
    # Write private key with 0600 permissions — do this BEFORE writing
    # any bytes so a race can't expose the key.
    fd = os.open(str(args.priv), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, bytes(signing_key))
    finally:
        os.close(fd)

    args.pub.parent.mkdir(parents=True, exist_ok=True)
    args.pub.write_bytes(bytes(verify_key))
    try:
        os.chmod(args.pub, 0o644)
    except OSError:
        pass

    print(f"ed25519 signing key written to {args.priv} (mode 0600)")
    print(f"ed25519 verify  key written to {args.pub}  (mode 0644)")
    print()
    print("Next: sign your RAT manifest with")
    print(f"  python3 controller/sign_rat.py controller/rat.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
