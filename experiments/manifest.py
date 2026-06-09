"""Trial reproducibility manifest writer / verifier.

Implements the schema locked in `EXPERIMENT_DESIGN.md` §3 + Testbed §6.
Every Tier-1 / Tier-2 trial drops a `manifest.yaml` with the locked
fields below; a `manifest.yaml.sha256` lock file freezes the manifest
post-write so integrity item 11 (manifest immutability) can be re-checked.

Public surface (consumed by `experiments/trial_runner.py` and
`experiments/integrity_checker.py`):

* :class:`TrialManifest`        — frozen dataclass holding the schema.
* :func:`compute_p4_binary_sha` — sha256 of the running ``ota_shield.conf``.
* :func:`compute_file_sha`      — local file sha256.
* :func:`write_manifest`        — atomically writes ``manifest.yaml`` + lock.
* :func:`verify_manifest_immutable` — recomputes manifest sha and compares
  against the lock; backs integrity item 11.

CLI (smoke):
    python -m experiments.manifest --trial /tmp/tr_test \
        --scenario test --duration 10
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# Schema version: bump when fields change. Aggregator skips unknown.
SCHEMA_VERSION = "1.0"

# Locked at panel level — embedded so any drift trips integrity item 11.
SCENARIO_LIBRARY_VERSION = "v1.0"
ADVERSARY_VERSION = "v1.0"
STATISTICAL_CONTRACT_VERSION = "v1.0"
VISUALIZATION_CONTRACT_VERSION = "v1.0"


@dataclasses.dataclass(frozen=True)
class TrialManifest:
    """Per-trial reproducibility manifest. Field-for-field with §3."""

    exp_id: str
    trial_id: str
    scenario_id: str
    declared_duration_s: float
    actual_duration_s: float
    master_seed: str = "0xCAFE"
    trial_seed: int = 0
    p4_binary_sha256: str = ""
    controller_git_rev: str = ""
    rat_lifecycle_sha256: str = ""
    p4_compile_log_sha: str = ""
    ports_config_sha: str = ""
    schema_version: str = SCHEMA_VERSION
    scenario_library_version: str = SCENARIO_LIBRARY_VERSION
    adversary_version: str = ADVERSARY_VERSION
    statistical_contract_version: str = STATISTICAL_CONTRACT_VERSION
    visualization_contract_version: str = VISUALIZATION_CONTRACT_VERSION
    sde_version: str = "9.13.2"
    preflight_integrity: dict[str, str] = dataclasses.field(default_factory=dict)
    postflight_integrity: dict[str, str] = dataclasses.field(default_factory=dict)
    host_clocks: dict[str, Any] = dataclasses.field(default_factory=dict)
    notes: str = ""
    written_at_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        if not d.get("written_at_utc"):
            d["written_at_utc"] = datetime.now(timezone.utc).isoformat()
        return d


# ----------------------------------------------------------------- sha256


def compute_file_sha(path: str | Path) -> str:
    """Stream a local file through sha256. Returns hex digest, or empty
    string if the file is missing (callers can choose to flag that)."""
    p = Path(path)
    if not p.is_file():
        return ""
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_p4_binary_sha(
    conf_path: str,
    *,
    ssh_host: str | None = None,
    timeout_s: float = 8.0,
) -> str:
    """sha256 of the running ``ota_shield.conf`` on the switch.

    If ``ssh_host`` is given we run ``sha256sum`` over SSH (matches the
    pattern in `run_e12b.py`); otherwise we sha the file locally. Empty
    string on any failure — caller decides whether that's fatal.
    """
    if ssh_host is None:
        return compute_file_sha(conf_path)

    cmd = (
        f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        f"{shlex.quote(ssh_host)} {shlex.quote(f'sha256sum {conf_path}')}"
    )
    try:
        res = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout_s, check=False,
        )
    except subprocess.TimeoutExpired:
        return ""
    if res.returncode != 0 or not res.stdout:
        return ""
    # `sha256sum` prints "<hex>  <path>".
    return res.stdout.split()[0].strip()


# ----------------------------------------------------------------- write/verify


def write_manifest(trial_dir: Path, manifest: TrialManifest) -> Path:
    """Write ``manifest.yaml`` + ``manifest.yaml.sha256`` atomically.

    Returns the manifest path. The ``.sha256`` lock file is what integrity
    item 11 (manifest immutability) reads back.
    """
    trial_dir = Path(trial_dir)
    trial_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = trial_dir / "manifest.yaml"
    lock_path = trial_dir / "manifest.yaml.sha256"

    payload = manifest.to_dict()
    # Stable serialization: sort_keys so the sha256 is reproducible regardless
    # of Python's dict insertion order (matters when re-checking item 11).
    yaml_text = yaml.safe_dump(payload, sort_keys=True, default_flow_style=False)
    manifest_path.write_text(yaml_text)
    digest = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
    lock_path.write_text(f"{digest}  {manifest_path.name}\n")
    return manifest_path


def verify_manifest_immutable(trial_dir: Path) -> bool:
    """Item 11: recompute sha256 of manifest.yaml vs the lock file.

    Returns True iff both files exist and the digests match. False on
    missing files or any mismatch — the integrity checker promotes that
    to ``item_11: fail`` and the trial is invalidated.
    """
    trial_dir = Path(trial_dir)
    manifest_path = trial_dir / "manifest.yaml"
    lock_path = trial_dir / "manifest.yaml.sha256"
    if not manifest_path.is_file() or not lock_path.is_file():
        return False
    expected = lock_path.read_text().split()[0].strip()
    actual = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return expected == actual


# ----------------------------------------------------------------- CLI smoke


def _cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Trial manifest writer (smoke).")
    ap.add_argument("--trial", required=True, type=Path,
                    help="Trial output dir (created if absent).")
    ap.add_argument("--scenario", required=True,
                    help="Scenario id, e.g. bess.benign.staged_rollout_v48.")
    ap.add_argument("--duration", type=float, required=True,
                    help="Declared trial duration in seconds.")
    ap.add_argument("--exp-id", default="SMOKE")
    ap.add_argument("--trial-id", default="t00")
    args = ap.parse_args(argv)

    manifest = TrialManifest(
        exp_id=args.exp_id,
        trial_id=args.trial_id,
        scenario_id=args.scenario,
        declared_duration_s=args.duration,
        actual_duration_s=args.duration,
        notes="placeholder manifest from `python -m experiments.manifest`",
    )
    path = write_manifest(args.trial, manifest)
    ok = verify_manifest_immutable(args.trial)
    print(f"[manifest] wrote {path} (immutable={ok})")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_cli())
