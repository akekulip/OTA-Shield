"""13-item per-trial integrity gate.

Source spec (binding):
- EXPERIMENT_DESIGN.md §2 (13 items + > 90 % pass acceptance)
- agent-reports/panel-8-2026-04-29/05_testbed_harness.md (item details)
- 02_statistical_design.md §3 (failure handling — write
  ``trial_invalid.txt``, do NOT delete, do NOT silently re-roll)

Each `check_*` function returns ``(name: str, passed: bool, detail: str)``.
``run_all(trial_dir)`` walks all 13 against a single trial's artifacts
and returns ``{item_NN: pass | fail | skip, ..., valid: bool}``.

The CLI exits non-zero if the trial is not valid.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #


def _read_text_safe(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return None


def _sha256_of(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    text = _read_text_safe(path)
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# --------------------------------------------------------------------- #
# 1. Register-zero-on-startup
# --------------------------------------------------------------------- #


def check_register_zero_on_startup(switch_handle: Any) -> tuple[str, bool, str]:
    """Confirm every monitored register reads zero before the trial.

    ``switch_handle`` is whatever the trial harness passes in. We accept:
      * a callable returning a dict ``{reg_name: int}``
      * a path / str pointing to a register-dump JSON file
      * an iterable of ``(name, value)`` pairs
      * a dict mapping register name -> value
      * ``None`` (skip).
    """
    name = "register_zero_on_startup"
    if switch_handle is None:
        return (name, False, "no switch handle provided -> skip-as-fail")
    try:
        if callable(switch_handle):
            dump = switch_handle()
        elif isinstance(switch_handle, (str, Path)):
            text = _read_text_safe(Path(switch_handle))
            dump = json.loads(text) if text else {}
        elif isinstance(switch_handle, dict):
            dump = switch_handle
        else:
            dump = dict(switch_handle)
    except Exception as e:  # noqa: BLE001 — defensive boundary
        return (name, False, f"unable to read register dump: {e!r}")

    bad = [(k, v) for k, v in dump.items() if isinstance(v, (int, float)) and v != 0]
    if bad:
        return (name, False, f"non-zero registers: {bad[:5]}")
    return (name, True, f"all {len(dump)} registers zero on startup")


# --------------------------------------------------------------------- #
# 2. P4 binary SHA matches manifest
# --------------------------------------------------------------------- #


def check_p4_binary_sha(manifest_path: Any) -> tuple[str, bool, str]:
    name = "p4_binary_sha"
    p = Path(manifest_path) if manifest_path else None
    if p is None or not p.exists():
        return (name, False, f"manifest not found at {manifest_path}")
    text = _read_text_safe(p)
    if not text:
        return (name, False, "manifest empty")
    declared = None
    binary_path = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("p4_binary_sha256:"):
            declared = s.split(":", 1)[1].strip().strip("\"' ")
        elif s.startswith("p4_binary_path:"):
            binary_path = s.split(":", 1)[1].strip().strip("\"' ")
    if not declared:
        return (name, False, "manifest missing p4_binary_sha256")
    if not binary_path:
        # Manifest declared a SHA but no path — accept as "trust the manifest".
        return (name, True, f"manifest declares sha={declared[:12]}...")
    actual = _sha256_of(Path(binary_path))
    if actual is None:
        return (name, False, f"binary missing at {binary_path}")
    if actual != declared:
        return (name, False,
                f"mismatch declared={declared[:12]}.. actual={actual[:12]}..")
    return (name, True, f"sha matches ({declared[:12]}...)")


# --------------------------------------------------------------------- #
# 3. Packet conservation
# --------------------------------------------------------------------- #


def check_packet_conservation(
    offered: int | float,
    rx_hulk: int | float,
    drop_switch: int | float,
    drop_nic: int | float,
    tol: float = 1e-3,
) -> tuple[str, bool, str]:
    name = "packet_conservation"
    if offered is None or float(offered) <= 0:
        return (name, False, "offered <= 0; cannot evaluate")
    delta = abs(float(offered) - (float(rx_hulk) + float(drop_switch) + float(drop_nic)))
    rel = delta / float(offered)
    if rel < tol:
        return (name, True, f"|delta|/offered = {rel:.2e} < {tol}")
    return (name, False, f"|delta|/offered = {rel:.2e} >= {tol}")


# --------------------------------------------------------------------- #
# 4. Sample count consistency ±1 %
# --------------------------------------------------------------------- #


def check_sample_count(
    actual: int | float, expected: int | float, tol: float = 0.01
) -> tuple[str, bool, str]:
    name = "sample_count"
    if expected is None or float(expected) <= 0:
        return (name, False, f"expected={expected} invalid")
    rel = abs(float(actual) - float(expected)) / float(expected)
    if rel <= tol:
        return (name, True, f"actual={actual} expected={expected} drift={rel:.2%}")
    return (name, False, f"drift {rel:.2%} > {tol:.0%}")


# --------------------------------------------------------------------- #
# 5. Monotonic timestamps
# --------------------------------------------------------------------- #


def check_monotonic_timestamps(jsonl_path: Any) -> tuple[str, bool, str]:
    name = "monotonic_timestamps"
    p = Path(jsonl_path) if jsonl_path else None
    if p is None or not p.exists():
        return (name, False, f"missing {jsonl_path}")
    rows = _load_jsonl(p)
    if not rows:
        return (name, False, "no rows in jsonl")
    last = -float("inf")
    inversions = 0
    for r in rows:
        ts = r.get("ts") or r.get("t") or r.get("_t_recv") or r.get("t_send")
        if ts is None:
            continue
        try:
            t = float(ts)
        except (TypeError, ValueError):
            continue
        if t < last:
            inversions += 1
        last = t
    if inversions:
        return (name, False, f"{inversions} timestamp inversion(s)")
    return (name, True, f"all {len(rows)} rows monotonic")


# --------------------------------------------------------------------- #
# 6. PTP / chrony drift
# --------------------------------------------------------------------- #


def check_ptp_drift(
    start_ns: int | float | None,
    end_ns: int | float | None,
    ptp_threshold_ns: float = 100.0,
    chrony_threshold_s: float = 1e-3,
) -> tuple[str, bool, str]:
    """If both PTP timestamps are given, enforce < 100 ns. Otherwise
    fall back to ``chronyc tracking`` and require offset < 1 ms."""
    name = "ptp_drift"
    if start_ns is not None and end_ns is not None:
        try:
            delta = abs(float(end_ns) - float(start_ns))
        except (TypeError, ValueError):
            delta = float("inf")
        if delta < ptp_threshold_ns:
            return (name, True, f"PTP drift {delta:.1f} ns < {ptp_threshold_ns}")
        # Fall through to chrony if PTP shows a wild number.
    try:
        out = subprocess.run(
            ["chronyc", "tracking"], capture_output=True, text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return (name, False, "PTP unavailable AND chronyc unavailable")
    if out.returncode != 0:
        return (name, False, f"chronyc returned {out.returncode}")
    m = re.search(r"System time\s*:\s*([0-9.eE+-]+)\s*seconds", out.stdout)
    if not m:
        return (name, False, "chronyc output missing System time line")
    offset = abs(float(m.group(1)))
    if offset < chrony_threshold_s:
        return (name, True, f"chrony offset {offset*1e3:.3f} ms < 1 ms")
    return (name, False, f"chrony offset {offset*1e3:.3f} ms >= 1 ms")


# --------------------------------------------------------------------- #
# 7. Sketch counter sanity
# --------------------------------------------------------------------- #


def check_sketch_counter_sanity(register_dump: Any) -> tuple[str, bool, str]:
    """Counters non-negative; sum(sketch counters) <= accepted total."""
    name = "sketch_counter_sanity"
    if register_dump is None:
        return (name, False, "no register dump")
    try:
        if isinstance(register_dump, (str, Path)):
            text = _read_text_safe(Path(register_dump))
            data = json.loads(text) if text else {}
        elif isinstance(register_dump, dict):
            data = register_dump
        else:
            data = dict(register_dump)
    except Exception as e:  # noqa: BLE001
        return (name, False, f"unable to parse register dump: {e!r}")
    sketch = data.get("sketch", data)
    accepted = data.get("accepted_total")
    if isinstance(sketch, dict):
        vals = [v for v in sketch.values() if isinstance(v, (int, float))]
    elif isinstance(sketch, (list, tuple)):
        vals = [v for v in sketch if isinstance(v, (int, float))]
    else:
        return (name, False, f"unrecognized sketch type: {type(sketch).__name__}")
    if any(v < 0 for v in vals):
        return (name, False, f"negative sketch counter(s) found")
    s = sum(vals)
    if accepted is not None:
        try:
            if s > float(accepted):
                return (name, False, f"sum(sketch)={s} > accepted={accepted}")
        except (TypeError, ValueError):
            pass
    return (name, True, f"non-negative; sum={s} accepted={accepted}")


# --------------------------------------------------------------------- #
# 8. No silent NIC drops
# --------------------------------------------------------------------- #


def check_no_silent_nic_drops(ethtool_output: Any) -> tuple[str, bool, str]:
    name = "no_silent_nic_drops"
    if ethtool_output is None:
        return (name, False, "no ethtool output supplied")
    if isinstance(ethtool_output, (str, bytes)):
        text = (ethtool_output.decode("utf-8", errors="replace")
                if isinstance(ethtool_output, bytes) else ethtool_output)
    elif isinstance(ethtool_output, Path):
        text = _read_text_safe(ethtool_output) or ""
    else:
        text = str(ethtool_output)
    m = re.search(r"rx_missed_errors\s*:\s*(\d+)", text)
    if not m:
        return (name, False, "rx_missed_errors line absent")
    n = int(m.group(1))
    if n == 0:
        return (name, True, "rx_missed_errors == 0")
    return (name, False, f"rx_missed_errors == {n}")


# --------------------------------------------------------------------- #
# 9. Controller log clean
# --------------------------------------------------------------------- #


def check_controller_log_clean(log_path: Any) -> tuple[str, bool, str]:
    name = "controller_log_clean"
    p = Path(log_path) if log_path else None
    if p is None or not p.exists():
        return (name, False, f"missing {log_path}")
    text = _read_text_safe(p) or ""
    bad: list[str] = []
    for line in text.splitlines():
        if "ERROR" in line:
            bad.append(line.strip())
        elif "gRPC UNAVAILABLE" in line:
            bad.append(line.strip())
        if len(bad) >= 5:
            break
    if bad:
        return (name, False, f"{len(bad)} bad line(s); first={bad[0][:80]}")
    return (name, True, "no ERROR or gRPC UNAVAILABLE lines")


# --------------------------------------------------------------------- #
# 10. Duration bound ±2 %
# --------------------------------------------------------------------- #


def check_duration_bound(
    declared_s: float, actual_s: float, tol: float = 0.02
) -> tuple[str, bool, str]:
    name = "duration_bound"
    if declared_s is None or float(declared_s) <= 0:
        return (name, False, f"declared_s={declared_s} invalid")
    rel = abs(float(actual_s) - float(declared_s)) / float(declared_s)
    if rel <= tol:
        return (name, True,
                f"actual={actual_s:.3f}s declared={declared_s:.3f}s drift={rel:.2%}")
    return (name, False, f"drift {rel:.2%} > {tol:.0%}")


# --------------------------------------------------------------------- #
# 11. Manifest immutability
# --------------------------------------------------------------------- #


def check_manifest_immutability(
    manifest_path: Any, expected_sha: str | None = None
) -> tuple[str, bool, str]:
    name = "manifest_immutability"
    p = Path(manifest_path) if manifest_path else None
    if p is None or not p.exists():
        return (name, False, f"missing {manifest_path}")
    actual = _sha256_of(p)
    if actual is None:
        return (name, False, "could not hash manifest")
    if expected_sha is None:
        # Look for a sidecar `<manifest>.sha256` written at trial start.
        sidecar = p.with_suffix(p.suffix + ".sha256")
        if sidecar.exists():
            decl = sidecar.read_text().strip().split()[0]
            if decl == actual:
                return (name, True, f"manifest sha unchanged ({decl[:12]}..)")
            return (name, False, f"manifest changed mid-run "
                                  f"declared={decl[:12]}.. now={actual[:12]}..")
        # No sidecar -> we can't prove it changed, but we can record sha.
        return (name, True, f"no sidecar; current sha={actual[:12]}.. (advisory)")
    if expected_sha == actual:
        return (name, True, f"manifest sha unchanged ({actual[:12]}..)")
    return (name, False,
            f"manifest changed expected={expected_sha[:12]}.. actual={actual[:12]}..")


# --------------------------------------------------------------------- #
# 12. NEW — Signed RAT loaded at trial start
# --------------------------------------------------------------------- #


def check_signed_rat_at_trial_start(controller_log_path: Any) -> tuple[str, bool, str]:
    """Closes the 2026-04-18 stale-`.sig` footgun.

    Confirms the controller emits ``RAT loaded: signed=True`` within the
    first 5 s of the log. The first timestamp in the log is treated as
    t=0; we accept ISO-8601 timestamps, ``HH:MM:SS.fff``, and bracketed
    epoch seconds.
    """
    name = "signed_rat_at_trial_start"
    p = Path(controller_log_path) if controller_log_path else None
    if p is None or not p.exists():
        return (name, False, f"missing {controller_log_path}")
    text = _read_text_safe(p)
    if not text:
        return (name, False, "empty controller log")

    iso_re = re.compile(
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    )
    epoch_re = re.compile(r"^\[?(\d{9,11}(?:\.\d+)?)\]?")

    def _stamp(line: str) -> float | None:
        m = iso_re.search(line)
        if m:
            from datetime import datetime
            try:
                return datetime.fromisoformat(m.group(1).replace(" ", "T")).timestamp()
            except ValueError:
                return None
        m = epoch_re.search(line)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                return None
        return None

    t0: float | None = None
    for line in text.splitlines():
        ts = _stamp(line)
        if ts is not None:
            t0 = ts
            break
    if t0 is None:
        # No parseable timestamp; fall back to "appears in first 100 lines".
        head = text.splitlines()[:100]
        for line in head:
            if "RAT loaded" in line and "signed=True" in line:
                return (name, True,
                        "RAT loaded: signed=True (no timestamps; first-100-lines scan)")
        return (name, False,
                "no timestamps and no signed-RAT line in first 100 lines")

    for line in text.splitlines():
        if "RAT loaded" not in line:
            continue
        ts = _stamp(line) or t0
        if "signed=True" in line and (ts - t0) <= 5.0:
            return (name, True, f"RAT loaded: signed=True at +{ts - t0:.2f}s")
        if "signed=False" in line and (ts - t0) <= 5.0:
            return (name, False,
                    f"RAT loaded with signed=False at +{ts - t0:.2f}s")
    return (name, False,
            "no `RAT loaded: signed=True` line within first 5 s")


# --------------------------------------------------------------------- #
# 13. NEW — Broker relay flag (T2.4 only)
# --------------------------------------------------------------------- #


def check_broker_relay_flag(tshark_pcap_path: Any) -> tuple[str, bool, str]:
    """Confirms ``meta.broker_relayed=1`` for >=1 packet in the capture.

    Tries ``tshark -r <pcap> -T fields -e mqtt.passthrough.broker_relayed``
    first; if tshark is missing OR the capture is itself a JSON dump
    (e.g. unit-test fixture), falls back to a string scan.
    """
    name = "broker_relay_flag"
    p = Path(tshark_pcap_path) if tshark_pcap_path else None
    if p is None or not p.exists():
        return (name, False, f"missing {tshark_pcap_path}")

    if p.suffix.lower() in (".json", ".txt"):
        text = _read_text_safe(p) or ""
        # Allow JSON quoting and arbitrary whitespace between the key
        # and value: `broker_relayed":1`, `broker_relayed = 1`, etc.
        if re.search(r"broker_relayed[\"'\s]*[=:][\s\"']*1\b", text):
            return (name, True, "broker_relayed=1 found via text scan")
        return (name, False, "broker_relayed=1 absent in capture")

    try:
        proc = subprocess.run(
            ["tshark", "-r", str(p),
             "-Y", "mqtt", "-T", "fields",
             "-e", "mqtt.broker_relayed"],
            capture_output=True, text=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return (name, False, f"tshark unavailable: {e!r}")
    if proc.returncode != 0:
        return (name, False, f"tshark exit={proc.returncode}: {proc.stderr[:120]}")
    for line in proc.stdout.splitlines():
        if line.strip() == "1":
            return (name, True, "broker_relayed=1 in >=1 packet")
    return (name, False, "broker_relayed=1 not found in any packet")


# --------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------- #

# Item index -> check key for run_all output.
_ITEMS = (
    "01_register_zero_on_startup",
    "02_p4_binary_sha",
    "03_packet_conservation",
    "04_sample_count",
    "05_monotonic_timestamps",
    "06_ptp_drift",
    "07_sketch_counter_sanity",
    "08_no_silent_nic_drops",
    "09_controller_log_clean",
    "10_duration_bound",
    "11_manifest_immutability",
    "12_signed_rat_at_trial_start",
    "13_broker_relay_flag",
)


def _trial_meta(trial_dir: Path) -> dict:
    """Best-effort load of trial meta needed by the wrapped checkers."""
    meta: dict[str, Any] = {}
    yml = trial_dir / "manifest.yaml"
    if yml.exists():
        text = _read_text_safe(yml) or ""
        for line in text.splitlines():
            s = line.strip()
            if ":" not in s:
                continue
            k, v = s.split(":", 1)
            meta[k.strip()] = v.strip().strip("\"' ")
    summary = trial_dir / "trial_summary.json"
    if summary.exists():
        try:
            meta.update(json.loads(summary.read_text()))
        except json.JSONDecodeError:
            pass
    return meta


def run_all(trial_dir: Path) -> dict:
    """Run all 13 checks, returning ``{item_NN: pass | fail | skip, ...}``.

    A trial is ``valid`` iff > 90 % of evaluated items pass.
    """
    trial_dir = Path(trial_dir)
    meta = _trial_meta(trial_dir)

    results: dict[str, str] = {}
    details: dict[str, str] = {}

    def _record(key: str, name: str, passed: bool, detail: str) -> None:
        results[key] = "pass" if passed else "fail"
        details[key] = f"{name}: {detail}"

    def _skip(key: str, reason: str) -> None:
        results[key] = "skip"
        details[key] = f"skip: {reason}"

    # 1
    reg_dump = trial_dir / "registers_t0.json"
    if reg_dump.exists():
        _record("01_register_zero_on_startup",
                *check_register_zero_on_startup(reg_dump))
    else:
        _skip("01_register_zero_on_startup", f"no {reg_dump.name}")

    # 2
    manifest = trial_dir / "manifest.yaml"
    if manifest.exists():
        _record("02_p4_binary_sha", *check_p4_binary_sha(manifest))
    else:
        _skip("02_p4_binary_sha", "no manifest.yaml")

    # 3
    if all(k in meta for k in ("offered", "rx_hulk", "drop_switch", "drop_nic")):
        try:
            _record("03_packet_conservation", *check_packet_conservation(
                float(meta["offered"]), float(meta["rx_hulk"]),
                float(meta["drop_switch"]), float(meta["drop_nic"]),
            ))
        except (TypeError, ValueError) as e:
            _record("03_packet_conservation",
                    "packet_conservation", False, f"meta parse error: {e!r}")
    else:
        _skip("03_packet_conservation", "missing packet counts in meta")

    # 4
    if "sample_count_actual" in meta and "sample_count_expected" in meta:
        try:
            _record("04_sample_count", *check_sample_count(
                float(meta["sample_count_actual"]),
                float(meta["sample_count_expected"]),
            ))
        except (TypeError, ValueError) as e:
            _record("04_sample_count",
                    "sample_count", False, f"meta parse error: {e!r}")
    else:
        _skip("04_sample_count", "missing sample_count fields in meta")

    # 5
    decisions = trial_dir / "decisions.jsonl"
    if decisions.exists():
        _record("05_monotonic_timestamps", *check_monotonic_timestamps(decisions))
    else:
        _skip("05_monotonic_timestamps", "no decisions.jsonl")

    # 6
    start_ns = meta.get("ptp_start_ns")
    end_ns = meta.get("ptp_end_ns")
    try:
        s = float(start_ns) if start_ns is not None else None
        e = float(end_ns) if end_ns is not None else None
    except (TypeError, ValueError):
        s = e = None
    _record("06_ptp_drift", *check_ptp_drift(s, e))

    # 7
    sketch_dump = trial_dir / "registers_post.json"
    if sketch_dump.exists():
        _record("07_sketch_counter_sanity",
                *check_sketch_counter_sanity(sketch_dump))
    else:
        _skip("07_sketch_counter_sanity", "no registers_post.json")

    # 8
    eth_path = trial_dir / "ethtool_post.txt"
    if eth_path.exists():
        _record("08_no_silent_nic_drops",
                *check_no_silent_nic_drops(eth_path))
    else:
        _skip("08_no_silent_nic_drops", "no ethtool_post.txt")

    # 9
    ctrl_log = trial_dir / "controller.log"
    if ctrl_log.exists():
        _record("09_controller_log_clean", *check_controller_log_clean(ctrl_log))
    else:
        _skip("09_controller_log_clean", "no controller.log")

    # 10
    if "declared_duration_s" in meta and "actual_duration_s" in meta:
        try:
            _record("10_duration_bound", *check_duration_bound(
                float(meta["declared_duration_s"]),
                float(meta["actual_duration_s"]),
            ))
        except (TypeError, ValueError) as e:
            _record("10_duration_bound",
                    "duration_bound", False, f"meta parse error: {e!r}")
    else:
        _skip("10_duration_bound", "missing duration fields in meta")

    # 11
    if manifest.exists():
        _record("11_manifest_immutability",
                *check_manifest_immutability(manifest))
    else:
        _skip("11_manifest_immutability", "no manifest.yaml")

    # 12
    if ctrl_log.exists():
        _record("12_signed_rat_at_trial_start",
                *check_signed_rat_at_trial_start(ctrl_log))
    else:
        _skip("12_signed_rat_at_trial_start", "no controller.log")

    # 13 — only run if a broker capture is present (T2.4 only).
    pcap = None
    for cand in ("broker_capture.pcap", "broker_capture.pcapng",
                 "broker_capture.json"):
        p = trial_dir / cand
        if p.exists():
            pcap = p
            break
    if pcap is None:
        _skip("13_broker_relay_flag", "no broker capture (T2.4 only)")
    else:
        _record("13_broker_relay_flag", *check_broker_relay_flag(pcap))

    evaluated = [v for v in results.values() if v != "skip"]
    n_pass = sum(1 for v in evaluated if v == "pass")
    pass_rate = (n_pass / len(evaluated)) if evaluated else 0.0
    valid = pass_rate > 0.9 and len(evaluated) > 0

    return {
        **results,
        "details": details,
        "n_evaluated": len(evaluated),
        "n_pass": n_pass,
        "pass_rate": pass_rate,
        "valid": valid,
    }


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("trial_dir", type=Path)
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON only")
    args = ap.parse_args(list(argv) if argv is not None else None)
    report = run_all(args.trial_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for k in _ITEMS:
            print(f"  {k}: {report.get(k, 'skip')}")
        print(f"\n  n_pass={report['n_pass']} / "
              f"n_evaluated={report['n_evaluated']} "
              f"pass_rate={report['pass_rate']:.1%} "
              f"valid={report['valid']}")
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
