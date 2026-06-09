# RAT manifest fields

`rat.json`, `rat_e12.json`, and `rat_stale_e12.json` all follow the same
schema, but some fields are advisory metadata rather than arbiter inputs.

## Enforced fields

- `authorized_source_ips`, `authorized_targets` — Gate A source/target match
- `valid_window_start` / `valid_window_end` — Gate A active-window check
- `rollback_window` (optional) — Gate B version range for R6 demotion

## Advisory fields (not consulted by the arbiter)

- `max_concurrent_targets` — documentation only. The controller does NOT
  enforce this bound and the P4 pipeline cannot see it. Different files
  intentionally carry different values (5, 5, 50) to illustrate that the
  arbiter's behavior is identical in all three cases. Do not rely on this
  as a defensive parameter; see §6.2 of the paper.

## Reload semantics

The controller loads the active RAT file once at startup. There is no
SIGHUP or inotify reload path in the current implementation: operators
editing RAT JSON mid-run will see no effect until the controller is
restarted. A signed-manifest pipeline with a monotonic sequence number
and a documented reload mechanism is the intended closure for this gap.
