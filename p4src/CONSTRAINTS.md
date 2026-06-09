# Tofino 1 P4 constraint classes (bf-p4c)

Future-incident grepability for the OTA-Shield P4 pipeline. Compiled
against Tofino 1 with bf-p4c (SDE 9.13.2 series). Eight constraint
classes plus two operational caveats — every one of these bit
OTA-Shield or its sibling pipelines during bringup; knowing them
upfront saves hours of bisection.

**Before modifying any of `headers.p4`, `parser.p4`,
`ingress_control.p4`, `policy_engine.p4`, `session_manager.p4`,
`fleet_monitor.p4`, `secondary_rules.p4`, `rule_r6_rollback.p4`, or
`deparser.p4` — re-read this file.** Several of the workarounds look
non-idiomatic and a well-meaning refactor will silently re-introduce
the original error class.

---

## Class 1 — 44-bit gateway predicate input

**Symptom**: `BUG_CHECK pred_size <= 44 (XX)` from MAU resource fitting
when an `if` chain combines a 32-bit magnitude compare (`<` or `>`)
with any other PHV-consuming predicate.

**Why**: Each gateway in the MAU pipeline consumes at most 44 bits of
PHV input. A `bit<32>` magnitude compare (lt / gt) burns 4 bytes
of that budget; combining with even a single second predicate
overflows.

**Fix**: Replace magnitude compares in gateways with range-match
tables (MAU TCAM range entries — no gateway PHV consumed).

**Where it bit OTA-Shield**: R1 cadence threshold check
(`coarse_time_sec_lo - last_seen < tau_R1`) initially in a gateway;
moved to a range-match table in `secondary_rules.p4`.

---

## Class 2 — Range-match key ≤ 20 bits (5 PHV nibbles)

**Symptom**: `Range match table requires too many nibbles` or fitter
failure when a TCAM range key is wider than `bit<20>`.

**Why**: TCAM range matching consumes one nibble per range pair, and
the per-table range nibble budget is 5.

**Fix**: Slice the field down to ≤20 bits (`session_bytes_val[31:16]`)
or scale to wider units (KB instead of bytes), or split into multiple
tables matched in series.

**Where it bit OTA-Shield**: R4 size-bucket gating used `bit<32>`
session_bytes; sliced to `[31:16]` (effectively 64KB resolution,
sufficient for the 1-2 MB OTA payload envelope).

---

## Class 3 — Byte-aligned PHV preferred

**Symptom**: `invalid SuperCluster` or `cannot allocate PHV` when
sub-byte fields (`bit<1>`, `bit<2>`, `bit<3>`, `bit<4>`) sit adjacent
to 32-bit register outputs in the same metadata struct.

**Why**: PHV allocation prefers byte-aligned containers; sub-byte
fields cluster into shared containers that conflict with adjacent
wide reads.

**Fix**: Widen every flag/counter field to `bit<8>` even when only
the LSB is meaningful. The PHV cost is negligible; the allocator
cost of a SuperCluster failure is hours.

**Where it bit OTA-Shield**: All `r1_fired`, `r2_fired`, ...,
`r6_fired` are `bit<8>` despite carrying a single bit of meaning.

---

## Class 4 — 48-byte learn quantum max

**Symptom**: `Learning quanta requires N bytes, greater than maximum
48`.

**Why**: Tofino 1 learn-filter digest payload is capped at 48 bytes
per quantum.

**Fix**: Trim digest fields, or slice wide headers
(`hdr.topic.bytes[255:160]` for a 96-bit prefix instead of the full
256-bit topic).

**Where it bit OTA-Shield**: The classify_digest carries a 96-bit
topic prefix (not the full 256), plus 5-tuple, plus rule bitmap, plus
session_id — fits in 48 bytes.

---

## Class 5 — Single-stage action arithmetic

**Symptom**: `action spanning multiple stages` when a single action
performs runtime-computed multi-operand arithmetic
(e.g. `a - b - c` with all three runtime values).

**Why**: A Tofino MAU action is single-stage; multi-operand subtract
where all operands are runtime PHV reads cannot be folded into a
single ALU op.

**Fix**: Pre-compute the partial result in metadata in an earlier
stage, or use compile-time constants for at least one operand.

**Where it bit OTA-Shield**: R1 inter-update delta originally had a
TTL-decrement chained into the same action; split into a metadata
prepass.

---

## Class 6 — bf-p4c silent ICE on sub-word end-around-carry  (★)

**Symptom**: `1 error generated` with **NO error text**, followed by
`Internal compiler error`. No source line cited.

**The trigger pattern** (idiomatic RFC 1624 one's-complement carry):

```p4
bit<17> tmp = (bit<17>)hdr.icmp.checksum + 17w0x0800;
hdr.icmp.checksum = tmp[15:0] + (bit<16>)tmp[16:16];
```

**Why**: bf-p4c on Tofino 1 cannot lower a `bit<N+1>` temp + slice +
add-carry into native ALU ops; instead of erroring on the construct,
the front-end ICEs without text. Cost two full bisection sessions
(8 compiles) to isolate on the p4_decoy Phase 0 work.

**Fix**: Guarded two-case constant add — mathematically equivalent
for all 65,536 inputs but uses only native `bit<16>` ALU ops:

```p4
if (hdr.icmp.checksum >= 16w0xF800) {
    hdr.icmp.checksum = hdr.icmp.checksum + 16w0x0801;
} else {
    hdr.icmp.checksum = hdr.icmp.checksum + 16w0x0800;
}
```

Threshold is `0x10000 - delta` for any delta. Generalizes to any
end-around-carry update where the delta is a compile-time constant.

**★ Most important entry in this file**: this is the only class
that fails *silently*. If you see "1 error generated" with empty
output, suspect this first.

---

## Class 7 — Dynamic Hash cannot be reused across different tuple shapes

**Symptom**: `MAU::HashGenExpression : Hash.get over dynamic hash
<name>.configure differ: Dynamic hashes must have the same field
list and sets of algorithm for each get call`.

**Why**: A `Hash<bit<N>>` extern remembers the field list of its
first `.get(...)` call and rejects subsequent calls with a different
tuple shape — even if the polynomial is identical.

**Fix**: Instantiate a separate `CRCPolynomial` + `Hash` per tuple
shape. Even identical polynomials over different field lists are
fine; the compiler just enforces one field list per Hash instance.

**Canary warning**: `Expected single call to get for hash instance` —
if you see this on a build that succeeded, the next change to the
hash's call sites with a different tuple will trigger the error
above.

**Where it bit a sibling pipeline**: p4_decoy Phase 1 reused a
`crc16_dnp` instance — once on `bit<64>` Phase 0 input, once on
`bit<128>` Phase 1 user block. Split into two Hash instances over
the same polynomial.

---

## Class 8 — SALU `if v == 0` sentinel branches

**Symptom**: SALU body with `if (value == 0) { ... } else { ... }`
compiles to a flattened branch that does not respect the sentinel
condition at runtime.

**Why**: bf-p4c flattens certain SALU `==` conditional branches
during peephole; the runtime behavior diverges from the source.

**Fix**: Do not rely on in-SALU `v == 0` sentinels. Seed register
slots from the controller at startup so every cell holds a known
non-zero or known-zero value, then branch on a different condition
inside the SALU.

---

## Operational caveat — Learn-digest name resolution

`bfrt_grpc` publishes digests by **instance name** (e.g.
`classify_digest`) — not by type name
(`phase1_classify_digest_t`). When attaching a controller-side
listener, match incoming `DigestList` against `digest.digest_id`
of each `pipe.ingress.classify_digest` learn, not the struct type.

This is not a bf-p4c constraint per se, but consumes the same
debugging budget when the controller silently never receives any
digest.

---

## Operational caveat — `ipv4_to_int` duplicated across controller

`controller/rat_arbiter.py:54` (uses `assert` — hard-fails on
malformed input) and `controller/rat_lifecycle.py:152` (uses
`ValueError` — graceful) both implement `ipv4_to_int`. The
duplication is **intentional**: the comment at `rat_arbiter.py:55-57`
explains it — `rat_arbiter.py` is loaded by the M7 Suricata wrapper
which must avoid the `bfrt_grpc` import chain that
`rat_lifecycle.py` pulls in.

Do not consolidate without rerouting the import chain. Disclosure
in §6.6 of the paper acknowledges the duplication as a measurement
artifact, not a refactor target.

---

## Why these constraints exist as a separate doc

Six of these (classes 1-5, 8) ate roughly 8 compile-iteration cycles
during OTA-Shield bringup. Class 6 cost two full bisection sessions
on the silent ICE. Class 7 emerged on the p4_decoy sibling. Each
costs hours when re-encountered cold; minutes when looked up here
first. Treat this as the "stop-the-line" doc — when bf-p4c emits a
strange error, search this file before searching the SDE
documentation.

**Updates**: append new classes here as they surface; do not
re-order classes 1-8 (existing references in this doc cite them by
number).
