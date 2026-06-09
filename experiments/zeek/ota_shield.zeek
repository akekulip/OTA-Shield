# OTA-Shield comparison script for Zeek.
#
# Implements the per-BMS state and fleet-cardinality counter that
# Suricata's rule DSL cannot express. This is what a Zeek user
# authoring a domain-aware baseline would plausibly write against
# the same PCAP the Suricata comparison uses, so the E10 baseline
# is not a strawman.
#
# Observed events are emitted as notices with OTA-Shield-compatible
# SIDs so the correlation script can reuse its 5-tuple matcher.
#
# Scope:
#   R1  — per-destination rapid replay inside tau_R1 = 14400 s
#   R2  — unauthorized source
#   R4  — cumulative session bytes > 2 MiB
#   R5  — fleet fanout count > 4 inside a 60 s window
#   R6  — per-BMS version-monotonicity (high-water mark)
#
# All thresholds are set to match the numbers OTA-Shield compiles
# into its P4 pipeline, so this baseline is a faithful
# comparison rather than a strawman.

@load base/frameworks/notice
@load base/protocols/mqtt

module OTAShield;

export {
    redef enum Notice::Type += {
        OTA_R1_RapidReplay,
        OTA_R2_UnauthorizedSource,
        OTA_R4_OversizeSession,
        OTA_R5_FleetFanout,
        OTA_R6_VersionRollback,
    };

    const authorized_sources: set[addr] = { 10.0.1.10 };
    const tau_R1_interval: interval = 14400 sec;
    const tau_R4_bytes:   count    = 2097152;
    const tau_R5_count:   count    = 4;
    const tau_R5_window:  interval = 60 sec;

    global last_seen: table[addr] of time &create_expire=14400sec;
    global session_bytes: table[string] of count &create_expire=3600sec;
    global fanout_window_start: time = network_time();
    global fanout_seen: set[addr] &create_expire=60sec;
    global version_hw: table[addr] of count &create_expire=86400sec;
}

function _fivekey(c: connection): string {
    return fmt("%s:%d->%s:%d",
               c$id$orig_h, c$id$orig_p,
               c$id$resp_h, c$id$resp_p);
}

# ---------------------------------------------------------------------
# MQTT PUBLISH hook: called per PUBLISH event by the base mqtt analyzer.
# ---------------------------------------------------------------------
event mqtt_publish(c: connection, is_orig: bool, msg_id: count,
                   msg: MQTT::PublishMsg) {
    if (!is_orig || c$id$resp_p != 1883/tcp) return;

    local src     = c$id$orig_h;
    local dst     = c$id$resp_h;
    local payload = msg$payload;
    local bytes   = |payload|;

    # -------- R2 unauthorized source
    if (src !in authorized_sources) {
        NOTICE([$note=OTA_R2_UnauthorizedSource,
                $conn=c,
                $msg=fmt("R2: unauthorized OTA source %s", src),
                $sub=_fivekey(c)]);
        return;   # R2 is terminal in the reference design
    }

    # -------- R1 rapid replay (per destination)
    local now = network_time();
    if (dst in last_seen && now - last_seen[dst] < tau_R1_interval) {
        NOTICE([$note=OTA_R1_RapidReplay,
                $conn=c,
                $msg=fmt("R1: rapid replay to %s (dt=%.1fs)",
                         dst, now - last_seen[dst]),
                $sub=_fivekey(c)]);
    }
    last_seen[dst] = now;

    # -------- R5 fleet fanout (approx. tumbling 60 s window)
    if (now - fanout_window_start > tau_R5_window) {
        fanout_seen = set();
        fanout_window_start = now;
    }
    add fanout_seen[dst];
    if (|fanout_seen| > tau_R5_count) {
        NOTICE([$note=OTA_R5_FleetFanout,
                $conn=c,
                $msg=fmt("R5: fleet fanout count=%d > %d",
                         |fanout_seen|, tau_R5_count),
                $sub=_fivekey(c)]);
    }

    # -------- R4 cumulative session bytes (per 5-tuple)
    local k = _fivekey(c);
    if (k !in session_bytes) session_bytes[k] = 0;
    session_bytes[k] += bytes;
    if (session_bytes[k] > tau_R4_bytes) {
        NOTICE([$note=OTA_R4_OversizeSession,
                $conn=c,
                $msg=fmt("R4: session bytes=%d > %d",
                         session_bytes[k], tau_R4_bytes),
                $sub=_fivekey(c)]);
    }

    # -------- R6 version-monotonicity (if payload begins with 'OTAS')
    if (|payload| >= 8 && payload[0:4] == "OTAS") {
        local v = 0;
        local i: count;
        for (i in set(0,1,2,3)) {
            v = v * 256 + bytestring_to_count(payload[4+i:5+i]);
        }
        if (dst in version_hw && v < version_hw[dst]) {
            NOTICE([$note=OTA_R6_VersionRollback,
                    $conn=c,
                    $msg=fmt("R6: v=%d < hw=%d on %s",
                             v, version_hw[dst], dst),
                    $sub=_fivekey(c)]);
        }
        if (dst !in version_hw || v > version_hw[dst]) {
            version_hw[dst] = v;
        }
    }
}
