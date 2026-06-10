/* OTA-Shield — session_manager.p4
 *
 * Per-session byte counter + first-timestamp + finalize logic.
 *
 * Registers:
 *   session_bytes_reg    : u32 × 65536  ~256 KB  (1 MAU stage)
 *   session_first_ts_reg : u32 × 65536  ~256 KB  (1 MAU stage)
 *
 * Session index = CRC32 of the 5-tuple, truncated to 16 bits. Birthday
 * collision probability is N(N-1) / 2^17 for N concurrent sessions
 * (~0.76% at N=1000; see §6.2 of the paper for production-scale
 * discussion). Collisions mis-attribute bytes between two flows that
 * happen to hash identically;
 * R4 (size) therefore may fire on the wrong session. Collision rate at the
 * evaluation scale is low enough that this does not materially affect
 * detection, but it is a documented limitation (not "harmless").
 *
 * session_bytes tracks TCP payload bytes (NOT including IP/TCP headers) so
 * that R4's "2 MB max firmware size" threshold is a true firmware-byte
 * threshold. The control plane computes `meta.l4_payload_len` before
 * invoking this control (see ingress_control.p4).
 *
 * first_ts sentinel: a 32-bit register initialised to 0. On first packet we
 * write `ts_lo32 | 1` so the slot is guaranteed non-zero post-write,
 * eliminating the 1-in-2^32 sentinel ambiguity.
 */

#ifndef _OTA_SHIELD_SESSION_MANAGER_P4_
#define _OTA_SHIELD_SESSION_MANAGER_P4_

#include "headers.p4"

control SessionManager(
    inout header_t   hdr,
    inout metadata_t meta)
{
    /* ---------- Session ID hash ---------- */
    Hash<session_idx_t>(HashAlgorithm_t.CRC32) session_hash;

    action compute_session_id() {
        meta.session_id = session_hash.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            hdr.ipv4.protocol
        });
    }

    /* ---------- session_bytes register (payload bytes only) ---------- */
    Register<bit<32>, session_idx_t>(SESSION_TABLE_SIZE, 0) session_bytes_reg;

    RegisterAction<bit<32>, session_idx_t, bit<32>>(session_bytes_reg)
    session_bytes_add = {
        void apply(inout bit<32> v, out bit<32> r) {
            v = v + (bit<32>)meta.l4_payload_len;
            r = v;
        }
    };

    RegisterAction<bit<32>, session_idx_t, bit<32>>(session_bytes_reg)
    session_bytes_read_clear = {
        void apply(inout bit<32> v, out bit<32> r) {
            r = v + (bit<32>)meta.l4_payload_len;
            v = 0;
        }
    };

    /* ---------- session_first_ts register ---------- */
    Register<bit<32>, session_idx_t>(SESSION_TABLE_SIZE, 0) session_first_ts_reg;

    /* Write `ts_lo32 | 1` (guaranteed non-zero) only on first packet (slot == 0). */
    RegisterAction<bit<32>, session_idx_t, bit<32>>(session_first_ts_reg)
    session_first_ts_set = {
        void apply(inout bit<32> v, out bit<32> r) {
            if (v == 0) {
                v = meta.ts_lo32 | 32w1;
            }
            r = v;
        }
    };

    RegisterAction<bit<32>, session_idx_t, bit<32>>(session_first_ts_reg)
    session_first_ts_read_clear = {
        void apply(inout bit<32> v, out bit<32> r) {
            r = v;
            v = 0;
        }
    };

    apply {
        compute_session_id();

        if (meta.is_session_end == 1) {
            meta.session_bytes_val    = session_bytes_read_clear.execute(meta.session_id);
            meta.session_first_ts_val = session_first_ts_read_clear.execute(meta.session_id);
        } else {
            meta.session_bytes_val    = session_bytes_add.execute(meta.session_id);
            meta.session_first_ts_val = session_first_ts_set.execute(meta.session_id);
        }
    }
}

#endif /* _OTA_SHIELD_SESSION_MANAGER_P4_ */
