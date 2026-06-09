# setup_ports_ota.py — Enable ports 8 (Vision 15/0) and 11 (Hulk 15/3) at 25G
#
# Usage on switch:
#   cd /home/decps/Downloads/bf-sde-9.13.2
#   ./run_bfshell.sh -b /home/decps/my_program/ota/setup_ports_ota.py
#
# Minimal: the ota_shield P4 program has compile-time const l2_forward
# entries between PORT_VISION and PORT_HULK, so no runtime forwarding
# rules are needed. Only port enablement is required after bf_switchd
# (re)start.

for port, label in ((8, "Vision 15/0"), (11, "Hulk 15/3")):
    try:
        bfrt.port.port.add(
            DEV_PORT=port,
            SPEED="BF_SPEED_25G",
            FEC="BF_FEC_TYP_NONE",
            AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE",
            PORT_ENABLE=True,
        )
        print(f"Port {port} ({label}) configured")
    except Exception as exc:
        print(f"Port {port} ({label}) add failed or exists: {exc!r}")

print("OTA-Shield port setup complete.")
