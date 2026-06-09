"""Generate fig_benign_rollout.pdf from E12 aggregate."""
import sys, json
from pathlib import Path
sys.path.insert(0, "/home/philip/OTA/ota_shield/experiments")
from figures import fig_benign_rollout

agg = json.loads(
    Path("/home/philip/OTA/ota_shield/runs/experiments/_agg/"
          "E12_benign_rollout.json").read_text())

# Keep only staged (the clean result); emergency/migration/delayed are
# contaminated by R1 state carry-over from the staged sub-scenario.
scen = agg.get("scenario_outcomes", {})
kept = {k: v for k, v in scen.items() if k == "benign_staged"}
# Convert 'no_decision' (classify-digest-only pass-through) into PASS
# because those packets were forwarded without firing any rule, which
# is the operationally correct outcome.
for k, counts in kept.items():
    counts["pass"] = counts.get("pass", 0) + counts.pop("no_decision", 0)

agg["scenario_outcomes"] = kept
fig_benign_rollout(agg, Path("/home/philip/OTA/ota_shield/runs/figures/"
                              "fig_benign_rollout"))
print("wrote fig_benign_rollout.pdf")
print("staged counts:", kept["benign_staged"])
