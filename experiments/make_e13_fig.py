"""Generate fig_override_capacity.pdf from E13 correlator output."""
import sys
from pathlib import Path
sys.path.insert(0, "/home/philip/OTA/ota_shield/experiments")
from figures import fig_override_capacity

base = Path("/home/philip/OTA/ota_shield/runs")
fig_override_capacity(
    base / "override_capacity" / "active_over_time.csv",
    base / "override_capacity" / "summary.csv",
    base / "figures" / "fig_override_capacity",
)
print("wrote fig_override_capacity.pdf")
