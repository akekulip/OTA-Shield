# OTA-Shield — p4build/Makefile
#
# Matches your existing bf_switchd pattern:
#   SDE         = /home/decps/Downloads/bf-sde-9.13.2
#   build dir   = $(SDE)/build/ota_shield/
#   conf file   = $(SDE)/build/ota_shield/ota_shield.conf
#
# Usage (from project root):
#   make build         # compile with bf-p4c
#   make resource      # print MAU/SRAM/hash utilisation
#   make smoke         # compile + tofino-model PTF
#   make load          # start bf_switchd on hardware (uses run_switch.sh)
#   make kmod          # load kernel driver (first-time per boot)
#   make clean

SDE         ?= /opt/bf-sde-9.13.2
SDE_INSTALL ?= $(SDE)/install
P4_PROG     := ota_shield
P4SRC_DIR   := ../p4src
P4_SRC      := $(P4SRC_DIR)/$(P4_PROG).p4
OUTDIR      := $(SDE)/build/$(P4_PROG)
CONF_FILE   := $(OUTDIR)/$(P4_PROG).conf
BFP4C       := $(SDE_INSTALL)/bin/bf-p4c
BF_SWITCHD  := $(SDE_INSTALL)/bin/bf_switchd
BF_KDRV     := $(SDE_INSTALL)/bin/bf_kdrv_mod_load
STATUS_PORT ?= 7777

.PHONY: build resource smoke load kmod clean check-sde help

help:
	@echo "Targets:"
	@echo "  build      Compile P4 program with bf-p4c"
	@echo "  resource   Print MAU/SRAM/hash resource report"
	@echo "  smoke      Compile + run tofino-model PTF suite"
	@echo "  kmod       Load bf_kdrv kernel module (first time per boot)"
	@echo "  load       Start bf_switchd on hardware"
	@echo "  clean      Remove build artefacts"
	@echo ""
	@echo "Env:"
	@echo "  SDE=$(SDE)"
	@echo "  OUTDIR=$(OUTDIR)"

check-sde:
	@if [ ! -x "$(BFP4C)" ]; then \
		echo "ERROR: bf-p4c not found at $(BFP4C)"; \
		echo "Set SDE=<path> or install BF-SDE 9.13.2"; \
		exit 1; \
	fi
	@echo "SDE        : $(SDE)"
	@echo "SDE_INSTALL: $(SDE_INSTALL)"
	@echo "OUTDIR     : $(OUTDIR)"

build: check-sde
	@mkdir -p $(OUTDIR)
	$(BFP4C) \
	    --target tofino \
	    --arch tna \
	    --std p4-16 \
	    -I$(P4SRC_DIR) \
	    -o $(OUTDIR) \
	    $(P4_SRC)
	@echo ""
	@echo "=== Build OK ==="
	@echo "Conf file: $(CONF_FILE)"
	@if [ -f $(OUTDIR)/pipe/logs/mau.resources.log ]; then \
		echo ""; \
		echo "=== MAU resource utilisation (first 60 lines) ==="; \
		head -60 $(OUTDIR)/pipe/logs/mau.resources.log; \
	fi

resource:
	@if [ -f $(OUTDIR)/pipe/logs/mau.resources.log ]; then \
		less $(OUTDIR)/pipe/logs/mau.resources.log; \
	else \
		echo "No resource log. Run 'make build' first."; \
	fi

smoke: build
	@bash ../testing/smoke/run_model.sh $(P4_PROG)

kmod: check-sde
	@echo "Loading bf_kdrv kernel module..."
	sudo $(BF_KDRV) $(SDE_INSTALL) 2>/dev/null || true
	@echo "Done."

load: check-sde
	@if [ ! -f $(CONF_FILE) ]; then \
		echo "ERROR: $(CONF_FILE) not found. Run 'make build' first."; \
		exit 1; \
	fi
	@echo "Starting bf_switchd with $(P4_PROG)..."
	@echo "  conf: $(CONF_FILE)"
	@echo "  status port: $(STATUS_PORT)"
	sudo $(BF_SWITCHD) \
	    --install-dir $(SDE_INSTALL) \
	    --conf-file $(CONF_FILE) \
	    --status-port $(STATUS_PORT)

clean:
	rm -rf $(OUTDIR)
	@echo "Removed $(OUTDIR)"
