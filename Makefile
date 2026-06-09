# OTA-Shield — top-level Makefile
#
# Thin wrapper that delegates to p4build/Makefile for P4 operations and
# runs the controller / smoke tests directly.

SHELL := /bin/bash

.PHONY: all build smoke load resource controller test clean help

all: build

help:
	@echo "OTA-Shield make targets:"
	@echo "  build       Compile the P4 program (bf-p4c)"
	@echo "  smoke       Compile and run tofino-model smoke test"
	@echo "  load        Load the compiled pipeline on hardware"
	@echo "  resource    Print the MAU/SRAM/TCAM/hash resource report"
	@echo "  controller  Start the Python P4Runtime controller"
	@echo "  test        Run PTF smoke tests"
	@echo "  clean       Remove build artefacts"

build:
	$(MAKE) -C p4build build

smoke:
	$(MAKE) -C p4build smoke

load:
	$(MAKE) -C p4build load

resource:
	$(MAKE) -C p4build resource

controller:
	cd controller && python3 ota_shield_controller.py

test:
	bash testing/smoke/run_model.sh

clean:
	$(MAKE) -C p4build clean
