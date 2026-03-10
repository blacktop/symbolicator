PYTHON ?= python3
ALL_SCRIPT := scripts/all.py

.PHONY: generate
generate:
	@echo " > Generating Symbolicator signatures"
	scripts/run.sh

.PHONY: refresh
refresh: DO_KEXTS=1
refresh: DO_KERNELS=1
refresh: refresh-kexts refresh-xnus

.PHONY: refresh-xnus
refresh-xnus:
	@echo " > Regenerating xnu Symbolicator signatures"
	DO_KERNELS=1 $(PYTHON) $(ALL_SCRIPT)

.PHONY: refresh-kexts
refresh-kexts:
	@echo " > Regenerating Symbolicator signatures from KDK extensions"
	DO_KEXTS=1 $(PYTHON) $(ALL_SCRIPT)

.PHONY: install-plugin
install-plugin:
	@echo " > Installing IDA Plugin"
	plugins/ida/install.sh

.PHONY: fmt
fmt:
	black -l 120 scripts/
	isort scripts/

.PHONY: ida-log
ida-log:
	tail -f /tmp/ida.log
