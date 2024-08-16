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
	@echo " > Regenerate Symbolicator signatures"
	DO_KERNELS=1 scripts/all.py 

.PHONY: refresh-kexts
refresh-kexts:
	@echo " > Regenerate Symbolicator signatures"
	DO_KEXTS=1 scripts/all.py 

.PHONY: install-plugin
install-plugin:
	@echo " > Installing IDA Plugin"
	plugins/ida/install.sh

.PHONY: fmt
fmt:
	black -l 120 scripts/
	isort scripts/