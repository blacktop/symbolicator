.PHONY: generate
generate:
	@echo " > Generating Symbolicator signatures"
	ida/run.sh 

.PHONY: refresh
refresh:
	@echo " > Regenerate Symbolicator signatures"
	ida/all.py 

.PHONY: install-plugin
install-plugin:
	@echo " > Installing IDA Plugin"
	ida/plugins/install.sh

.PHONY: fmt
fmt:
	black -l 120 ida/