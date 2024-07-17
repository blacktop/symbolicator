.PHONY: generate
verify:
	@echo " > Generating Symbolicator signatures"
	ida/run.sh 

.PHONY: verify
verify:
	@echo " > Verifying signatures syntax/format"
	pkl eval kernel/**/*.pkl

.PHONY: install-plugin
install-plugin:
	@echo " > Installing IDA Plugin"
	ida/plugins/install.sh ida/plugins/symbolicate.py