.PHONY: generate
generate:
	@echo " > Generating Symbolicator signatures"
	ida/run.sh 

.PHONY: refresh
refresh:
	@echo " > Regenerate Symbolicator signatures"
	ida/all.py 

.PHONY: verify
verify:
	@echo " > Verifying signatures syntax/format"
	pkl eval kernel/**/*.pkl

.PHONY: install-plugin
install-plugin:
	@echo " > Installing IDA Plugin"
	ida/plugins/install.sh ida/plugins/symbolicate.py