test:
	@echo "Launching tests"
	@ NODE_ENV="test" ./node_modules/.bin/mocha --timeout 2000 --reporter spec
	@echo "Tests finished"

testVersionSwitch:
	@echo "Testing that node-pbkdf2 works across version switches"
	@ ./test/testVersionSwitch.sh

.PHONY: test
