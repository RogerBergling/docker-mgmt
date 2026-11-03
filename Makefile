.PHONY: help test lint check run

help:
	@printf '%s\n' \
		'make test   Run the standard-library unit tests' \
		'make lint   Byte-compile the package and tests' \
		'make check  Run lint and tests (validation target)' \
		'make run    Start the interactive menu'

test:
	python3 -m unittest discover -s tests -t . -v

lint:
	python3 -m compileall -q docker_mgmt tests

check: lint test

run:
	python3 -m docker_mgmt
