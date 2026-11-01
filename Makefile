.PHONY: test check build

test:
	python -m unittest discover -s tests -v

check:
	python -m compileall -q src tests
	python -m unittest discover -s tests -v
	python -m pip check

build:
	python -m build
