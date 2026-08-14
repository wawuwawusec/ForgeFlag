.PHONY: test smoke start stop restart status build-exe docker-build clean

test:
	PYTHONPATH=src python3 -m unittest discover -s tests

build-exe:
	pyinstaller --clean --noconfirm forgeflag.spec

docker-build:
	scripts/forgeflag-control docker-build

clean:
	rm -rf build dist .forgeflag/smoke.sqlite .forgeflag/smoke-input

smoke:
	rm -f .forgeflag/smoke.sqlite
	rm -rf .forgeflag/artifacts/smoke-forensics
	mkdir -p .forgeflag/smoke-input
	printf 'flag{forgeflag_smoke_local}\n' > .forgeflag/smoke-input/flag.txt
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/smoke.sqlite init
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/smoke.sqlite add-challenge smoke-forensics --category forensics --attachment .forgeflag/smoke-input/flag.txt
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/smoke.sqlite run smoke-forensics
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/smoke.sqlite findings smoke-forensics
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/smoke.sqlite observations smoke-forensics
	PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/smoke.sqlite report smoke-forensics

start:
	scripts/forgeflag-control start

start-mcp:
	scripts/forgeflag-control start --mcp

stop:
	scripts/forgeflag-control stop

restart:
	scripts/forgeflag-control restart

status:
	scripts/forgeflag-control status
