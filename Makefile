.PHONY: help install build test dev scan rules test-rules dashboard link unlink pack clean

help:
	@echo "Preflight dev commands:"
	@echo "  make install     Install dependencies (npm ci)"
	@echo "  make build       Build CLI (tsup)"
	@echo "  make test        Run tests"
	@echo "  make dev         Run CLI from TS (preflight scan .)"
	@echo "  make scan        Scan current directory (dist)"
	@echo "  make rules       List rules (dist)"
	@echo "  make test-rules  Validate rule fixtures (dist)"
	@echo "  make dashboard   Serve dashboard (dist)"
	@echo "  make link        Create global preflight symlink (npm link)"
	@echo "  make unlink      Remove global preflight symlink"
	@echo "  make pack        Create npm tarball (npm pack)"
	@echo "  make clean       Remove build artifacts"

install:
	npm ci

build:
	npm run build

test:
	npm test

dev:
	npm run dev -- scan .

scan:
	npm run build
	node dist/cli.js scan .

rules:
	npm run build
	node dist/cli.js rules

test-rules:
	npm run build
	node dist/cli.js test-rules

dashboard:
	npm run build
	node dist/cli.js dashboard

link:
	npm link

unlink:
	npm unlink -g preflight

pack:
	npm pack

clean:
	rm -rf dist
