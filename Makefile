# Serrier — vanliga kommandon. `make` eller `make help` listar dem.
.DEFAULT_GOAL := help
.PHONY: help dev test lint scan guard

help:  ## Visa den här hjälpen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-10s\033[0m %s\n", $$1, $$2}'

dev:  ## Starta backend + frontend med ett kommando (Ctrl-C stänger båda)
	@./scripts/dev.sh

test:  ## Kör backend-testsviten
	@cd backend && uv run pytest -q

lint:  ## Ruff (kod + tester)
	@cd backend && uv run ruff check serrier tests

scan:  ## Skanna ett repo lokalt: make scan REPO=/sökväg (ingen server behövs)
	@cd backend && uv run python -m serrier.cli "$(abspath $(REPO))"

guard:  ## Kör ett AI-verktyg genom Pre-Send Guardian: make guard CMD="claude"
	@cd backend && uv run serrier-guard run -- $(CMD)
