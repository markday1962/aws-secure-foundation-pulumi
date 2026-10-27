PROJECTS := account-baseline network

.PHONY: install test lint

install:
	@for p in $(PROJECTS); do (cd $$p && uv sync) || exit 1; done

test:
	@for p in $(PROJECTS); do (cd $$p && uv run pytest) || exit 1; done

lint:
	@for p in $(PROJECTS); do (cd $$p && uv run ruff format --check . && uv run ruff check . && uv run pyright) || exit 1; done
