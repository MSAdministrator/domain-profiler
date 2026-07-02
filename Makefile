# Makefile for domain-profiler development

.PHONY: help install test test-fast test-coverage test-unit test-integration clean lint format check mutation mutation-module mutation-results mutation-survivors mutation-html mutation-clean

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package in development mode with all dependencies
	pip install -e ".[dev]"

test:  ## Run all tests with coverage
	pytest --cov=domain_profiler --cov-report=term-missing --cov-report=html

test-fast:  ## Run tests in parallel (fast)
	pytest -n auto

test-unit:  ## Run unit tests only
	pytest -m unit

test-integration:  ## Run integration tests only
	pytest -m integration

test-coverage:  ## Generate detailed coverage report
	pytest --cov=domain_profiler --cov-report=html --cov-report=xml --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"

test-verbose:  ## Run tests with verbose output
	pytest -v

test-specific:  ## Run specific test file (use TEST_FILE=path/to/test.py)
	pytest $(TEST_FILE) -v

clean:  ## Clean up build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

lint:  ## Run linting and type checking
	uv run mypy src/domain_profiler --ignore-missing-imports

type-check:  ## Run type checking with mypy
	uv run mypy src/domain_profiler --ignore-missing-imports --show-error-codes

format:  ## Format code (if you add formatting tools later)
	@echo "Add formatting tools like black, isort to pyproject.toml for this target"

check:  ## Run all checks (tests, linting, etc.)
	$(MAKE) test
	$(MAKE) type-check

build:  ## Build package
	python -m build

install-from-source:  ## Install from source
	pip install -e .

run-example:  ## Run example commands
	@echo "Running DNS analysis example:"
	domain-profiler run example.com
	@echo ""
	@echo "Running live analysis example (will make real network calls):"
	domain-profiler run example.com --live

dev-setup:  ## Complete development setup
	$(MAKE) install
	@echo "Development environment ready!"
	@echo "Run 'make test' to run the test suite"

# --- Mutation testing (test-quality) ---------------------------------------
# Mutation testing measures whether tests would *catch* bugs, not just run code.
# Config lives in [tool.mutmut] in pyproject.toml. See the test-quality skill
# for the full sufficiency->necessity workflow.

mutation:  ## Run mutation testing on the whole package (slow)
	uv run mutmut run

mutation-module:  ## Mutate one module only, e.g. `make mutation-module MODULE=caa`
	@test -n "$(MODULE)" || (echo "Usage: make mutation-module MODULE=<name>  (e.g. caa)"; exit 1)
	uv run mutmut run 'domain_profiler.$(MODULE).*'

mutation-results:  ## Show the full mutant result list
	uv run mutmut results

mutation-survivors:  ## List only surviving mutants (test gaps to close)
	@uv run mutmut results 2>/dev/null | grep ': survived' || echo "No surviving mutants 🎉"

mutation-html:  ## Generate the browsable HTML mutation report
	uv run mutmut html
	@echo "Open html/index.html"

mutation-clean:  ## Remove mutmut's cache/output
	rm -rf mutants/ .mutmut-cache html/
	@echo "Run 'make help' to see all available commands" 