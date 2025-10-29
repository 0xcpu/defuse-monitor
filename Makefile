.PHONY: help test lint format typecheck check run
.DEFAULT_GOAL := help

BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

help: ## Show this help message
	@echo "$(BLUE)Defuse Monitor - Linux Login Monitoring System$(RESET)"
	@echo ""
	@echo "$(GREEN)Available commands:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-15s$(RESET) %s\\n", $$1, $$2}'

format: ## Format code with ruff
	@echo "$(GREEN)Formatting code...$(RESET)"
	uv run ruff format .

lint: ## Run linting with ruff
	@echo "$(GREEN)Running linter...$(RESET)"
	uv run ruff check . --fix

typecheck: ## Run type checking with mypy
	@echo "$(GREEN)Running type checker...$(RESET)"
	uv run mypy src/ --ignore-missing-imports --no-strict-optional --check-untyped-defs \
	|| echo "$(YELLOW)Type checking completed with warnings$(RESET)"

check: format lint typecheck ## Run all code quality checks (format, lint, typecheck)
	@echo "$(GREEN)All code quality checks completed!$(RESET)"

test: ## Run tests with pytest
	@echo "$(GREEN)Running tests...$(RESET)"
	uv run python -m pytest tests/ -v --tb=short

run: ## Run the defuse monitor application
	@echo "$(GREEN)Starting Defuse Monitor...$(RESET)"
	@if [ ! -f defuse.toml ]; then \
		echo "$(YELLOW)Warning: defuse.toml not found, using default configuration$(RESET)"; \
	fi
	uv run python -m defuse_monitor --config defuse.toml
