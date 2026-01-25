.PHONY: test coverage clean lint format install-dev

# Install development dependencies
install-dev:
	pip install pytest pytest-cov ruff bandit mypy

# Run linter
lint:
	ruff check src/ tools/ test/

# Format code
format:
	ruff format src/ tools/ test/

# Check formatting without modifying
format-check:
	ruff format --check src/ tools/ test/

# Run tests with pytest
test:
	PYTHONPATH=src pytest test/ -v

# Run tests with coverage
coverage:
	PYTHONPATH=src pytest test/ -v --cov=src --cov-report=term-missing --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

# Security scan
security:
	bandit -r src/ -ll -ii

# Type check
typecheck:
	mypy src/ --ignore-missing-imports

# Run all checks (what CI does)
ci: lint format-check test

# Clean build artifacts
clean:
	rm -rf .coverage htmlcov .pytest_cache .mypy_cache .ruff_cache coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
