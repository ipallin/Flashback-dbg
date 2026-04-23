.PHONY: install test lint check clean help

# Instalar dependencias de desarrollo
install:
	pip install -e ".[dev]"

# Ejecutar todos los tests
test:
	pytest

# Ejecutar tests con cobertura
test-cov:
	pytest --cov=src --cov-report=term-missing

# Linting
lint:
	flake8 src/ tests/

# Lint + tests (usar antes de cada commit)
check: lint test

# Limpiar artefactos
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

# Ejecutar el pipeline completo sobre un binario
# Uso: make run BIN=binarios_prueba/hello
run:
	python -m src.cli.main all $(BIN)

help:
	@echo "Comandos disponibles:"
	@echo "  make install     Instalar dependencias"
	@echo "  make test        Ejecutar tests"
	@echo "  make test-cov    Tests con cobertura"
	@echo "  make lint        Linting con flake8"
	@echo "  make check       lint + test (antes de commit)"
	@echo "  make clean       Limpiar artefactos"
	@echo "  make run BIN=X   Ejecutar pipeline sobre un binario"
