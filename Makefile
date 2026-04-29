.PHONY: install test test-cov lint check clean run help

install:
	pip install -e ".[dev]"

test:
	pytest

test-cov:
	pytest --cov=flashback --cov-report=term-missing

lint:
	flake8 flashback/ tests/

check: lint test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

# Uso: make run BIN=data/binarios/test
run:
	python flashback.py $(BIN) -o $(BIN).c --verbose

help:
	@echo "Comandos disponibles:"
	@echo "  make install          Instalar dependencias"
	@echo "  make test             Ejecutar tests"
	@echo "  make test-cov         Tests con cobertura"
	@echo "  make lint             Linting con flake8"
	@echo "  make check            lint + tests (antes de commit)"
	@echo "  make clean            Limpiar artefactos"
	@echo "  make run BIN=<ruta>   Ejecutar pipeline sobre un binario"
