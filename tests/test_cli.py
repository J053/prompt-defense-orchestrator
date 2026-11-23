"""
Pruebas de Verificación y Rigor de la Fase 3: audit.py (CLI Unificado).
"""
import subprocess
import sys
import os
import pytest


def test_cli_help_flag():
    """Verifica que audit.py responda adecuadamente al flag --help."""
    result = subprocess.run(
        [sys.executable, "audit.py", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    assert result.returncode == 0
    assert "Prompt Defense Orchestrator" in result.stdout
    assert "--url" in result.stdout


def test_cli_empty_url_handling():
    """Verifica que audit.py maneje adecuadamente la entrada vacía sin crashear."""
    result = subprocess.run(
        [sys.executable, "audit.py"],
        input="",
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    assert result.returncode in (0, 1)
    assert "Tesis:" in result.stdout or "ORCHESTRATOR" in result.stdout.replace(" ", "")
