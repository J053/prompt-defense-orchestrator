"""
Pruebas de Verificación y Rigor de la Fase 2: ForensicReportGenerator.
"""
import os
import json
import pytest
from src.orchestrator.scanner import ScanResult, VulnerabilityFinding, SecurityInterceptionEvent
from src.models.report_generator import ForensicReportGenerator


def test_report_generator_cvss_calculation():
    """Verifica que el cálculo CVSS v3.1 asigne severidad alta ante intentos de secuestro."""
    generator = ForensicReportGenerator(output_dir="reports")

    # Caso con intercepción de seguridad
    result_with_attack = ScanResult(
        target_url="http://localhost:3000",
        status_code=200,
        headers_analyzed={},
        body_length=500,
        execution_time_s=1.2,
        findings=[VulnerabilityFinding("http://localhost:3000", "XSS", "LOW", "detalles")],
        interceptions=[SecurityInterceptionEvent("send_http_post", {"url": "http://evil.com"}, "ParamPolicy blocked")]
    )

    cvss_attack = generator.calculate_overall_cvss(result_with_attack)
    assert cvss_attack["score"] == 8.8
    assert cvss_attack["severity"] == "HIGH"
    assert "Indirect Prompt Injection" in cvss_attack["category"]


def test_report_generator_export_files(tmp_path):
    """Verifica la generación física de los archivos JSON y Markdown en disco."""
    reports_dir = str(tmp_path / "reports")
    generator = ForensicReportGenerator(output_dir=reports_dir)

    sample_result = ScanResult(
        target_url="http://localhost:8080/login.php",
        status_code=200,
        headers_analyzed={"Server": "Apache"},
        body_length=1200,
        execution_time_s=2.5,
        findings=[
            VulnerabilityFinding("http://localhost:8080/login.php", "SQL Injection", "HIGH", "Login vulnerable")
        ],
        interceptions=[]
    )

    summary = generator.generate_report(sample_result)

    assert os.path.exists(summary["json_path"])
    assert os.path.exists(summary["md_path"])
    assert summary["score"] == 8.5
    assert summary["severity"] == "HIGH"

    # Verificar que el JSON es válido y contiene los campos forenses
    with open(summary["json_path"], "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["metadata"]["target_application"] == "http://localhost:8080/login.php"
        assert data["metadata"]["cvss_base_score"] == 8.5
        assert len(data["findings"]) == 1

    # Verificar que el Markdown contiene el encabezado y detalles
    with open(summary["md_path"], "r", encoding="utf-8") as f:
        md_text = f.read()
        assert "Expediente Forense de Ciberseguridad" in md_text
        assert "SQL Injection" in md_text
