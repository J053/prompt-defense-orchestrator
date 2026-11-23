"""
Pruebas de Verificación y Rigor de la Fase B, C & D: HeadlessBrowserDriver con DAST en DVWA y OWASP Juice Shop.
"""
import os
import pytest
from src.sandbox.browser_driver import (
    HeadlessBrowserDriver,
    DetectedForm,
    ProbeResult,
    SQL_ERROR_SIGNATURES
)


def test_browser_driver_extract_dvwa_forms():
    """Verifica que el driver extraiga con precisión el formulario de login de DVWA."""
    driver = HeadlessBrowserDriver()
    forms = driver.extract_forms("http://127.0.0.1:8080/login.php")

    assert len(forms) >= 1
    login_form = forms[0]
    assert login_form.method == "POST"
    field_names = [f.name for f in login_form.fields]
    assert "username" in field_names
    assert "password" in field_names


def test_browser_driver_send_probe_and_screenshot(tmp_path):
    """Verifica que el envío de una sonda diagnóstica genere un resultado y captura PNG."""
    evidence_dir = str(tmp_path / "evidence")
    driver = HeadlessBrowserDriver(evidence_dir=evidence_dir)

    result = driver.send_input_probe(
        url="http://127.0.0.1:8080/login.php",
        target_selector="input[name='username']",
        probe_value="probe_admin'",
        submit_selector="input[type='submit']"
    )

    assert isinstance(result, ProbeResult)
    assert result.tested_selector == "input[name='username']"
    assert result.probe_payload == "probe_admin'"

    # Verificar que se generó la captura de pantalla física
    assert result.evidence_screenshot is not None
    assert os.path.exists(result.evidence_screenshot)
    assert result.evidence_screenshot.endswith(".png")


def test_sql_error_signatures_library():
    """Verifica que la base de firmas cubra los principales motores de bases de datos."""
    assert any("mysql" in sig for sig in SQL_ERROR_SIGNATURES)
    assert any("postgres" in sig or "pg_" in sig for sig in SQL_ERROR_SIGNATURES)
    assert any("sqlite" in sig for sig in SQL_ERROR_SIGNATURES)
    assert any("ora-" in sig for sig in SQL_ERROR_SIGNATURES)


def test_browser_driver_auto_login_and_sqli_detection(tmp_path):
    """Verifica la detección activa de SQL Injection en DVWA autenticado."""
    evidence_dir = str(tmp_path / "evidence")
    driver = HeadlessBrowserDriver(evidence_dir=evidence_dir)

    # 1. Iniciar sesión automática
    cookies = driver.auto_login_dvwa("http://127.0.0.1:8080")
    assert "PHPSESSID" in cookies
    assert cookies.get("security") == "low"

    # 2. Extraer formularios de la página vulnerable
    forms = driver.extract_forms("http://127.0.0.1:8080/vulnerabilities/sqli/", cookies=cookies)
    assert len(forms) >= 1
    sqli_form = forms[0]
    field_names = [f.name for f in sqli_form.fields]
    assert "id" in field_names

    # 3. Enviar sonda diagnóstica y validar detección de error SQL
    probe_res = driver.send_input_probe(
        url="http://127.0.0.1:8080/vulnerabilities/sqli/",
        target_selector="input[name='id']",
        probe_value="'",
        submit_selector="input[name='Submit']",
        cookies=cookies
    )

    assert probe_res.sql_error_detected is True
    assert probe_res.detected_signature is not None
    assert "mariadb" in probe_res.detected_signature or "sql syntax" in probe_res.detected_signature
    assert probe_res.evidence_screenshot is not None
    assert os.path.exists(probe_res.evidence_screenshot)


def test_browser_driver_juice_shop_spa_forms():
    """Fase D: Verifica que el driver extraiga formularios reactivos en la SPA de Juice Shop."""
    driver = HeadlessBrowserDriver()
    forms = driver.extract_forms("http://127.0.0.1:3000/#/login")

    assert len(forms) >= 1
    login_form = forms[0]
    selectors = [f.selector for f in login_form.fields]
    assert "#email" in selectors or any("email" in s.lower() for s in selectors)
    assert "#password" in selectors or any("password" in s.lower() for s in selectors)


def test_browser_driver_juice_shop_probing_and_evidence(tmp_path):
    """Fase D: Verifica el sondeo interactivo y generación de evidencias en Juice Shop SPA."""
    evidence_dir = str(tmp_path / "evidence")
    driver = HeadlessBrowserDriver(evidence_dir=evidence_dir)

    result = driver.send_input_probe(
        url="http://127.0.0.1:3000/#/login",
        target_selector="#email",
        probe_value="test_auditor@probe.com'",
        submit_selector="#loginButton"
    )

    assert isinstance(result, ProbeResult)
    assert result.tested_selector == "#email"
    assert result.evidence_screenshot is not None
    assert os.path.exists(result.evidence_screenshot)
