"""
Pruebas de Verificación de Infraestructura de la Fase A: Playwright Chromium Headless.
"""
import pytest
from playwright.sync_api import sync_playwright


def test_playwright_chromium_launch():
    """Verifica que Chromium headless se ejecute y cierre adecuadamente."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        assert browser.is_connected()
        page = browser.new_page()
        page.set_content("<html><body><h1>Autonomous Auditor</h1></body></html>")
        h1_text = page.locator("h1").inner_text()
        assert h1_text == "Autonomous Auditor"
        browser.close()


def test_playwright_dvwa_rendering():
    """Verifica que Playwright cargue DVWA en el puerto 8080 y detecte los inputs."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://127.0.0.1:8080/login.php", timeout=5000)
        assert "DVWA" in page.title()
        assert page.locator("input[name='username']").count() == 1
        assert page.locator("input[name='password']").count() == 1
        browser.close()


def test_playwright_juice_shop_spa_rendering():
    """Verifica que Playwright renderice la SPA de Angular de Juice Shop en el puerto 3000."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://127.0.0.1:3000", wait_until="domcontentloaded", timeout=6000)
        assert "OWASP Juice Shop" in page.title()
        # En una SPA, al renderizar hay botones dinámicos
        assert page.locator("button").count() > 0
        browser.close()
