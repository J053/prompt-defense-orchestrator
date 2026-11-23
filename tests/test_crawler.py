"""
Pruebas de Verificación y Rigor de la Fase E1: WebCrawlerEngine (Mapeo de Superficie y Crawling).
"""
import pytest
from src.sandbox.crawler import WebCrawlerEngine, DiscoveredRoute, CrawlReport
from src.sandbox.browser_driver import HeadlessBrowserDriver


def test_crawler_exclusion_policy():
    """Verifica que la lista negra excluya trampas de logout y acciones destructivas."""
    crawler = WebCrawlerEngine()
    
    # Deben ser excluidas
    assert crawler._is_excluded("http://127.0.0.1:8080/logout.php") is True
    assert crawler._is_excluded("http://127.0.0.1:8080/signout") is True
    assert crawler._is_excluded("http://127.0.0.1:8080/setup.php") is True
    assert crawler._is_excluded("http://127.0.0.1:8080/assets/logo.png") is True
    
    # Deben ser permitidas
    assert crawler._is_excluded("http://127.0.0.1:8080/vulnerabilities/sqli/") is False
    assert crawler._is_excluded("http://127.0.0.1:8080/vulnerabilities/xss_r/") is False
    assert crawler._is_excluded("http://127.0.0.1:3000/#/search") is False
    assert crawler._is_excluded("http://127.0.0.1:3000/#/login") is False


def test_crawler_same_origin():
    """Verifica que el motor rechace dominios externos fuera del alcance."""
    crawler = WebCrawlerEngine()
    base = "http://127.0.0.1:8080/index.php"

    assert crawler._is_same_origin(base, "http://127.0.0.1:8080/vulnerabilities/sqli/") is True
    assert crawler._is_same_origin(base, "http://127.0.0.1:3000/api") is False
    assert crawler._is_same_origin(base, "https://github.com/digininja/DVWA") is False
    assert crawler._is_same_origin(base, "https://google.com") is False


def test_crawler_categorization():
    """Verifica que las heurísticas asignen categorías de ciberseguridad correctas."""
    crawler = WebCrawlerEngine()

    assert crawler._categorize_endpoint("/login.php", "Login") == "AUTH"
    assert crawler._categorize_endpoint("/vulnerabilities/sqli/", "SQL Injection") == "VULN_SQLI"
    assert crawler._categorize_endpoint("/vulnerabilities/xss_r/", "Reflected XSS") == "VULN_XSS"
    assert crawler._categorize_endpoint("/vulnerabilities/csrf/", "CSRF") == "VULN_CSRF"
    assert crawler._categorize_endpoint("/vulnerabilities/upload/", "Upload") == "FILE_UPLOAD"
    assert crawler._categorize_endpoint("/vulnerabilities/exec/", "Command Injection") == "COMMAND_EXEC"
    assert crawler._categorize_endpoint("/instructions.php", "Help") == "INFO"
    assert crawler._categorize_endpoint("/security.php", "Security Level") == "CONFIG"


def test_crawler_live_dvwa_crawling():
    """Verifica el rastreo real en DVWA descubriendo módulos vulnerables sin caer en logout."""
    driver = HeadlessBrowserDriver()
    cookies = driver.auto_login_dvwa("http://127.0.0.1:8080")

    crawler = WebCrawlerEngine(max_depth=2, max_routes=8)
    report = crawler.crawl(seed_url="http://127.0.0.1:8080/index.php", cookies=cookies)

    assert isinstance(report, CrawlReport)
    assert report.total_discovered >= 3
    
    paths = [r.path for r in report.routes]
    
    # Debe haber descubierto módulos vulnerables
    assert any("vulnerabilities" in p for p in paths)
    
    # NUNCA debe haber visitado logout ni setup.php
    assert not any("logout" in p.lower() for p in paths)
    assert not any("setup.php" in p.lower() for p in paths)


def test_crawler_live_juice_shop_spa():
    """Verifica el rastreo en la SPA de Juice Shop respetando rutas dinámicas."""
    crawler = WebCrawlerEngine(max_depth=1, max_routes=5)
    report = crawler.crawl(seed_url="http://127.0.0.1:3000/")

    assert isinstance(report, CrawlReport)
    assert report.total_discovered >= 1
    assert report.execution_time_s > 0
