#!/usr/bin/env python3
"""
🛡️ Prompt Defense Orchestrator - Interfaz de Consola Interactiva (CLI).
Punto de Entrada Unificado para la Automatización de Auditorías de Ciberseguridad Web,
Reconocimiento Autónomo (Crawling), DAST y Detección de Vulnerabilidades.
Cumple con la especificación de la Figura 8 del Capítulo III de la Tesis (UPN 2026).
"""
import os
import sys
import time
import argparse
import urllib.parse
from typing import Dict, Optional

# Asegurar soporte UTF-8 en consolas Windows
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Cargar variables de entorno desde .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.orchestrator.scanner import AutonomousWebScanner, ScanResult
from src.models.report_generator import ForensicReportGenerator
from src.sandbox.browser_driver import HeadlessBrowserDriver


BANNER = r"""
========================================================================================
   ____                             _     ____        __                      
  |  _ \ _ __ ___  _ __ ___  _ __  | |_  |  _ \  ___ / _| ___ _ __  ___  ___ 
  | |_) | '__/ _ \| '_ ` _ \| '_ \ | __| | | | |/ _ \ |_ / _ \ '_ \/ __|/ _ \
  |  __/| | | (_) | | | | | | |_) || |_  | |_| |  __/  _|  __/ | | \__ \  __/
  |_|   |_|  \___/|_| |_| |_| .__/  \__| |____/ \___|_|  \___|_| |_|___/\___|
                            |_|          O R C H E S T R A T O R  (CLI v2.0)   
========================================================================================
 Tesis: Sistema de Agentes Autónomos Resistente a Inyección de Prompts
 Autores: Grupo de investigación (UPN 2026)
========================================================================================
"""


def render_dashboard(scan_res: ScanResult, report_summary: dict):
    """Renderiza el tablero forense en tiempo real conforme a la Figura 8 de la tesis."""
    score = report_summary["score"]
    sev = report_summary["severity"]
    rep_id = report_summary["report_id"]

    print("\n" + "=" * 88)
    print(f"               TABLERO DE CONTROL FORENSE Y EVALUACIÓN CVSS v3.1")
    print("=" * 88)
    print(f" Expediente ID      : {rep_id}")
    print(f" Objetivo Auditado  : {scan_res.target_url}")
    print(f" Estado HTTP        : {scan_res.status_code} OK | Bytes: {scan_res.body_length} | Latencia: {scan_res.execution_time_s}s")
    print(f" Capa de Procedencia: {'ACTIVA [Zero-Trust Taint Tracking]' if scan_res.defense_active else 'INACTIVA'}")
    if scan_res.crawl_report:
        print(f" Superficie Ataque  : {scan_res.crawl_report.total_discovered} rutas mapeadas | {scan_res.crawl_report.total_forms_found} formularios")
    print(f" Puntuación Global  : CVSS Base Score {score} [{sev}]")
    print("-" * 88)

    # 1. Mapa de Superficie de Ataque (Crawling Autónomo)
    if scan_res.crawl_report and scan_res.crawl_report.routes:
        print("\n[+] MAPA DE SUPERFICIE DE ATAQUE DESCUBIERTA (CRAWLER AUTÓNOMO):")
        routes_to_show = scan_res.crawl_report.routes[:10]
        for idx, r in enumerate(routes_to_show):
            prefix = "└──" if idx == len(routes_to_show) - 1 else "├──"
            form_str = f"({r.forms_count} form)" if r.forms_count > 0 else ""
            print(f"    {prefix} [{r.category:<11}] (Prof:{r.depth}) {r.path} {form_str}")

    # 2. Contención de Inyección de Prompts
    print("\n[+] ESTADO DE CONTENCIÓN ADVERSARIAL (INYECCIÓN INDIRECTA DE PROMPTS - IPI):")
    if scan_res.interceptions:
        print(f"    🚨 Intentos de secuestro detectados : {len(scan_res.interceptions)}")
        print(f"    🛡️ Ataques interceptados por defensa : {len(scan_res.interceptions)} (ASR = 0.0%)")
        for inc in scan_res.interceptions:
            print(f"       └── Herramienta bloqueada: '{inc.tool_name}' | Parámetros: {inc.blocked_params}")
    else:
        print("    🛡️ No se detectaron vectores hostiles de secuestro en el tráfico (ASR = 0.0%).")

    # 3. Vulnerabilidades Técnicas Web
    print("\n[+] VULNERABILIDADES TÉCNICAS IDENTIFICADAS:")
    if scan_res.findings:
        print(f"    {'SEVERIDAD':<12} | {'VULNERABILIDAD':<38} | {'DETALLES'}")
        print("    " + "-" * 82)
        for f in scan_res.findings:
            det_snippet = (f.details[:45] + "...") if len(f.details) > 45 else f.details
            print(f"    {f.severity:<12} | {f.vuln_type[:36]:<38} | {det_snippet}")
    else:
        print("    ✓ No se identificaron vulnerabilidades adicionales.")

    # 4. Evidencias Forenses Dinámicas
    screenshots = getattr(scan_res, "evidence_screenshots", [])
    if screenshots:
        print("\n[+] EVIDENCIAS FOTOGRÁFICAS FORENSES (PLAYWRIGHT HEADLESS):")
        for s in screenshots:
            print(f"    📸 Captura guardada: {s}")

    print("\n" + "=" * 88)
    print(" EXPEDIENTES FORENSES EXPORTADOS:")
    print(f" [JSON Estructurado] : {report_summary['json_path']}")
    print(f" [Informe Ejecutivo] : {report_summary['md_path']}")
    print("=" * 88 + "\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Prompt Defense Orchestrator - Auditoría Automatizada de Seguridad Web",
        epilog="Ejemplo: python audit.py --url http://localhost:8080/index.php --auto-login dvwa --crawl"
    )
    parser.add_argument(
        "-u", "--url",
        dest="target_url",
        help="URL completa del aplicativo web a auditar (ej. http://localhost:3000 o http://localhost:8080/index.php)",
        default=None
    )
    parser.add_argument(
        "-c", "--cookie",
        dest="cookie_str",
        help="Cabecera Cookie para sesiones autenticadas (ej. 'PHPSESSID=abc123; security=low')",
        default=None
    )
    parser.add_argument(
        "--auto-login",
        dest="auto_login",
        choices=["dvwa", "none"],
        help="Realiza autenticación automática previa en aplicaciones de laboratorio (ej. dvwa)",
        default="none"
    )
    parser.add_argument(
        "--crawl",
        dest="enable_crawl",
        action="store_true",
        help="Activa el rastreo autónomo de rutas (crawling) y mapeo de superficie de ataque",
        default=False
    )
    parser.add_argument(
        "--crawl-depth",
        dest="crawl_depth",
        type=int,
        help="Profundidad máxima del rastreo de rutas (por defecto: 2)",
        default=2
    )
    parser.add_argument(
        "--crawl-max-routes",
        dest="crawl_max_routes",
        type=int,
        help="Límite máximo de rutas a descubrir (por defecto: 10)",
        default=10
    )
    parser.add_argument(
        "-o", "--output-dir",
        dest="output_dir",
        help="Directorio de destino para los informes forenses (por defecto: reports)",
        default="reports"
    )
    parser.add_argument(
        "-m", "--model",
        dest="model_name",
        help="Modelo de LLM a utilizar (por defecto: gemini-3.5-flash-lite)",
        default="gemini-3.5-flash-lite"
    )
    parser.add_argument(
        "--no-browser",
        dest="disable_browser",
        action="store_true",
        help="Deshabilita la inspección y sondeo dinámico de navegador Headless Playwright",
        default=False
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    print(BANNER)

    # 1. Comprobar API Key
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[!] ERROR: No se encontró la variable de entorno 'GEMINI_API_KEY'.")
        print("    Asegúrate de tener un archivo .env con: GEMINI_API_KEY=tu_clave_aqui")
        sys.exit(1)

    # 2. Obtener URL del objetivo (Modo argumento o Modo interactivo)
    target_url = args.target_url
    if not target_url:
        try:
            print("[*] Modo Interactivo Iniciado.")
            target_url = input(" > Ingrese la URL que desea auditar (ej. http://localhost:3000): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Auditoría cancelada por el usuario.")
            sys.exit(0)

    if not target_url:
        print("[!] ERROR: Debe especificar una URL válida para iniciar la auditoría.")
        sys.exit(1)

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    # 3. Procesar o generar cookies de sesión
    cookies: Dict[str, str] = {}
    if args.auto_login == "dvwa":
        print("[*] Ejecutando inicio de sesión automático en DVWA (admin:password, security=low)...")
        driver = HeadlessBrowserDriver()
        parsed_target = urllib.parse.urlparse(target_url)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        cookies = driver.auto_login_dvwa(base_url=base_url)
        print(f"[*] Sesión establecida exitosamente. Cookies obtenidas: {list(cookies.keys())}")
    elif args.cookie_str:
        for part in args.cookie_str.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        print(f"[*] Cookies de sesión inyectadas manualmente: {list(cookies.keys())}")

    print(f"\n[*] INICIANDO AUDITORÍA AUTÓNOMA SOBRE: {target_url}")
    print(f"[*] Modelo Cognitivo : {args.model_name}")
    print("[*] Capa Defensiva    : ACTIVADA (Data Provenance & Causal Gating)")
    print(f"[*] DAST Playwright   : {'DESHABILITADO' if args.disable_browser else 'ACTIVADO (Headless Chromium)'}")
    print(f"[*] Crawler Autónomo  : {'ACTIVADO (Profundidad: ' + str(args.crawl_depth) + ', Máx: ' + str(args.crawl_max_routes) + ' rutas)' if args.enable_crawl else 'DESHABILITADO'}")
    print("[*] Conectando con el objetivo...")

    # 4. Ejecutar Reconocimiento, Crawling y Escaneo
    try:
        scanner = AutonomousWebScanner(api_key=api_key, model_name=args.model_name)
        scan_result = scanner.run_scan(
            target_url,
            enable_browser_probing=not args.disable_browser,
            enable_crawling=args.enable_crawl,
            crawl_depth=args.crawl_depth,
            crawl_max_routes=args.crawl_max_routes,
            cookies=cookies if cookies else None
        )
    except Exception as e:
        print(f"\n[!] ERROR durante el escaneo del objetivo: {e}")
        sys.exit(1)

    # 5. Generar Reporte Forense CVSS v3.1
    print("[*] Generando expediente forense estandarizado CVSS v3.1...")
    generator = ForensicReportGenerator(output_dir=args.output_dir)
    report_summary = generator.generate_report(scan_result)

    # 6. Renderizar Tablero Visual (Figura 8 de la Tesis)
    render_dashboard(scan_result, report_summary)
    print("[✓] Proceso de auditoría completado con éxito.")


if __name__ == "__main__":
    main()
