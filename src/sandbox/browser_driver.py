"""
Driver de Navegador Headless con Playwright para Auditoría Web Activa.
Fase B, C & D: Extracción de elementos interactivos, sondeo diagnóstico de formularios,
gestión de sesiones autenticadas y capturas forenses (SSR y SPAs modernas).
"""
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page


# Firmas de error de bases de datos para detección activa de SQL Injection
SQL_ERROR_SIGNATURES = [
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql_",
    "mysql_fetch_array()",
    "valid mysql result",
    "check the manual that corresponds to your mariadb server version",
    "check the manual that corresponds to your mysql server version",
    # PostgreSQL
    "pg_query(): query failed",
    "syntax error at or near",
    "postgresql query failed",
    # SQLite
    "sqlite3::sqlexception",
    "sqlite_error",
    "unrecognized token",
    "near \": syntax error",
    # Oracle / Microsoft SQL Server
    "ora-01756",
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "driver][sql server]"
]


@dataclass
class FormField:
    """Representa un campo de formulario detectable e interactuable."""
    selector: str
    field_type: str
    name: str
    id_attr: str
    current_value: str
    is_interactive: bool = True


@dataclass
class DetectedForm:
    """Representa un formulario interactivo encontrado en el DOM."""
    form_id: str
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    submit_selector: Optional[str] = None


@dataclass
class ProbeResult:
    """Resultado del sondeo diagnóstico sobre un parámetro o campo web."""
    tested_selector: str
    probe_payload: str
    sql_error_detected: bool
    detected_signature: Optional[str] = None
    response_status: int = 200
    alert_dialog_text: Optional[str] = None
    evidence_screenshot: Optional[str] = None
    response_snippet: str = ""


class HeadlessBrowserDriver:
    """Controlador de navegador headless Chromium para auditorías dinámicas y DAST."""

    def __init__(self, evidence_dir: str = "reports/evidence"):
        self.evidence_dir = os.path.abspath(evidence_dir)
        os.makedirs(self.evidence_dir, exist_ok=True)

    def _setup_context(self, browser: Browser, url: str, cookies: Optional[Dict[str, str]] = None) -> BrowserContext:
        """Crea un contexto de navegador e inyecta cookies si están provistas."""
        context = browser.new_context()
        if cookies:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.hostname or "127.0.0.1"
            cookie_items = [{"name": k, "value": str(v), "domain": domain, "path": "/"} for k, v in cookies.items()]
            context.add_cookies(cookie_items)
        return context

    def auto_login_dvwa(self, base_url: str = "http://127.0.0.1:8080", username: str = "admin", password: str = "password") -> Dict[str, str]:
        """Inicia sesión automáticamente en DVWA y retorna las cookies de sesión con security=low."""
        cookies_dict: Dict[str, str] = {}
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            try:
                login_url = f"{base_url.rstrip('/')}/login.php"
                page.goto(login_url, wait_until="domcontentloaded", timeout=10000)
                page.fill("input[name='username']", username)
                page.fill("input[name='password']", password)
                page.click("input[name='Login']")
                page.wait_for_load_state("domcontentloaded", timeout=5000)

                # Fijar nivel de seguridad a low si es posible
                sec_url = f"{base_url.rstrip('/')}/security.php"
                page.goto(sec_url, wait_until="domcontentloaded", timeout=10000)
                if page.locator("select[name='security']").count() > 0:
                    page.select_option("select[name='security']", "low")
                    page.click("input[name='seclev_submit']")
                    page.wait_for_load_state("domcontentloaded", timeout=5000)

                for c in context.cookies():
                    cookies_dict[c["name"]] = c["value"]
                cookies_dict["security"] = "low"
            finally:
                browser.close()
        return cookies_dict

    def extract_forms(self, url: str, cookies: Optional[Dict[str, str]] = None) -> List[DetectedForm]:
        """Navega a la URL y extrae todos los formularios e inputs interactivos del DOM."""
        detected: List[DetectedForm] = []

        with sync_playwright() as p:
            browser: Browser = p.chromium.launch(headless=True)
            context = self._setup_context(browser, url, cookies)
            page: Page = context.new_page()
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=10000)
                time.sleep(1)  # Pausa breve para hidratación SPA/SSR

                form_elements = page.locator("form").all()
                if form_elements:
                    for idx, form in enumerate(form_elements):
                        action = form.get_attribute("action") or url
                        method = (form.get_attribute("method") or "GET").upper()
                        form_id = form.get_attribute("id") or f"form_{idx}"

                        fields: List[FormField] = []
                        inputs = form.locator("input, textarea, select").all()
                        submit_btn = None

                        for inp in inputs:
                            tag_name = inp.evaluate("el => el.tagName.toLowerCase()")
                            itype = (inp.get_attribute("type") or "text").lower()
                            name = inp.get_attribute("name") or ""
                            fid = inp.get_attribute("id") or ""
                            val = inp.input_value() if tag_name == "input" and itype not in ("submit", "button", "hidden") else ""

                            if fid:
                                selector = f"#{fid}"
                            elif name:
                                selector = f"{tag_name}[name='{name}']"
                            else:
                                selector = f"{tag_name}"

                            if itype in ("submit", "button") or tag_name == "button":
                                submit_btn = selector
                                continue

                            fields.append(FormField(
                                selector=selector,
                                field_type=itype,
                                name=name,
                                id_attr=fid,
                                current_value=val,
                                is_interactive=(itype != "hidden")
                            ))

                        if not submit_btn:
                            btn_loc = form.locator("button, input[type='submit']")
                            if btn_loc.count() > 0:
                                submit_btn = "button, input[type='submit']"

                        detected.append(DetectedForm(
                            form_id=form_id,
                            action=action,
                            method=method,
                            fields=fields,
                            submit_selector=submit_btn
                        ))
                else:
                    # En SPAs como Juice Shop, los inputs pueden encontrarse en componentes personalizados
                    loose_inputs = page.locator("input:not([type='hidden']):not([type='submit'])").all()
                    if loose_inputs:
                        fields = []
                        for inp in loose_inputs:
                            name = inp.get_attribute("name") or ""
                            fid = inp.get_attribute("id") or ""
                            itype = inp.get_attribute("type") or "text"
                            selector = f"#{fid}" if fid else (f"input[name='{name}']" if name else "input")
                            fields.append(FormField(
                                selector=selector,
                                field_type=itype,
                                name=name,
                                id_attr=fid,
                                current_value="",
                                is_interactive=True
                            ))
                        detected.append(DetectedForm(
                            form_id="loose_inputs_form",
                            action=url,
                            method="DYNAMIC_DOM",
                            fields=fields,
                            submit_selector="button[type='submit'], button"
                        ))

            finally:
                browser.close()

        return detected

    def send_input_probe(
        self,
        url: str,
        target_selector: str,
        probe_value: str = "' OR '1'='1",
        submit_selector: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> ProbeResult:
        """
        Envía una sonda diagnóstica a un input, somete el formulario y verifica
        si el servidor responde con firmas de error SQL o si activa alertas.
        Resiliente ante formularios reactivos de Angular/React con botones deshabilitados.
        """
        sql_error_found = False
        detected_sig = None
        alert_text = None
        status_code = 200
        response_text = ""
        screenshot_path = None

        with sync_playwright() as p:
            browser: Browser = p.chromium.launch(headless=True)
            context = self._setup_context(browser, url, cookies)
            page: Page = context.new_page()

            def handle_dialog(dialog):
                nonlocal alert_text
                alert_text = dialog.message
                dialog.dismiss()

            page.on("dialog", handle_dialog)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=10000)
                time.sleep(0.5)

                input_elem = page.locator(target_selector).first
                if input_elem.count() > 0:
                    input_elem.fill(probe_value)

                    # Intentar pulsar botón de envío de forma resiliente
                    if submit_selector and page.locator(submit_selector).count() > 0:
                        btn = page.locator(submit_selector).first
                        try:
                            # Timeout corto de 2.0s por si el botón está desactivado en la SPA
                            btn.click(timeout=2000)
                        except Exception:
                            # Fallback para formularios reactivos
                            try:
                                input_elem.press("Enter", timeout=2000)
                            except Exception:
                                pass
                    else:
                        try:
                            input_elem.press("Enter", timeout=2000)
                        except Exception:
                            pass

                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=3000)
                    except Exception:
                        pass
                    time.sleep(0.8)

                response_text = page.content()
                content_lower = response_text.lower()

                for sig in SQL_ERROR_SIGNATURES:
                    if sig in content_lower:
                        sql_error_found = True
                        detected_sig = sig
                        break

            except Exception as e:
                response_text = f"[ERROR_DURING_PROBE]: {str(e)}"
            finally:
                # Captura forense fotográfica garantizada
                try:
                    timestamp = int(time.time() * 1000)
                    sanitized_host = urllib.parse.urlparse(url).netloc.replace(":", "_")
                    filename = f"evidence_{sanitized_host}_{timestamp}.png"
                    screenshot_path = os.path.join(self.evidence_dir, filename)
                    page.screenshot(path=screenshot_path)
                except Exception:
                    pass
                browser.close()

        return ProbeResult(
            tested_selector=target_selector,
            probe_payload=probe_value,
            sql_error_detected=sql_error_found,
            detected_signature=detected_sig,
            response_status=status_code,
            alert_dialog_text=alert_text,
            evidence_screenshot=screenshot_path,
            response_snippet=response_text[:300]
        )
