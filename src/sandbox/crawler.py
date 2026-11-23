"""
Motor de Descubrimiento de Rutas y Mapeo de Superficie de Ataque (Web Crawler).
Componente de la Fase E1 del Orquestador Unificado (audit.py).

Funcionalidades:
1. Rastreo web controlado dentro del alcance estricto (Same-Origin Scope).
2. Detección de enlaces en aplicaciones tradicionales (SSR) y SPAs (Hash Routing / Angular / React).
3. Lista de exclusión contra trampas de sesión (logout/signout) y acciones destructivas.
4. Categorización heurística del propósito funcional de cada endpoint.
5. Deduplicación y normalización de URLs para evitar bucles infinitos.
"""
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page


# Patrones de exclusión para evitar destrucción de sesiones o reseteo destructivo
EXCLUSION_PATTERNS = [
    r"logout",
    r"signout",
    r"cerrar[-_]sesion",
    r"logoff",
    r"exit",
    r"setup\.php",   # Evitar reseteo de base de datos en DVWA
    r"reset_db",
    r"drop",
    r"delete",
    r"\.pdf$",
    r"\.zip$",
    r"\.png$",
    r"\.jpg$",
    r"\.jpeg$",
    r"\.gif$",
    r"\.svg$",
    r"\.css$",
    r"\.woff2?$"
]


@dataclass
class DiscoveredRoute:
    """Representa una ruta o endpoint descubierto durante el crawling."""
    url: str
    path: str
    category: str
    forms_count: int = 0
    depth: int = 0
    title: str = ""
    discovered_via: str = "seed"


@dataclass
class CrawlReport:
    """Reporte consolidado del proceso de rastreo y mapeo de superficie."""
    seed_url: str
    routes: List[DiscoveredRoute] = field(default_factory=list)
    total_discovered: int = 0
    total_forms_found: int = 0
    execution_time_s: float = 0.0


class WebCrawlerEngine:
    """Motor de crawling autónomo enfocado en reconocimiento y mapeo de superficie de ataque."""

    def __init__(
        self,
        max_depth: int = 2,
        max_routes: int = 15,
        timeout_ms: int = 6000
    ):
        self.max_depth = max_depth
        self.max_routes = max_routes
        self.timeout_ms = timeout_ms

    def _is_excluded(self, url: str) -> bool:
        """Determina si una URL coincide con la lista negra de exclusión."""
        url_lower = url.lower()
        for pattern in EXCLUSION_PATTERNS:
            if re.search(pattern, url_lower):
                return True
        return False

    def _is_same_origin(self, base_url: str, candidate_url: str) -> bool:
        """Verifica que la URL pertenezca exactamente al mismo origen (scheme, host, port)."""
        base_parsed = urllib.parse.urlparse(base_url)
        cand_parsed = urllib.parse.urlparse(candidate_url)

        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
        cand_origin = f"{cand_parsed.scheme}://{cand_parsed.netloc}"

        return base_origin == cand_origin

    def _normalize_url(self, base_url: str, raw_link: str) -> Optional[str]:
        """Normaliza una URL relativa o absoluta y elimina anclas superfluas salvo en SPAs."""
        if not raw_link or raw_link.startswith(("javascript:", "mailto:", "tel:", "#")):
            # Si es solo '#' no es una ruta SPA
            if raw_link.startswith("#/") or raw_link.startswith("#!"):
                # Es una ruta SPA relativa a la URL base
                parsed_base = urllib.parse.urlparse(base_url)
                origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                return f"{origin}/{raw_link}"
            return None

        # Resolver URL relativa contra la base
        full_url = urllib.parse.urljoin(base_url, raw_link)
        parsed = urllib.parse.urlparse(full_url)

        # En aplicaciones no-SPA, eliminar fragmentos '#'
        fragment = parsed.fragment
        is_spa_route = fragment.startswith("/") or fragment.startswith("!/")

        clean_fragment = fragment if is_spa_route else ""
        normalized = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            clean_fragment
        ))

        return normalized.rstrip("#")

    def _categorize_endpoint(self, path: str, title: str) -> str:
        """Asigna una categoría heurística de ciberseguridad a la ruta descubierta."""
        p_lower = path.lower()
        t_lower = title.lower()
        combined = f"{p_lower} {t_lower}"

        if any(w in combined for w in ("login", "signin", "auth", "session", "acceso")):
            return "AUTH"
        if any(w in combined for w in ("sqli", "sql_injection", "sql")):
            return "VULN_SQLI"
        if any(w in combined for w in ("xss", "cross_site_scripting")):
            return "VULN_XSS"
        if any(w in combined for w in ("csrf", "cross_site_request")):
            return "VULN_CSRF"
        if any(w in combined for w in ("upload", "subida", "archivo")):
            return "FILE_UPLOAD"
        if any(w in combined for w in ("exec", "command", "ping", "cmd")):
            return "COMMAND_EXEC"
        if any(w in combined for w in ("admin", "dashboard", "panel", "manage", "gestión")):
            return "ADMIN"
        if any(w in combined for w in ("security", "config", "ajustes", "preferencias")):
            return "CONFIG"
        if any(w in combined for w in ("search", "buscar", "product", "item", "cart", "basket", "shop")):
            return "DATA_INPUT"
        if any(w in combined for w in ("api/", "rest/", "graphql", "/v1/", "/v2/")):
            return "API"
        if any(w in combined for w in ("instruction", "help", "ayuda", "about", "info", "doc")):
            return "INFO"

        return "GENERAL"

    def crawl(
        self,
        seed_url: str,
        cookies: Optional[Dict[str, str]] = None
    ) -> CrawlReport:
        """
        Ejecuta el rastreo autónomo en anchura (BFS) descubriendo rutas,
        formularios e infiriendo el perfil funcional de cada endpoint.
        """
        start_time = time.time()
        parsed_seed = urllib.parse.urlparse(seed_url)
        origin = f"{parsed_seed.scheme}://{parsed_seed.netloc}"

        visited_urls: Set[str] = set()
        discovered_routes: List[DiscoveredRoute] = []
        total_forms = 0

        # Cola de exploración: (url_a_visitar, profundidad, origen_de_enlace)
        queue: List[tuple] = [(seed_url, 0, "seed")]

        with sync_playwright() as p:
            browser: Browser = p.chromium.launch(headless=True)
            context: BrowserContext = browser.new_context()

            # Configurar cookies de sesión si están provistas
            if cookies:
                domain = parsed_seed.hostname or "127.0.0.1"
                cookie_items = [
                    {"name": k, "value": str(v), "domain": domain, "path": "/"}
                    for k, v in cookies.items()
                ]
                context.add_cookies(cookie_items)

            page: Page = context.new_page()

            try:
                while queue and len(discovered_routes) < self.max_routes:
                    current_url, depth, source = queue.pop(0)

                    # Normalización para deduplicación
                    clean_url = current_url.split("?")[0] if "PHPSESSID" in current_url else current_url
                    if clean_url in visited_urls:
                        continue

                    visited_urls.add(clean_url)

                    # Navegar al endpoint
                    try:
                        page.goto(current_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                        time.sleep(0.6)  # Tiempo para renderizado de SPA y ejecución JS
                    except Exception:
                        continue

                    page_title = page.title() or ""
                    parsed_curr = urllib.parse.urlparse(current_url)
                    path_fragment = parsed_curr.path + (f"#{parsed_curr.fragment}" if parsed_curr.fragment else "")

                    # Contar formularios e inputs en el DOM
                    form_count = page.locator("form").count()
                    if form_count == 0:
                        # Revisar inputs interactivos en SPAs
                        loose_inputs = page.locator("input:not([type='hidden']):not([type='submit'])").count()
                        if loose_inputs > 0:
                            form_count = 1

                    total_forms += form_count
                    category = self._categorize_endpoint(path_fragment, page_title)

                    route_obj = DiscoveredRoute(
                        url=current_url,
                        path=path_fragment or "/",
                        category=category,
                        forms_count=form_count,
                        depth=depth,
                        title=page_title,
                        discovered_via=source
                    )
                    discovered_routes.append(route_obj)

                    # Si aún estamos dentro del límite de profundidad, descubrir nuevos enlaces
                    if depth < self.max_depth and len(discovered_routes) < self.max_routes:
                        # 1. Enlaces <a>
                        raw_links = page.evaluate("""
                            () => {
                                const links = [];
                                document.querySelectorAll('a[href]').forEach(a => links.push(a.getAttribute('href')));
                                document.querySelectorAll('form[action]').forEach(f => links.push(f.getAttribute('action')));
                                return links;
                            }
                        """)

                        for raw_link in raw_links:
                            normalized = self._normalize_url(current_url, raw_link)
                            if not normalized:
                                continue

                            # Comprobar políticas de seguridad de rastreo
                            if not self._is_same_origin(origin, normalized):
                                continue

                            if self._is_excluded(normalized):
                                continue

                            clean_candidate = normalized.split("?")[0] if "PHPSESSID" in normalized else normalized
                            if clean_candidate not in visited_urls and not any(q[0] == normalized for q in queue):
                                queue.append((normalized, depth + 1, current_url))

            finally:
                browser.close()

        total_time = round(time.time() - start_time, 3)

        return CrawlReport(
            seed_url=seed_url,
            routes=discovered_routes,
            total_discovered=len(discovered_routes),
            total_forms_found=total_forms,
            execution_time_s=total_time
        )
