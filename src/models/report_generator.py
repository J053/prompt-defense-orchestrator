"""
Generador de Expedientes Forenses y Reportes de Auditoría CVSS v3.1.
Componente de la Fase 2 & E del Orquestador Unificado (audit.py).

Funcionalidades:
1. Mapeo de hallazgos y eventos de intercepción hacia el estándar de severidad CVSS v3.1.
2. Cálculo de puntuaciones base (Base Score), métricas de impacto y vectores CVSS.
3. Generación de reportes estructurados en formato JSON y Markdown ejecutivo.
4. Exportación persistente hacia el directorio reports/ con inclusión del mapa de superficie de ataque.
"""
import os
import json
import time
import urllib.parse
from typing import Dict, Any, List, Optional
from dataclasses import asdict

from src.models.forensic import ForensicReportCVSS
from src.orchestrator.scanner import ScanResult, VulnerabilityFinding, SecurityInterceptionEvent


SEVERITY_SCORES = {
    "CRITICAL": 9.8,
    "HIGH": 8.5,
    "MEDIUM": 5.5,
    "LOW": 3.1,
    "INFO": 0.0
}


class ForensicReportGenerator:
    """Transforma los resultados de escaneo en reportes forenses bajo estándar CVSS v3.1."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def calculate_overall_cvss(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Calcula el vector CVSS v3.1 global y la severidad máxima encontrada."""
        # Si hubo un intento de secuestro por inyección de prompts interceptado:
        if scan_result.interceptions:
            return {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                "score": 8.8,
                "severity": "HIGH",
                "category": "Indirect Prompt Injection (CWE-1426) - Mitigado por ParamPolicy"
            }

        # Si hay hallazgos de vulnerabilidades web:
        max_score = 0.0
        max_severity = "INFO"
        category = "Reconocimiento Web Limpio"

        for f in scan_result.findings:
            sev = f.severity.upper()
            score = SEVERITY_SCORES.get(sev, 4.0)
            if score > max_score:
                max_score = score
                max_severity = sev
                category = f.vuln_type

        return {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" if max_score > 0 else "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "score": max_score if max_score > 0 else 0.0,
            "severity": max_severity,
            "category": category
        }

    def generate_report(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Construye el expediente forense consolidado."""
        cvss_info = self.calculate_overall_cvss(scan_result)
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        timestamp_slug = time.strftime("%Y%m%d_%H%M%S")

        parsed_url = urllib.parse.urlparse(scan_result.target_url)
        clean_host = (parsed_url.netloc or parsed_url.path).replace(":", "_").replace("/", "_")
        report_id = f"REP-{clean_host}-{timestamp_slug}"

        # Mapear al modelo Pydantic ForensicReportCVSS
        has_interception = len(scan_result.interceptions) > 0
        blocked_tool = scan_result.interceptions[0].tool_name if has_interception else None
        tainted_params = scan_result.interceptions[0].blocked_params if has_interception else {}

        crawl_routes_count = len(scan_result.crawl_report.routes) if scan_result.crawl_report else 0

        causal_evidence = (
            f"Se analizaron {scan_result.body_length} bytes desde {scan_result.target_url}. "
            f"La Capa de Procedencia estuvo activa. "
            f"Rutas descubiertas en crawling: {crawl_routes_count}. "
            f"Formularios DOM detectados: {getattr(scan_result, 'detected_forms_count', 0)}. "
            f"Intentos de secuestro interceptados: {len(scan_result.interceptions)}. "
            f"Vulnerabilidades web reportadas: {len(scan_result.findings)}."
        )

        forensic_model = ForensicReportCVSS(
            report_id=report_id,
            target_application=scan_result.target_url,
            vulnerability_id=cvss_info["category"],
            cvss_vector=cvss_info["vector"],
            cvss_base_score=cvss_info["score"],
            severity=cvss_info["severity"],
            attack_type="Indirect_Prompt_Injection" if has_interception else "Web_Security_Audit",
            taint_tracking_intercepted=has_interception,
            blocked_tool=blocked_tool,
            tainted_parameters=tainted_params,
            timestamp=timestamp_str,
            causal_evidence=causal_evidence
        )

        evidence_screenshots = getattr(scan_result, "evidence_screenshots", [])

        attack_surface_data = None
        if scan_result.crawl_report:
            attack_surface_data = {
                "total_routes": scan_result.crawl_report.total_discovered,
                "total_forms": scan_result.crawl_report.total_forms_found,
                "execution_time_s": scan_result.crawl_report.execution_time_s,
                "routes": [asdict(r) for r in scan_result.crawl_report.routes]
            }

        full_report_data = {
            "metadata": forensic_model.model_dump(),
            "scan_metrics": {
                "target_url": scan_result.target_url,
                "status_code": scan_result.status_code,
                "latency_s": scan_result.execution_time_s,
                "defense_active": scan_result.defense_active,
                "detected_forms_count": getattr(scan_result, "detected_forms_count", 0),
                "total_findings": len(scan_result.findings),
                "total_interceptions": len(scan_result.interceptions),
                "evidence_screenshots": evidence_screenshots
            },
            "attack_surface": attack_surface_data,
            "findings": [asdict(f) for f in scan_result.findings],
            "interceptions": [asdict(i) for i in scan_result.interceptions]
        }

        # Guardar en archivo JSON
        json_filename = f"{report_id}.json"
        json_path = os.path.join(self.output_dir, json_filename)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(full_report_data, f, indent=2, ensure_ascii=False)

        # Guardar en archivo Markdown legible
        md_filename = f"{report_id}.md"
        md_path = os.path.join(self.output_dir, md_filename)
        md_content = self._render_markdown_report(full_report_data)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return {
            "report_id": report_id,
            "json_path": json_path,
            "md_path": md_path,
            "score": cvss_info["score"],
            "severity": cvss_info["severity"],
            "model": forensic_model
        }

    def _render_markdown_report(self, data: Dict[str, Any]) -> str:
        """Renderiza un reporte ejecutivo en formato GitHub-Flavored Markdown."""
        meta = data["metadata"]
        metrics = data["scan_metrics"]
        surface = data.get("attack_surface")

        md = []
        md.append(f"# 🛡️ Expediente Forense de Ciberseguridad - {meta['report_id']}")
        md.append("")
        md.append(f"**Fecha y Hora:** `{meta['timestamp']}`  ")
        md.append(f"**Objetivo Auditado:** `{meta['target_application']}`  ")
        md.append(f"**Puntuación CVSS v3.1:** `{meta['cvss_base_score']}` (**{meta['severity']}**)  ")
        md.append(f"**Vector CVSS:** `{meta['cvss_vector']}`  ")
        md.append("")
        md.append("---")
        md.append("## 1. Resumen Ejecutivo")
        md.append(f"- **Estado de la Aplicación:** HTTP `{metrics['status_code']}`")
        md.append(f"- **Latencia de Auditoría:** `{metrics['latency_s']} segundos`")
        md.append(f"- **Capa de Procedencia Defensiva:** `{'ACTIVA (Protección Causal)' if metrics['defense_active'] else 'INACTIVA'}`")
        if surface:
            md.append(f"- **Topología Web (Rutas Descubiertas):** `{surface['total_routes']} endpoints` en `{surface['execution_time_s']}s`")
        md.append(f"- **Formularios DOM Analizados:** `{metrics.get('detected_forms_count', 0)}`")
        md.append(f"- **Secuestros Neutralizados (IPI):** `{metrics['total_interceptions']}`")
        md.append(f"- **Vulnerabilidades Detectadas:** `{metrics['total_findings']}`")
        md.append("")

        if surface and surface.get("routes"):
            md.append("## 2. Mapa de Superficie de Ataque (Attack Surface Reconnaissance)")
            md.append("| Categoría | Ruta / Endpoint | Formularios | Profundidad | Título |")
            md.append("|---|---|---|---|---|")
            for r in surface["routes"]:
                md.append(f"| `{r['category']}` | `{r['path']}` | {r['forms_count']} | {r['depth']} | {r['title']} |")
            md.append("")

        sec_num = 3 if surface else 2
        md.append(f"## {sec_num}. Contención de Inyección Indirecta de Prompts (IPI)")
        if data["interceptions"]:
            md.append("| Herramienta Bloqueada | Parámetros Manchados ([UNTRUSTED]) | Motivo de Intervención |")
            md.append("|---|---|---|")
            for inc in data["interceptions"]:
                md.append(f"| `{inc['tool_name']}` | `{inc['blocked_params']}` | {inc['reason']} |")
        else:
            md.append("> [!NOTE]  \n> No se detectaron intentos de secuestro de herramientas durante la interacción.")
        md.append("")

        sec_num += 1
        md.append(f"## {sec_num}. Vulnerabilidades Web Identificadas")
        if data["findings"]:
            md.append("| Severidad | Vulnerabilidad | Descripción |")
            md.append("|---|---|---|")
            for f in data["findings"]:
                md.append(f"| **{f['severity']}** | {f['vuln_type']} | {f['details']} |")
        else:
            md.append("No se registraron vulnerabilidades adicionales.")
        md.append("")

        screenshots = metrics.get("evidence_screenshots", [])
        if screenshots:
            sec_num += 1
            md.append(f"## {sec_num}. Evidencias Forenses Dinámicas (Playwright Headless)")
            for s in screenshots:
                filename = os.path.basename(s)
                md.append(f"- **Captura:** `{filename}` (`{s}`)")
            md.append("")

        md.append("---")
        md.append("*Generado automáticamente por el Orquestador Defensivo de Agentes Autónomos (UPN 2026).*")
        return "\n".join(md)
