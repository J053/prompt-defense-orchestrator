"""
Módulo de Capa de Procedencia y Seguimiento de Máculas (Data Provenance & Taint Tracking).
Implementa la separación de planos, el etiquetado de procedencia y la compuerta ParamPolicy.
"""
from enum import Enum
from typing import Any, Dict, List, Tuple


class SourceTag(str, Enum):
    TRUSTED = "[TRUSTED]"
    UNTRUSTED_EXTERNAL = "[UNTRUSTED_EXTERNAL]"
    SYSTEM = "[SYSTEM]"


class ParamPolicyBlockedException(Exception):
    """Excepción lanzada cuando una política de parámetros bloquea una llamada a herramienta secuestrada."""
    def __init__(self, tool_name: str, param_name: str, reason: str):
        super().__init__(f"ParamPolicy BLOCK: Herramienta '{tool_name}' bloqueada en parámetro '{param_name}'. Motivo: {reason}")
        self.tool_name = tool_name
        self.param_name = param_name
        self.reason = reason


class TaintTracker:
    """Rastreador de procedencia causal que etiqueta y verifica el flujo de datos."""

    @staticmethod
    def sanitize_and_tag(data: str, source_type: str = "untrusted") -> str:
        """
        Sanitiza y etiqueta los datos de entrada según su nivel de confiabilidad.
        """
        if not isinstance(data, str):
            data = str(data)

        if source_type in ("untrusted", "external", "web_response", "html"):
            tag = SourceTag.UNTRUSTED_EXTERNAL.value
        elif source_type in ("system", "operator"):
            tag = SourceTag.TRUSTED.value
        else:
            tag = SourceTag.UNTRUSTED_EXTERNAL.value

        # Neutralizar escapes nulos y delimitadores de inyección
        clean_text = data.replace("\x00", "").strip()
        return f"{tag} {clean_text}"

    @classmethod
    def is_tainted(cls, value: Any) -> bool:
        """
        Verifica de forma recursiva si un valor contiene la etiqueta de dato contaminado / no confiable.
        """
        if isinstance(value, str):
            return SourceTag.UNTRUSTED_EXTERNAL.value in value
        elif isinstance(value, dict):
            return any(cls.is_tainted(k) or cls.is_tainted(v) for k, v in value.items())
        elif isinstance(value, (list, tuple, set)):
            return any(cls.is_tainted(item) for item in value)
        return False


class ParamPolicyValidator:
    """Validador de políticas de invocación de herramientas en tiempo de ejecución."""

    SENSITIVE_TOOLS = {
        "send_http_post",
        "execute_command",
        "send_email",
        "write_file",
        "file_write",
        "exfiltrate_data",
        "drop_database",
        "modify_privileges",
        "bash_execute",
        "request_external_url"
    }

    BENIGN_TOOLS = {
        "analyze_dom",
        "list_endpoints",
        "parse_headers",
        "calculate_cvss",
        "log_evidence",
        "inspect_forms",
        "report_vulnerability",
        "record_observation",
        "detect_sqli",
        "check_xss",
        "test_csrf",
        "detect_rce"
    }

    @classmethod
    def validate_tool_call(cls, tool_name: str, tool_args: Dict[str, Any], is_defense_active: bool = True) -> Tuple[bool, str]:
        """
        Intervención causal antes de ejecutar la herramienta.
        Si la defensa está activa y una herramienta privilegiada recibe parámetros contaminados,
        aborta la ejecución y bloquea el secuestro del agente.
        """
        if tool_name not in cls.SENSITIVE_TOOLS | cls.BENIGN_TOOLS:
            raise ParamPolicyBlockedException(tool_name, "*", "Herramienta no registrada")

        if not is_defense_active:
            # Modo Ablación (Defensa OFF): Permite la ejecución, permitiendo que el payload secuestre la herramienta
            return True, "ALLOWED_ABLATION"

        if tool_name in cls.SENSITIVE_TOOLS:
            for param_key, param_value in tool_args.items():
                if TaintTracker.is_tainted(param_value):
                    reason = f"Parámetro '{param_key}' contiene datos etiquetados con {SourceTag.UNTRUSTED_EXTERNAL.value}"
                    raise ParamPolicyBlockedException(tool_name, param_key, reason)

        return True, "ALLOWED_TRUSTED"


class DualGraphAlignment:
    """Comprobación de pertenencia de herramientas; no valida aristas ni orden causal."""

    @staticmethod
    def verify_alignment(injected_reasoning_graph: List[str], authorization_graph: List[str]) -> Tuple[bool, float]:
        """
        Contrasta la secuencia de herramientas invocadas (IRG) frente al grafo limpio de autorización (AG).
        Retorna (is_aligned, alignment_score).
        """
        if not injected_reasoning_graph:
            return True, 1.0

        clean_set = set(authorization_graph)
        unauthorized_steps = [tool for tool in injected_reasoning_graph if tool not in clean_set]

        if unauthorized_steps:
            score = max(0.0, 1.0 - (len(unauthorized_steps) / len(injected_reasoning_graph)))
            return False, score

        return True, 1.0
