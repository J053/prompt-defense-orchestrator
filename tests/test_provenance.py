"""
Pruebas Unitarias para la Capa de Procedencia y Seguimiento de Máculas (Taint Tracking).
"""
import pytest
from src.defense.provenance import (
    SourceTag,
    TaintTracker,
    ParamPolicyBlockedException,
    ParamPolicyValidator,
    DualGraphAlignment
)


def test_taint_tracker_tagging():
    """Verifica que los datos no confiables reciban la etiqueta [UNTRUSTED_EXTERNAL]."""
    raw_html = "<html><body><h1>Search Results</h1><script>alert(1)</script></body></html>"
    tagged = TaintTracker.sanitize_and_tag(raw_html, source_type="untrusted")
    assert tagged.startswith(SourceTag.UNTRUSTED_EXTERNAL.value)
    assert TaintTracker.is_tainted(tagged) is True


def test_taint_tracker_trusted():
    """Verifica que las directivas del operador mantengan el tag [TRUSTED]."""
    operator_instruction = "Auditar endpoints SQLi en formulario de login."
    tagged = TaintTracker.sanitize_and_tag(operator_instruction, source_type="operator")
    assert tagged.startswith(SourceTag.TRUSTED.value)
    assert TaintTracker.is_tainted(tagged) is False


def test_param_policy_blocks_tainted_tool_call():
    """Verifica que la compuerta ParamPolicy aborte una llamada privilegiada con parámetros contaminados."""
    tainted_param = TaintTracker.sanitize_and_tag("http://attacker.com/steal_cookie", source_type="untrusted")
    tool_args = {"url": tainted_param, "method": "POST"}

    with pytest.raises(ParamPolicyBlockedException) as excinfo:
        ParamPolicyValidator.validate_tool_call("send_http_post", tool_args, is_defense_active=True)

    assert "bloqueada" in str(excinfo.value)
    assert "send_http_post" in str(excinfo.value)


def test_param_policy_allows_trusted_tool_call():
    """Verifica que las herramientas benignas con parámetros limpios se ejecuten sin restricciones."""
    clean_args = {"dom_element": "form#login", "action": "inspect"}
    allowed, status = ParamPolicyValidator.validate_tool_call("analyze_dom", clean_args, is_defense_active=True)
    assert allowed is True
    assert status == "ALLOWED_TRUSTED"


def test_param_policy_ablation_allows_all():
    """En modo ablación (Defensa OFF), verifica que no se bloquee la herramienta (simulando secuestro)."""
    tainted_param = TaintTracker.sanitize_and_tag("http://attacker.com/leak", source_type="untrusted")
    tool_args = {"url": tainted_param}
    allowed, status = ParamPolicyValidator.validate_tool_call("send_http_post", tool_args, is_defense_active=False)
    assert allowed is True
    assert status == "ALLOWED_ABLATION"


def test_dual_graph_alignment():
    """Verifica que AuthGraph detecte la desviación entre el grafo de razonamiento inyectado y el limpio."""
    clean_graph = ["analyze_dom", "inspect_forms", "calculate_cvss", "log_evidence"]
    injected_graph = ["analyze_dom", "send_http_post", "exfiltrate_data"]

    aligned, score = DualGraphAlignment.verify_alignment(injected_graph, clean_graph)
    assert aligned is False
    assert score < 1.0

    aligned_ok, score_ok = DualGraphAlignment.verify_alignment(clean_graph, clean_graph)
    assert aligned_ok is True
    assert score_ok == 1.0
