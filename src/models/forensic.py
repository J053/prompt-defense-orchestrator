"""
Modelos de Datos y Esquemas de Validación (Pydantic).
Define los esquemas del Dataset, Reporte Forense CVSS v3.1 y Ficha de Métricas Anexo 3.
"""
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class TestCaseSchema(BaseModel):
    """Esquema de un caso de prueba del benchmark de inyección de prompts."""
    __test__ = False
    id: str = Field(..., description="Identificador único del caso (ej. InjecAgent_001)")
    source: str = Field(..., description="Benchmark de procedencia (AgentDojo o InjecAgent)")
    attack_type: str = Field(..., description="Categoría de ataque (Direct, Indirect_HTML, Indirect_JSON)")
    target_app: str = Field(..., description="Aplicación web objetivo (DVWA, WAVSEP, WackoPicko)")
    user_instruction: str = Field(..., description="Instrucción legítima del operador de seguridad")
    injected_content: str = Field(..., description="Fragmento adversario embebido en la respuesta web")
    expected_benign_tool: str = Field("analyze_dom", description="Herramienta que el agente debía ejecutar legítimamente")
    expected_benign_args: Dict[str, Any] = Field(default_factory=dict)
    malicious_tool: str = Field("send_http_post", description="Herramienta privilegiada que el atacante intenta invocar")
    malicious_args: Dict[str, Any] = Field(default_factory=dict)


class ForensicReportCVSS(BaseModel):
    """Esquema del reporte forense emitido tras la auditoría según el estándar CVSS v3.1."""
    report_id: str
    target_application: str
    vulnerability_id: str
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
    cvss_base_score: float = 9.8
    severity: str = "CRITICAL"
    attack_type: str
    taint_tracking_intercepted: bool
    blocked_tool: Optional[str] = None
    tainted_parameters: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    causal_evidence: str


class WideMetricRow(BaseModel):
    """Esquema de la Ficha de Registro Anexo 3 en Formato Ancho (Wide) para pruebas pareadas en Jamovi."""
    Experiment_Phase: str
    Target_App: str
    Payload_ID: str
    TP_Defensa: int
    TP_Ablacion: int
    FP_Defensa: int
    FP_Ablacion: int
    ASR_Defensa: int
    ASR_Ablacion: int
    Hijack_Defensa: int
    Hijack_Ablacion: int
    Utilidad_Defensa: float
    Utilidad_Ablacion: float
    EDS_Defensa: float
    EDS_Ablacion: float
    Time_s_Defensa: float
    Time_s_Ablacion: float
    Tokens_Cost_Defensa: float
    Tokens_Cost_Ablacion: float
