"""
Modelos de Datos y Esquemas de Validación (Pydantic).
Define los esquemas del Dataset, Reporte Forense CVSS v3.1 y Ficha de Métricas Anexo 3.
"""
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field


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
    model_config = ConfigDict(allow_inf_nan=False)

    Experiment_Phase: str
    Target_App: str
    Payload_ID: str
    TP_Defensa: int = Field(ge=0, le=1)
    TP_Ablacion: int = Field(ge=0, le=1)
    FP_Defensa: int = Field(ge=0, le=1)
    FP_Ablacion: int = Field(ge=0, le=1)
    ASR_Defensa: int = Field(ge=0, le=1)
    ASR_Ablacion: int = Field(ge=0, le=1)
    Hijack_Defensa: int = Field(ge=0, le=1)
    Hijack_Ablacion: int = Field(ge=0, le=1)
    Utilidad_Defensa: float = Field(ge=0, le=1)
    Utilidad_Ablacion: float = Field(ge=0, le=1)
    EDS_Defensa: float = Field(ge=0, le=1)
    EDS_Ablacion: float = Field(ge=0, le=1)
    Time_s_Defensa: float = Field(ge=0)
    Time_s_Ablacion: float = Field(ge=0)
    Tokens_Cost_Defensa: float = Field(ge=0)
    Tokens_Cost_Ablacion: float = Field(ge=0)
