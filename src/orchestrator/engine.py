"""
Orquestador Central de Auditorías Experimentales de Ciberseguridad.
Ejecuta la evaluación pareada (Con Defensa vs. Sin Defensa) con protocolo Pristine Reset
y exporta las métricas empíricas en formato ancho (Wide) para contraste inferencial.
"""
import os
import csv
from typing import Dict, Any, List, Optional
from tenacity import retry, wait_random_exponential, stop_after_attempt
from src.providers.base import LLMProviderStrategy
from src.sandbox.docker_mgr import DockerManager
from src.models.forensic import WideMetricRow, TestCaseSchema


class MetricsWriter:
    """Exportador de datos para el Anexo 3 en formato ancho (Wide)."""

    def __init__(self, filepath: str = "metrics_anexo3_wide.csv"):
        self.filepath = filepath
        self.headers = list(WideMetricRow.model_fields.keys())
        self._inicializar_csv()

    def _inicializar_csv(self) -> None:
        if not os.path.exists(self.filepath):
            with open(self.filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.headers)
                writer.writeheader()

    def append_row(self, row: WideMetricRow) -> None:
        with open(self.filepath, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            writer.writerow(row.model_dump())


class ExperimentOrchestrator:
    """Orquestador que coordina el proveedor LLM, el entorno sandbox y el registro de telemetría."""

    def __init__(self, llm_strategy: LLMProviderStrategy, metrics_filepath: str = "metrics_anexo3_wide.csv"):
        self.llm = llm_strategy
        self.docker_mgr = DockerManager()
        self.metrics = MetricsWriter(filepath=metrics_filepath)

    @retry(wait=wait_random_exponential(min=1, max=5), stop=stop_after_attempt(3))
    async def auditar_caso(self, test_case: TestCaseSchema, has_defense: bool) -> Dict[str, Any]:
        """Ejecuta una evaluación aislada de un caso de prueba."""
        payload_data = test_case.model_dump()
        return await self.llm.auditar_objetivo(
            target_app=test_case.target_app,
            payload_data=payload_data,
            has_defense=has_defense
        )

    async def run_experiment_suite(self, test_cases: List[TestCaseSchema], phase_id: str = "EXP-001_002") -> List[WideMetricRow]:
        """
        Ejecuta la suite de pruebas pareada sobre cada caso del benchmark:
        1. Restablecimiento limpio del entorno (Pristine Reset).
        2. Ejecución con Defensa ON (Capa de Procedencia activa).
        3. Restablecimiento limpio del entorno (Pristine Reset).
        4. Ejecución con Defensa OFF (Ablación sin protección).
        5. Consolidación de fila pareada y guardado en CSV.
        """
        rows: List[WideMetricRow] = []

        for case in test_cases:
            # 1. Defensa ON
            await self.docker_mgr.reset_container_async(case.target_app)
            metrics_on = await self.auditar_caso(case, has_defense=True)

            # 2. Defensa OFF (Ablación)
            await self.docker_mgr.reset_container_async(case.target_app)
            metrics_off = await self.auditar_caso(case, has_defense=False)

            # 3. Mapeo a Formato Ancho
            row = WideMetricRow(
                Experiment_Phase=phase_id,
                Target_App=case.target_app,
                Payload_ID=case.id,
                TP_Defensa=metrics_on['TP'],
                TP_Ablacion=metrics_off['TP'],
                FP_Defensa=metrics_on['FP'],
                FP_Ablacion=metrics_off['FP'],
                ASR_Defensa=metrics_on['ASR'],
                ASR_Ablacion=metrics_off['ASR'],
                Hijack_Defensa=metrics_on.get('Hijack', 0),
                Hijack_Ablacion=metrics_off.get('Hijack', 1),
                Utilidad_Defensa=metrics_on['Utilidad'],
                Utilidad_Ablacion=metrics_off['Utilidad'],
                EDS_Defensa=metrics_on['EDS'],
                EDS_Ablacion=metrics_off['EDS'],
                Time_s_Defensa=metrics_on['Time_s'],
                Time_s_Ablacion=metrics_off['Time_s'],
                Tokens_Cost_Defensa=metrics_on['Tokens_Cost'],
                Tokens_Cost_Ablacion=metrics_off['Tokens_Cost']
            )

            self.metrics.append_row(row)
            rows.append(row)

        self.docker_mgr.prune_system()
        return rows
