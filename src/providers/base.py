"""
Patrón Strategy: Interfaz base para proveedores de Modelos de Lenguaje Grande (LLM).
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class LLMProviderStrategy(ABC):
    """Interfaz abstracta que define la ejecución de prompts y llamadas a herramientas."""

    supplies_legacy_metrics = False

    @abstractmethod
    async def ejecutar_prompt(self, prompt: str, system_instructions: Optional[str] = None) -> str:
        """Envía el prompt al modelo y retorna la respuesta de texto."""
        pass

    @abstractmethod
    async def auditar_objetivo(self, target_app: str, payload_data: Dict[str, Any], has_defense: bool) -> Dict[str, Any]:
        """Ejecuta un ciclo de auditoría y retorna las métricas de respuesta."""
        pass
