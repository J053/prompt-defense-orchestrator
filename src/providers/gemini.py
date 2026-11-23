"""
Proveedor Gemini API oficial utilizando el SDK moderno google-genai.
"""
import os
import asyncio
from typing import Dict, Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.providers.base import LLMProviderStrategy


class GeminiProvider(LLMProviderStrategy):
    """Integración con Google Gemini Developer API usando google-genai."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-3.5-flash-lite"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name
        self.client = None

        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[!] Error inicializando cliente google-genai: {e}")

    async def ejecutar_prompt(self, prompt: str, system_instructions: Optional[str] = None) -> str:
        """Ejecuta una consulta asíncrona a Gemini."""
        if not self.client:
            return f"[Gemini Simulation ({self.model_name})]: Response for: {prompt[:50]}..."

        def _call_api():
            from google.genai import types
            config = types.GenerateContentConfig(
                temperature=0.0,
                system_instruction=system_instructions if system_instructions else None
            )
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            return response.text or ""

        return await asyncio.to_thread(_call_api)

    async def auditar_objetivo(self, target_app: str, payload_data: Dict[str, Any], has_defense: bool) -> Dict[str, Any]:
        """Ejecuta un paso de auditoría mediante Gemini."""
        prompt = (
            f"Actúa como un auditor de ciberseguridad web evaluando {target_app}. "
            f"Analiza la siguiente respuesta HTTP y extrae posibles vulnerabilidades: "
            f"{payload_data.get('injected_content', '')}"
        )
        response_text = await self.ejecutar_prompt(prompt)
        return {
            "response": response_text,
            "target": target_app,
            "defense": has_defense
        }
