# 🛡️ Prompt Defense Orchestrator

**Tesis:** Sistema de Agentes Autónomos Basado en Modelos de Lenguaje Grande Resistente a Inyección de Prompts para la Detección de Vulnerabilidades Web en el Sector Comercial, Perú, 2026.
**Autores:** Grupo de investigación (Grupo 12)
**Universidad:** Universidad Privada del Norte (UPN) - Taller de Tesis 2

## 🎯 Descripción del Proyecto
Plataforma orquestadora basada en Python que automatiza la ejecución de auditorías de ciberseguridad utilizando agentes LLM autónomos. Incorpora metodologías de mitigación de sesgos como el **Pristine Docker Reset** y el **Taint Tracking** (Capa de Procedencia) para aislar datos no confiables y evitar la cascada de errores (*error cascading*).

## 🛠️ Arquitectura Base
El software ha sido diseñado aplicando el **Patrón Strategy** y la **Inyección de Dependencias**, lo que permite intercambiar el cerebro del agente (LLM Provider) de manera dinámica sin alterar la lógica de las pruebas:
- \AntigravityProvider\ (Motor actual basado en SDK asíncrono)
- \GeminiProvider\ (API RESTful)
- \OllamaProvider\ (Modelos locales Llama3/Mistral)

Toda la ejecución ha sido migrada a un flujo asíncrono (\syncio\), encapsulando las interacciones con Docker en subprocesos aislados para máxima eficiencia operativa.

## 🚀 Instalación y Reproducibilidad
Para cumplir con los estándares de rigor científico, este software garantiza la reproducibilidad de los experimentos.

1. **Crear y activar el entorno virtual:**
   \\\ash
   python -m venv venv
   .\venv\Scripts\activate
   \\\
2. **Instalar dependencias fijadas:**
   \\\ash
   pip install -r requirements.txt
   \\\
3. **Despliegue del Entorno de Pruebas (Docker):**
   Asegúrate de tener Docker Desktop en ejecución. Los contenedores vulnerables (DVWA, WAVSEP, WackoPicko) serán instanciados y destruidos automáticamente por el orquestador en cada iteración del experimento.
   
4. **Ejecutar Pruebas (Semana 5):**
   \\\ash
   python scripts/run_experiments.py
   \\\
   Los resultados se exportarán de forma incremental (*Fail-Safe*) a \out/metrics_anexo3_wide.csv\ en formato "Ancho", listo para contrastes de hipótesis pareadas en Jamovi (McNemar, Wilcoxon, t-Student).
