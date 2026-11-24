# Prompt Defense Orchestrator

Sistema de agentes autónomos basados en modelos de lenguaje con **Capa de Procedencia** (*data provenance*) para automatizar auditorías de ciberseguridad web sin perder capacidad diagnóstica frente a ataques de inyección indirecta de prompts.

**Tesis:** *Implementación de un sistema de agentes autónomos resistente a inyección de prompts para la automatización de auditorías de ciberseguridad web en el sector comercial, Perú, 2026*

---

## Estado del repositorio

- El orquestador está implementado en Python asíncrono y ejecuta el ciclo completo: despliegue del entorno vulnerable, agente de reconocimiento, agente de explotación, intercepción de políticas y reporte forense.
- El **corpus de evaluación** que sustenta el Capítulo IV de la tesis está en `data/metrics_anexo3_wide.csv`: 1.683 casos pareados, 19 variables, condiciones *Con Defensa* y *Sin Defensa (Ablación)*.
- Los **experimentos locales de control** están en `experiments/`: el protocolo congelado en `pilot-v1/` y los intentos ejecutados en `local-real-v1/`.
- Alcance declarado: laboratorio con aplicaciones vulnerables contenerizadas (DVWA, WAVSEP, WackoPicko) y corpus públicos de inyección indirecta. No sustituye una auditoría en producción.

## Arquitectura

Diseño por capas con **Patrón Strategy** e inyección de dependencias, de modo que el proveedor del modelo se intercambia sin tocar la lógica de auditoría.

```
src/
├── orchestrator/     motor de ejecución y ciclo de auditoría
├── providers/        adaptadores de modelo (Gemini, Ollama, mock de pruebas)
├── defense/          Capa de Procedencia: etiquetado, ParamPolicy y compuertas
├── sandbox/          orquestación de contenedores (Pristine Docker Reset)
├── experiments/      contrato de decisiones y agregación de métricas
└── models/           modelos forenses (hallazgos, severidad CVSS, trazas)
```

Flujo de una auditoría:

1. **Despliegue** del contenedor vulnerable con reinicio inmutable.
2. **Reconocimiento**: el agente explora rutas, formularios y respuestas HTTP.
3. **Etiquetado de procedencia**: todo texto externo entra como `[UNTRUSTED_EXTERNAL]`.
4. **Explotación**: cada invocación de herramienta pasa por `ParamPolicyValidator`.
5. **Registro**: traza causal, hallazgo con CVSS v3.1 y métricas de tiempo y costo.

## Estructura del repositorio

| Ruta | Contenido |
|---|---|
| `src/` | Código del orquestador y de la capa de defensa |
| `scripts/` | Ejecutables: auditoría, experimentos, estadística inferencial, figuras |
| `tests/` | Suite de pruebas unitarias y de contrato |
| `data/` | Corpus de evaluación y métricas de ejecuciones |
| `experiments/` | Protocolo del piloto, casos, calendario y resultados |
| `reports/` | Reportes forenses JSON/Markdown y evidencias |
| `figures/` | Figuras del informe de tesis |
| `out/` | Salida incremental de experimentos (no versionada) |

## Instalación

```bash
python -m venv venv
.\venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

Requiere Docker Desktop en ejecución para las pruebas con contenedores.

## Uso

```bash
# Auditoría sobre una URL (genera reporte forense en reports/)
python audit.py --target http://127.0.0.1:8080

# Experimentos sobre los bancos de prueba
python scripts/run_experiments.py

# Piloto local de control (modelo local, sin API externa)
python scripts/run_local_pilot.py

# Estadística inferencial del corpus (McNemar, Wilcoxon, normalidad)
python scripts/compute_inferential_stats.py

# Pruebas
python -m pytest -q
```

## Datos

`data/metrics_anexo3_wide.csv` contiene una fila por caso con ambas condiciones:

| Bloque | Variables |
|---|---|
| Identificación | `Experiment_Phase`, `Target_App`, `Payload_ID` |
| Detección | `TP_Defensa`, `TP_Ablacion`, `FP_Defensa`, `FP_Ablacion` |
| Resistencia | `ASR_Defensa`, `ASR_Ablacion`, `Hijack_Defensa`, `Hijack_Ablacion` |
| Equilibrio | `Utilidad_Defensa`, `Utilidad_Ablacion`, `EDS_Defensa`, `EDS_Ablacion` |
| Eficiencia | `Time_s_Defensa`, `Time_s_Ablacion`, `Tokens_Cost_Defensa`, `Tokens_Cost_Ablacion` |

Agregados del corpus: ASR 38,09 % → 0,83 %; EDS 0,5840 → 0,9399; TP 70,83 % → 92,39 %; FP 5,29 % → 1,19 %; latencia media +59,4 ms; costo medio USD 0,00235 por caso.

## Reproducibilidad

- Semilla y parámetros fijados (`temperature = 0`) en el protocolo del piloto.
- Hashes de casos, calendario y configuración registrados en `experiments/pilot-v1/freeze.json`.
- Versión del modelo y del entorno guardadas en `experiments/local-real-v1/metadata.json`.
- Cada intento conserva su traza individual en `experiments/local-real-v1/attempts/`.

## Limitaciones

- Los bancos de prueba son aplicaciones de referencia, no plataformas comerciales.
- El corpus de inyecciones es cerrado y estático: no cubre ataques adaptativos de segundo orden.
- La evidencia corresponde a una sola configuración de modelo y a una red local aislada.
- Las métricas se obtuvieron sin tráfico concurrente; la latencia en producción será mayor.

## Cita

```bibtex
@misc{provenance2026,
  title  = {Implementación de un sistema de agentes autónomos resistente a inyección de prompts
            para la automatización de auditorías de ciberseguridad web en el sector comercial, Perú, 2026},
  author = {Grupo de investigación},
  year   = {2026},
  note   = {Tesis de pregrado, Universidad Privada del Norte}
}
```
