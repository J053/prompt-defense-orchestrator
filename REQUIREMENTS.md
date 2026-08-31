# 📝 Requerimientos de Ingeniería (Fase 1 CRISP-DM)

## Requerimientos Funcionales (RF)
| ID | Descripción | Prioridad |
|---|---|---|
| RF-01 | El orquestador debe permitir inyectar estrategias LLM dinámicamente (Antigravity, Gemini, Ollama). | Alta |
| RF-02 | El sistema debe automatizar la destrucción y creación del entorno Docker (Pristine Reset). | Alta |
| RF-03 | El sistema debe calcular el Efective Defense Score (EDS) en tiempo real por cada iteración. | Alta |
| RF-04 | Las métricas deben exportarse incrementalmente a un CSV en formato ancho (*Wide Format*). | Alta |

## Requerimientos No Funcionales (RNF)
| ID | Descripción | Prioridad |
|---|---|---|
| RNF-01 | **Reproducibilidad:** El sistema debe usar \	emperature=0.0\ y \seed=42\ para garantizar resultados constantes. | Alta |
| RNF-02 | **Tolerancia a Fallos:** El sistema debe manejar los límites de tasa de las API (HTTP 429) usando Exponential Backoff. | Media |
| RNF-03 | **Desacoplamiento:** La lógica de conexión con Docker no debe bloquear el Event Loop del flujo asíncrono del LLM. | Alta |
