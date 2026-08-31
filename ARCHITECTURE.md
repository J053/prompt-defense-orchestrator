# 🏛️ Arquitectura de Software e Ingeniería

Este documento sustenta las decisiones de diseño para el **Capítulo III** de la Tesis, asegurando el cumplimiento de la metodología CRISP-DM y el desacoplamiento de agentes.

## 1. Arquitectura Multi-Agente (Separation of Concerns)

`mermaid
graph TD;
    subgraph Orquestador_Central
        A[Experiment Orchestrator]
    end
    
    subgraph LLM_Strategy
        B[LLMProviderStrategy]
        B1[AntigravityProvider]
        B2[GeminiProvider]
        B3[OllamaProvider]
        B <|-- B1
        B <|-- B2
        B <|-- B3
    end
    
    subgraph Infraestructura
        C[DockerManager]
        D[MetricsWriter - CSV Incremental]
    end
    
    A -->|Inyección de Dependencia| B
    A -->|Manejo de Estado| C
    A -->|Tracking Fail-Safe| D
`

## 2. Flujo Metodológico CRISP-DM

`mermaid
flowchart LR
    F1[Comprensión del Negocio\n- Modelo de Amenazas] --> F2[Comprensión de Datos\n- Corpus AgentDojo/InjecAgent]
    F2 --> F3[Preparación de Datos\n- Taint Tracking]
    F3 --> F4[Modelado\n- Arquitectura Multi-Agente]
    F4 --> F5[Evaluación Experimental\n- Bucle N=30 con Jamovi]
    F5 --> F6[Despliegue\n- Docker y JSON/PDF]
`

## 3. Justificación de Decisiones (State of the Art)

*   **Pristine Docker Reset:** Controla el sesgo de rendimiento garantizando entornos vírgenes, mitigando la "contaminación de estados" (Yu et al., 2026).
*   **Desacoplamiento de Agentes:** El sistema separa las responsabilidades de reconocimiento y explotación para evitar la "cascada de errores" (Li et al., 2026).
*   **Determinismo y Excepciones:** Se fuerza la semilla (\seed=42\) y \	emperature=0.0\. Las trazas de excepción asíncronas se truncan para evitar el colapso del contexto (Context Collapse).
