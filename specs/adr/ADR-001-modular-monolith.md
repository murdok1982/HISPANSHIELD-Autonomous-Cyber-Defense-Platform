# ADR-001: Monolito modular con FastAPI (Python 3.12)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Decisores:** Arquitectura, Plataforma
- **Relacionados:** `ADR-002`, `ADR-003`, `ADR-004`, `ADR-012`

## Contexto

HISPANSHIELD debe desplegarse en administraciones públicas y operadores de infraestructuras críticas, con frecuencia en air-gap y con equipos de TI pequeños. Doce dominios funcionales comparten datos con alta interconexión (activo ↔ vulnerabilidad ↔ evento ↔ incidente ↔ política). El entorno verificado no dispone de orquestador de contenedores ni de plataforma de microservicios.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Microservicios por dominio | Escalado independiente, aislamiento de fallos | Coste operativo, latencia, consistencia distribuida, 12 deployments en air-gap |
| Monolito no modular | Simplicidad inicial | Acoplamiento, imposible extraer dominios, tests frágiles |
| **Monolito modular (elegido)** | Un artefacto, fronteras explícitas, transacciones locales | Escalado vertical y por workers; requiere disciplina |

## Decisión

Un único backend Python 3.12 con FastAPI, organizado en módulos de frontera estricta (`api → services → repositories → models`), workers separados por cola (no por servicio) y contratos internos vía `services/public.py` y eventos de outbox.

## Consecuencias

**Positivas**
- Despliegue y backup simples (un binario, una BD).
- Transacciones atómicas entre dominio y eventos.
- Depuración local sin infraestructura distribuida.
- Camino de extracción: cada módulo ya expone interfaz pública y eventos.

**Negativas**
- Escalado no independiente por dominio; se compensa con workers especializados.
- Riesgo de erosión de fronteras; mitigado con `test_import_boundaries.py` (AST) y revisión.
- Un fallo de proceso afecta a más funciones; mitigado con aislamiento de workers y reinicio supervisado.

**Métricas de reversión**
- Si un dominio requiere >50% de la CPU total de forma sostenida, se evalúa extraerlo.
- Si el tiempo de despliegue supera 15 min o el acoplamiento impide cambios aislados en 2 releases consecutivos, se replantea.

## Verificación

`backend/tests/unit/test_import_boundaries.py`; estructura de `ARCHITECTURE.md §2`; revisión de PR con checklist de fronteras.
