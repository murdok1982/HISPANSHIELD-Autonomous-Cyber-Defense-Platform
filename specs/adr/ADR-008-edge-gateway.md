# ADR-008: Edge gateway Python + SQLite WAL store-and-forward con mTLS

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-002`, `specs/integrations/connector-contract.md`, `specs/architecture/deployment-architecture.md`

## Contexto

Las sedes (subestaciones, hospitales, edificios administrativos) tienen conectividad intermitente y equipos limitados. Los eventos no pueden perderse durante un corte, y el reenvío debe respetar el orden. No se puede asumir Docker ni un agente pesado.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Forwarder ligero (Fluent Bit/Vector) | Maduro, eficiente | Configuración compleja, binario externo, menos control del contrato |
| Agente en Go/Rust | Binario único, rendimiento | Otro lenguaje y toolchain en el proyecto |
| **Python + SQLite WAL (elegido)** | Mismo lenguaje, fácil de auditar, SQLite robusto, sin servicio | Consumo mayor que Go; límites de throughput por sede |
| Buffer en memoria | Simple | Pérdida al reiniciar |

## Decisión

Paquete `hispanshield_edge` con cola SQLite en modo WAL, secuencia monotónica por evento, reintentos con backoff, envío por lotes firmados (HMAC) sobre mTLS opcional/exigible, configuración YAML+env, unidad systemd, CLI de operación (`status`, `flush`, `export`).

## Consecuencias

**Positivas**
- Cero pérdida de eventos aceptados localmente; reenvío ordenado por `sequence`.
- Instalación en appliance mínimo sin contenedores.
- Mismo contrato HTTP que cualquier conector; testeable de forma aislada.
- Fácil de auditar (pocas dependencias).

**Negativas**
- Throughput por sede limitado (miles de ev/s, suficiente para una sede).
- Sin HA nativa: se documenta activo/pasivo.
- SQLite requiere cuidado con corrupción (WAL, checkpoint, backups locales).

**Métricas de reversión**
- Si una sede supera 20k ev/s sostenidos, evaluar forwarder compilado.
- Si la corrupción de cola ocurre >1 vez al año, revisar diseño de persistencia.

## Verificación

`edge/tests/test_store_and_forward.py` (1.000 eventos, corte de red, orden exacto), `test_mtls.py`, `test_contract.py`, prueba de reinicio con cola no vacía.
