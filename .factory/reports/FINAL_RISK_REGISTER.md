# FINAL RISK REGISTER — 0.1.2

| ID | Riesgo | Prob. | Impacto | Mitigación actual | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| R-01 | Outbox sin LISTEN/NOTIFY/jobs | Media | Medio | poll 1 s + SKIP LOCKED + leases | Abierto (TASK-008) |
| R-02 | Consumidor externo no idempotente duplica efectos | Media | Alto | contrato documentado; notificaciones idempotentes | Abierto |
| R-03 | Forja de auditoría con clave + BD | Baja | Crítico | HMAC v3 + checkpoints; falta WORM externo | Parcial |
| R-04 | Picos de ingesta sin particiones | Media | Alto | retención y límites; sin benchmark | Abierto |
| R-05 | Búsqueda LIKE sin FTS a escala | Alta | Medio | cursor + índices; benchmark pendiente | Abierto |
| R-06 | Cloud CSPM/importadores ausentes | Alta | Medio | declarado no soportado | Aceptado |
| R-07 | E2E/Docker/restore no ejecutados | Alta | Medio | gates marcados NOT RUN | Abierto |
| R-08 | Revisión independiente no realizada | Alta | Alto | auditor mismo equipo | Abierto |
| R-09 | Break-glass single-admin autoaprobado | Media | Medio | ticket, justificación, TTL, auditoría | Aceptado |
| R-10 | air-gap no verificado | Media | Alto | bundle pendiente | Abierto |

No se acepta ningún riesgo CRITICAL/HIGH sin dueño y fecha de revisión.
