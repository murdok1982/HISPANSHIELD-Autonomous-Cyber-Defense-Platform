# ROADMAP

- **Documento:** `docs/roadmap.md`
- **Estado:** `APPROVED` v1.0
- **Nota:** las fases son relativas y dependen del gate anterior; no se prometen fechas sin equipo asignado.

---

## 1. VISIÓN DE RELEASES

| Release | Contenido | Criterio de salida | Estado |
| :--- | :--- | :--- | :--- |
| `1.0` MVP operativo | 12 dominios, 23 pantallas, autonomía A0-A4, cumplimiento UE, air-gap | Exit Gate completo | `SPECIFIED` |
| `1.1` Endurecimiento | Mejoras de rendimiento, más conectores, OIDC experimental | 1.0 en producción ≥3 meses | `PLANNED` |
| `1.2` Escala | pgvector/Qdrant opcional, HA documentada, más frameworks | Demanda de clientes | `PLANNED` |
| `2.0` Federación | OIDC/SAML, multi-instancia, analítica avanzada | Requisito de mercado | `EXPLORATION` |

---

## 2. FASE 1.0 — DETALLE POR TRIMESTRE LÓGICO

### Q1 lógico: Núcleo y confianza
- Fases 0-1: scaffolding, seguridad base, identidad, tenancy, RBAC, design system, shell.
- Hitos: `D1` (login+RBAAC+aislamiento), `D2` parcial.
- Riesgo dominante: aislamiento multi-tenant.

### Q2 lógico: Contexto y detección
- Fases 2-3: activos, ASM, vulnerabilidades, SIEM, detección, alertas, búsqueda, SSE.
- Hitos: `D2`, `D3`.
- Riesgo dominante: rendimiento de ingesta y búsqueda.

### Q3 lógico: Respuesta y autonomía
- Fases 4-6: incidentes, CTI, forense, SOAR, autonomía, kill switch, laboratorio.
- Hitos: `D4`, `D5`, `D6`.
- Riesgo dominante: acciones destructivas y durabilidad.

### Q4 lógico: IA, superficies y cumplimiento
- Fases 7-9: IA, IoT/OT/Cloud, conectores, edge, cumplimiento, informes.
- Hitos: `D7`, `D8`, `D9`.
- Riesgo dominante: honestidad de IA y exactitud normativa.

### Cierre: Consola y entrega
- Fases 10-11: 23 pantallas, a11y, E2E, deploy, backup, air-gap, SBOM, auditoría.
- Hitos: `D10`, `D11`.
- Riesgo dominante: calidad visual y verificación de despliegue.

---

## 3. BACKLOG POST-1.0 (PRIORIZADO)

| Prioridad | Item | Valor | Esfuerzo | Dependencia |
| :--- | :--- | :--- | :--- | :--- |
| P1 | Federación OIDC/SAML | Integración corporativa | Alto | Interfaz `auth/providers.py` |
| P1 | Más conectores (EDR/firewall/IdP específicos) | Cobertura real | Medio | Contrato de conector |
| P1 | Descubrimiento pasivo de red (SPAN/NetFlow) | Visibilidad | Alto | Nuevo protocolo |
| P2 | pgvector/Qdrant opcional | RAG a escala | Medio | `VectorStore` |
| P2 | Alta disponibilidad multi-nodo | Continuidad | Alto | Réplica + leader election |
| P2 | Motor de correlación avanzado (grafo) | Detección | Alto | Neo4j o tablas de grafo |
| P3 | Adquisición forense remota (agente) | Forense | Muy alto | Nuevo componente endpoint |
| P3 | Escritura OT controlada | Respuesta industrial | Muy alto | Certificación y safety case |
| P3 | App móvil | Notificación | Medio | API estable |
| P3 | Marketplace de playbooks | Ecosistema | Medio | Versionado y firma |

---

## 4. CRITERIOS DE PRIORIZACIÓN

1. **Seguridad y cumplimiento** antes que funcionalidad nueva.
2. **Cobertura de un caso de uso completo** antes que amplitud superficial.
3. **Demanda verificada de clientes** antes que intuición.
4. **Reversibilidad**: lo que añade riesgo operativo requiere más evidencia.
5. **Coste operativo**: cada servicio nuevo debe justificar su existencia en air-gap.

---

## 5. HITOS DE VALOR (NO FECHAS)

| Hito | Valor para el cliente |
| :--- | :--- |
| `V1` Inventario y postura | "Sé qué tengo y qué está expuesto" |
| `V2` Detección operativa | "Veo lo que pasa y me avisa" |
| `V3` Respuesta asistida | "Respondo rápido y con evidencia" |
| `V4` Autonomía gobernada | "Puedo automatizar sin perder el control" |
| `V5` Cumplimiento demostrable | "Puedo probarlo ante el regulador" |
| `V6` Operación autónoma | "Funciona en mi perímetro, sin nube" |

---

## 6. RIESGOS DE ROADMAP

| Riesgo | Efecto | Mitigación |
| :--- | :--- | :--- |
| Amplitud excesiva en 1.0 | Nada termina | Gates por fase, scope con exclusiones |
| Presión por fechas | Se saltan gates | Exit Gate no negociable |
| Dependencia de un cliente ancla | Requisitos a medida | Configurabilidad, no forks |
| Cambio normativo | Retrabajo | Frameworks versionados |
| Falta de IA en cliente | Percepción de producto incompleto | Mensaje claro: IA asistiva opcional |
