# GUÍA DE CONECTORES

- **Documento:** `docs/connector-guide.md`
- **Estado:** `APPROVED` v1.0
- **Contrato normativo:** `specs/integrations/connector-contract.md`
- **Protocolos:** `specs/integrations/protocol-registry.md`

---

## 1. CUÁNDO ESCRIBIR UN CONECTOR

Escribe un conector cuando necesites:
- Ingerir eventos de un sistema que no habla syslog/webhook estándar.
- Ejecutar una acción de respuesta en una plataforma con API propia.
- Leer postura/inventario de un proveedor cloud o CMDB.
- Consumir un feed de inteligencia con formato particular.

**No** escribas un conector para lógica de negocio, correlación o enriquecimiento: eso va en servicios.

---

## 2. ESTRUCTURA

```text
backend/app/integrations/connectors/<key>/
├── manifest.json          # contrato declarativo
├── adapter.py             # implementación del Protocol
├── mapping.py             # normalización a OCSF (si ingesta)
├── actions.py             # acciones y compensaciones (si bidireccional)
└── tests/
    ├── test_manifest.py
    ├── test_config.py
    ├── test_mapping.py
    ├── test_actions.py
    └── fixtures/
```

---

## 3. MANIFIESTO MÍNIMO

```json
{
  "key": "acme_firewall",
  "name": "ACME Firewall",
  "version": "1.0.0",
  "kind": "bidirectional",
  "transport": ["https_api"],
  "capabilities": ["events.read", "ip.block", "ip.unblock"],
  "config_schema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["base_url"],
    "properties": {
      "base_url": {"type": "string", "format": "uri"},
      "verify_tls": {"type": "boolean", "default": true}
    }
  },
  "secrets_schema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["api_key"],
    "properties": {"api_key": {"type": "string", "minLength": 16}}
  },
  "rate_limit": {"default_per_minute": 600},
  "health_check": {"type": "active", "path": "/health"},
  "min_core_version": "1.0.0"
}
```

---

## 4. IMPLEMENTACIÓN

```python
class AcmeFirewallConnector:
    key = "acme_firewall"
    capabilities = frozenset({"events.read", "ip.block", "ip.unblock"})

    def __init__(self, config: dict, secrets: dict, http: HttpClient):
        self.config = config
        self._secrets = secrets
        self._http = http

    def validate_config(self, config: dict) -> None:
        validate_json_schema(config, MANIFEST["config_schema"])

    async def health(self) -> HealthResult:
        r = await self._http.get(f"{self.config['base_url']}/health", timeout=10)
        return HealthResult(state="healthy" if r.ok else "degraded", latency_ms=r.elapsed_ms)

    async def test_connection(self) -> TestResult:
        r = await self._http.get(f"{self.config['base_url']}/api/v1/version", timeout=10)
        return TestResult(ok=r.ok, detail=r.text[:200])

    async def pull(self, cursor: str | None, limit: int) -> PullResult:
        r = await self._http.get(
            f"{self.config['base_url']}/api/v1/logs",
            params={"after": cursor, "limit": limit},
            headers={"Authorization": f"Bearer {self._secrets['api_key']}"},
        )
        return PullResult(events=[map_to_ocsf(e) for e in r.json()["items"]], next_cursor=r.json().get("next"))

    async def execute(self, action: str, params: dict, idempotency_key: str) -> ActionResult:
        if action == "ip.block":
            r = await self._http.post(
                f"{self.config['base_url']}/api/v1/blocks",
                json={"ip": params["ip"], "ttl": params.get("duration_minutes", 60)},
                headers={"Idempotency-Key": idempotency_key},
            )
            return ActionResult(ok=r.status in (200, 201, 409), external_id=r.json().get("id"))
        raise ActionNotSupported(action)

    async def verify(self, result: ActionResult) -> VerificationResult:
        r = await self._http.get(f"{self.config['base_url']}/api/v1/blocks/{result.external_id}")
        return VerificationResult(verified=r.json().get("state") == "active")

    async def compensate(self, result: ActionResult) -> CompensationResult:
        r = await self._http.delete(f"{self.config['base_url']}/api/v1/blocks/{result.external_id}")
        return CompensationResult(ok=r.status in (200, 204, 404))
```

---

## 5. MAPEO A OCSF

| Campo OCSF | Origen típico |
| :--- | :--- |
| `class_uid` | Tipo de evento (4001 network activity, 3002 authentication, 1001 file) |
| `activity_id` | Acción (allow/deny/create/delete) |
| `severity_id` | Normalizar a 0..6 |
| `time` | Timestamp UTC (si falta, usar `ingested_at` y marcar) |
| `metadata.product` | Vendor/product/version |
| `actor.user.name` | Usuario |
| `src_endpoint` / `dst_endpoint` | IP y puerto (`INET` válido) |
| `observables` | IPs, dominios, hashes |
| `raw` | Mensaje original (inmutable) |

**Regla:** si un campo no existe, se omite; no se inventa. Se registra `mapping_warnings`.

---

## 6. ERRORES

Mapea cada error del proveedor a un `code` normalizado:

```python
ERROR_MAP = {
    401: "auth_failed",
    403: "forbidden",
    429: "rate_limited",
    500: "upstream_5xx",
    503: "upstream_5xx",
}
```

Un error no mapeado → `invalid_response` con log redactado. Nunca lanzar excepciones crudas al broker.

---

## 7. SEGURIDAD

1. **Nunca** loguear secretos; usar `has_secret` y prefijos.
2. TLS verificado; prohibido `verify=False`.
3. Respetar el guard anti-SSRF (salvo `allow_private_network=true` explícito y auditado).
4. Validar tamaño de respuesta y timeout.
5. No ejecutar comandos de shell.
6. Declarar `idempotent` con honestidad; si no lo es, la acción requerirá A4.

---

## 8. PRUEBAS OBLIGATORIAS

```bash
pytest -q backend/app/integrations/connectors/acme_firewall/tests
```

| Test | Verifica |
| :--- | :--- |
| `test_manifest` | Esquema y capacidades válidas |
| `test_config` | Rechazo de config inválida/extra |
| `test_secret_not_exposed` | No fuga en logs ni respuestas |
| `test_mapping` | Muestra real → OCSF esperado |
| `test_idempotent_push` | Duplicado no duplica |
| `test_error_mapping` | Códigos normalizados |
| `test_health_state` | Secuencia de fallos y recuperación |
| `test_actions` | Ejecutar, verificar, compensar |
| `test_no_ssrf` | Destino interno bloqueado |

---

## 9. REGISTRO Y ACTIVACIÓN

```bash
# El manifiesto se descubre al arrancar; validar
python -m app.integrations.registry --validate acme_firewall

# Registrar en una organización (API)
curl -X POST /api/v1/connectors \
  -H "X-Organization-Id: $ORG" -H "X-CSRF-Token: $CSRF" \
  -d '{"key":"acme_firewall","name":"FW principal","config":{"base_url":"https://fw.example.eu"},"secret":{"api_key":"..."}}'

# Probar
curl -X POST /api/v1/connectors/$ID/test
```

---

## 10. CHECKLIST DE ACEPTACIÓN DEL CONECTOR

- [ ] Manifiesto válido y versionado.
- [ ] Config y secretos separados.
- [ ] Mapeo OCSF probado con muestra real.
- [ ] Errores normalizados.
- [ ] Health check funcional.
- [ ] Idempotencia demostrada.
- [ ] Verificación y compensación (si acción).
- [ ] Sin fuga de secretos.
- [ ] Anti-SSRF respetado.
- [ ] Documentado en esta guía y en la matriz de compatibilidad.
