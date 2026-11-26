# HISPANSHIELD Edge Gateway Agent

The edge agent (`edge/hispanshield_edge`) is the only HISPANSHIELD component that
runs inside a customer or OT site. It is a store-and-forward telemetry shipper:
it never makes policy decisions, never scans a network and never holds platform
credentials beyond its own per-gateway HMAC key.

```
 local sources                    gateway host                         core
 ─────────────                    ────────────                         ────
 JSON/JSONL spool ─┐
 UDP syslog ───────┼─► collectors ─► SQLite WAL queue ─► EdgeClient ─► /api/v1/edge/...
 OT read-only spool┘   (passive)      (durable, ordered)    (HMAC+HTTPS)   FastAPI
```

## 1. Package layout

| Module | Responsibility |
| :--- | :--- |
| `config.py` | `GatewayConfig` dataclass, stable machine fingerprint, allow-listed runtime settings, atomic `0600` persistence, redacted `describe()` |
| `queue.py` | SQLite WAL queue: monotonic `sequence`, pending/sent state, cursor, attempts, loud trim |
| `client.py` | Signed HTTPS transport, enrollment, heartbeat, batch ingest, signed config bundle verification, error taxonomy |
| `collectors.py` | Atomic JSON/JSONL spool, passive UDP syslog (RFC3164/5424), read-only OT spool |
| `agent.py` | Collection/shipping loop, backoff, clock-skew warning, status file, structured JSON logs, signals |
| `cli.py`, `__main__.py` | `enroll`, `run`, `status`, `flush`, `queue` |

## 2. Lifecycle

1. **Enrollment token.** An operator with `edge:write` creates a single-use,
   HMAC-signed token valid for 15 minutes (`POST /api/v1/edge/gateways/enroll-token`).
   The token is delivered out of band and supplied through
   `HISPANSHIELD_ENROLL_TOKEN` (preferred) or an interactive prompt.
2. **Register.** `POST /api/v1/edge/gateways/register` with
   `{enrollment_token, fingerprint, name, version, certificate_serial?}`. The
   gateway id is generated server-side; the shared key is returned **once**.
3. **Verify the enrollment bundle.** The response bundle is HMAC-SHA256 over
   canonical JSON (`sort_keys=True, separators=(",", ":")`). A missing, malformed
   or mis-bound bundle aborts enrollment; nothing is persisted.
4. **Persist.** Config is written atomically with mode `0600` in a `0700`
   directory. The shared key never enters logs, status files or CLI output.
5. **Heartbeat.** Signed `POST /heartbeat` reports version, queue stats and
   status; the response provides `server_time`, the server cursor, the next
   heartbeat interval and a config version.
6. **Ship.** Oldest pending envelope first, one at a time. Sequences are
   allocated at enqueue time, in the same SQLite transaction as the payload, so
   a sequence can never be reused for new data.
7. **Refresh (best effort).** Every 6 hours the agent attempts a signed
   `GET /config-bundle`; unsigned or invalid signatures are rejected and the
   last verified configuration is retained.

## 3. Wire protocol (must match `backend/app/modules/edge`)

| Call | Auth | Notes |
| :--- | :--- | :--- |
| `POST /api/v1/edge/gateways/register` | enrollment token | public, rate-limited server-side |
| `POST /api/v1/edge/gateways/{id}/heartbeat` | HMAC | idempotent, retried with jitter |
| `POST /api/v1/edge/gateways/{id}/events` | HMAC | 1..500 events, `kind ∈ {network, ot, iot, json}` |
| `GET /api/v1/edge/gateways/{id}/config-bundle` | HMAC attempt | see limitation below |

Authenticated headers:

```
X-Gateway-Fingerprint: <stable fingerprint>
X-Gateway-Timestamp:   <epoch seconds>
X-Gateway-Signature:   <hex HMAC-SHA256>
```

Signed message (exact bytes, `PATH` exactly as sent, including `/api/v1/...`):

```
{timestamp}\n{METHOD}\n{PATH}\n{sha256_hex(body)}
```

The backend rejects timestamps outside ±300 s. The agent warns (once per
crossing) when `server_time` differs from the local clock by more than 120 s so
operators can fix time sync before signatures start failing.

Event envelope:

```json
{"sequence": 42, "kind": "json", "events": [{"...": "..."}], "batch_id": "optional"}
```

Responses: `{accepted, sequence, processed, duplicates, cursor}`. The backend
rejects `sequence <= cursor` as replay (HTTP 409) after validating the signature.

**Config bundle limitation (current control plane):** the backend route
`GET /gateways/{id}/config-bundle` is declared with the tenant permission
`edge:read`, so a gateway credential receives `401`. The agent sends a correctly
signed GET anyway, treats `401/403/404` as *remote config unavailable* (not
fatal) and keeps the verified enrollment bundle. Remote reconfiguration becomes
active automatically if the core later exposes that route to gateway
credentials; no agent change is required.

### Error handling

| Condition | Agent behavior |
| :--- | :--- |
| `401/403` on heartbeat/events | **Fatal**: stop, exit code `3`, re-enrollment required |
| `404` on heartbeat/events (unknown or revoked gateway) | **Fatal**: stop, exit code `3`, investigate the gateway record |
| `401/403/404` on config bundle | Non-fatal: keep last verified config |
| `409` replay on events | Mark envelope delivered, continue; backend already has it |
| `409` revoked on config bundle | Fatal: stop, exit code `3` |
| `409` duplicate fingerprint on register | Not retried; operator must investigate |
| `429` / `5xx` | Backoff with jitter; ingestion continues offline |
| Connection error on event POST | Exactly one retry (backend replay/dedupe makes it safe) |
| Read timeout on event POST | **No retry** at client level; the queue retries later after a full cycle, avoiding a blind duplicate race |
| `400/413/422` on events | Mark failed, keep the envelope at the head, log loudly; never silently drop |
| Invalid bundle signature | Reject the bundle; fatal only during enrollment, otherwise keep old config and log critical |

## 4. Durable queue and offline behavior

* SQLite in WAL mode, `synchronous=FULL`, `busy_timeout=10s`, one connection per
  process/thread, `BEGIN IMMEDIATE` for sequence allocation.
* `enqueue()` allocates `sequence` and inserts the payload in one transaction.
  Nothing is held only in memory; a power cut cannot lose an assigned sequence.
* The agent marks an envelope sent **after** the `200`, persisting the server
  cursor in the same transaction. A crash in between causes a resend, the
  backend answers `409 replay`, and the agent marks it delivered. That is
  at-least-once delivery with server-side idempotency.
* While offline, collectors keep writing to SQLite. Network calls run with
  bounded timeouts after collection, so ingestion is never blocked by the core.
* `buffer_max_events` (default 50 000) is a last-resort disk guard. When the
  backlog exceeds it, the **oldest unsent** envelopes are deleted and the drop is
  logged at ERROR with the affected sequences. No silent trimming.
* Size the disk as `events × average_event_bytes × safety_factor`. A 256 KB cap
  per object is enforced by the spool collectors.

## 5. Configuration allow-list

Only these keys from a verified server bundle are applied; unknown keys
(including `_internal_*`) are ignored and reported. Server config can never widen
local capabilities.

| Key | Type | Default | Bounds |
| :--- | :--- | :--- | :--- |
| `buffer_max_events` | int | 50000 | 100 .. 1 000 000 |
| `batch_size` | int | 200 | 1 .. 500 (envelope limit) |
| `flush_interval_seconds` | int | 30 | 5 .. 3600 |
| `heartbeat_interval_seconds` | int | 60 | 15 .. 3600 |
| `log_level` | enum | info | debug/info/warning/error |
| `collectors` | list[str] | syslog, network, ot, iot | 20 identifiers, alphanumeric |
| `store_forward` | bool | true | |
| `allow_remote_config` | bool | true | |
| `tags` | list[str] | [] | 20 short identifiers |

`collectors` is advisory documentation of enabled sources; local process flags
decide which listeners actually open. A compromised or malicious core cannot
make the agent open a new port.

## 6. Security properties

* TLS verification is **always on**. `--ca-bundle` adds a private CA; `--client-cert`
  / `--client-key` enable mTLS. `http://` is refused unless `--insecure` was
  explicitly used at enrollment (stored in the config; intended for labs only).
* Redirects are not followed; environment proxies are ignored (`trust_env=False`)
  so a stray `HTTPS_PROXY` cannot intercept telemetry.
* The shared key is stored only in `gateway.json` (`0600`), never logged, never
  printed by the CLI, never written to the status file.
* Config bundles are verified with constant-time comparison over canonical JSON.
  An unsigned or tampered bundle is rejected.
* Enrollment tokens are single-use, short-lived and never persisted by the agent.
* Syslog is passive UDP. The agent never sends packets to OT/IT devices and never
  performs discovery, scanning or credential use against controllers.
* Queue, spool and status live under a `0700` data directory; the SQLite file is
  `0600`. JSON logs go to stdout/stderr for journald.

## 7. Deployment

### Install

```bash
python3.12 -m venv /opt/hispanshield-edge/venv
/opt/hispanshield-edge/venv/bin/pip install /path/to/edge
install -d -m 0700 -o hispanshield-edge -g hispanshield-edge /var/lib/hispanshield-edge
install -d -m 0750 -o root -g hispanshield-edge /etc/hispanshield-edge
install -d -m 0750 -o hispanshield-edge -g hispanshield-edge \
  /var/spool/hispanshield-edge/spool
install -d -m 0550 -o root -g hispanshield-edge /var/spool/hispanshield-edge/ot
```

Enroll once, as the service user, with the token supplied by the platform:

```bash
sudo -u hispanshield-edge env HISPANSHIELD_ENROLL_TOKEN='hs_enroll...' \
  /opt/hispanshield-edge/venv/bin/hispanshield-edge enroll \
  --url https://core.example.com --name site-a \
  --config /etc/hispanshield-edge/gateway.json \
  --ca-bundle /etc/hispanshield-edge/core-ca.pem
```

For mTLS add `--client-cert /etc/hispanshield-edge/gateway.crt
--client-key /etc/hispanshield-edge/gateway.key`.

Install `edge/systemd/hispanshield-edge.service.example` as
`/etc/systemd/system/hispanshield-edge.service`, create
`/etc/hispanshield-edge/agent.env` (see the unit), then:

```bash
systemctl daemon-reload
systemctl enable --now hispanshield-edge
journalctl -u hispanshield-edge -f
```

The example unit uses `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`,
`ProtectHome`, an empty capability bounding set, `RestrictAddressFamilies`,
`SystemCallFilter=@system-service`, `UMask=0077`, `MemoryMax=256M` and explicit
read/write paths. Adjust `ReadWritePaths` if spool directories differ.

### Read-only OT spool

The site's OT broker/gateway writes observations; HISPANSHIELD only reads them.

```bash
# on the OT side (not this agent): append JSONL observations, one object/line
cat >> /var/spool/hispanshield-edge/ot/observations.jsonl <<'EOF'
{"site":"plant-1","asset":"plc-7","metric":"pressure","value":4.2,"ts":"2026-11-26T10:00:00Z"}
EOF
chmod 0550 /var/spool/hispanshield-edge/ot/observations.jsonl

/opt/hispanshield-edge/venv/bin/hispanshield-edge run \
  --config /etc/hispanshield-edge/gateway.json \
  --data-dir /var/lib/hispanshield-edge \
  --spool-dir /var/spool/hispanshield-edge/spool \
  --ot-spool /var/spool/hispanshield-edge/ot
```

Offsets are kept in the data directory (`ot-offsets.json`, `0600`), not in the
OT mount, so the OT spool can be genuinely read-only. Truncation/rotation is
detected by size and inode and handled by restarting at offset 0.

### Syslog

`--syslog-port 5514` opens a **UDP listener**. Keep it on loopback
(`--syslog-bind 127.0.0.1`) or inside a WireGuard/management VLAN; never expose
it to the internet. Datagrams above 64 KB are dropped and counted.

## 8. Operations

```bash
# human status: enrollment, queue depth, cursor, agent state
hispanshield-edge status --config /etc/hispanshield-edge/gateway.json

# raw queue inspection (oldest first, attempts and last error)
hispanshield-edge queue --config ... --json

# ship now without starting collectors
hispanshield-edge flush --config ... --max-batches 50

# destructive: remove one blocked envelope after investigation
hispanshield-edge queue --config ... --drop 123 --yes
```

Exit codes: `0` OK, `1` unexpected, `2` configuration/usage/collector failure,
`3` fatal authentication (re-enroll), `4` core unreachable or shipping deferred,
`5` rejected config bundle.

### Key rotation

The control plane's rotate-key endpoint returns the new key once to the operator.
The agent has no unauthenticated way to fetch it: update `shared_key` in
`gateway.json` (`0600`) through your secret-management path and restart, or
re-enroll with a fresh token if the gateway record can be replaced. A stale key
produces `401` and exit code `3`, never silent data loss.

## 9. What the gateway can never do

* Change detection, autonomy, policy or permissions.
* Widen its own allow-list or enable collectors the operator did not start.
* Scan, probe or write to OT/IT devices (no active scanning, no controller writes).
* Accept an unsigned or tampered configuration bundle.
* Disable TLS verification, follow redirects or use an environment proxy.
* Leak its shared key or enrollment token into logs, status or CLI output.
* Drop data silently: trimming and permanent rejections are logged at ERROR and
  the affected sequence is visible in `queue`/`status`.

## 10. Troubleshooting

| Symptom | Likely cause | Action |
| :--- | :--- | :--- |
| `401 Gateway signature is invalid or expired` | clock skew >300 s or rotated key | check `status` for `server_time_skew_seconds`; fix NTP; verify key; re-enroll if rotated |
| `clock.skew` warnings but shipping works | skew 120–300 s | fix the clock before it exceeds 300 s |
| `409 replay` repeatedly on new data | sequence reuse (should be impossible) | verify only one agent runs per queue file; never delete/restore `edge-queue.sqlite3` without re-enrolling (sequence reset looks like replay to the core) |
| `5 rejected config bundle` | tampered/unsigned bundle | check core integrity and CA; agent refuses unsafe config |
| `TLS handshake failed` | wrong CA, hostname or missing client cert | pass `--ca-bundle`/mTLS files; confirm SAN |
| `queue` shows growing `oldest_age_s` | core unreachable or 5xx | check connectivity; data is retained and will flush |
| `blocking_error` with 400/413/422 | malformed event or oversized envelope | inspect the envelope; fix producer; `queue --drop --yes` only after export |
| `buffer_max_events` ERROR log | disk budget exhausted | increase disk or reduce collection; trimmed sequences are logged |
| `bind ... Address already in use` | another syslog listener | change `--syslog-port` or stop the conflicting process |
| Collectors not reading spool | file extension not `.json`/`.jsonl`, hidden file, or in `archive/` | rename into the spool root; check `failed/*.error` |

## 11. Tests

```bash
cd edge
python3.12 -m pip install -e .
python3.12 -m pytest tests -q
ruff format . && ruff check .
```

The suite covers signature vectors computed independently, config atomicity and
redaction, queue durability/ordering/trim/concurrency across two connections,
enrollment, replay, 401/503 handling, invalid bundles, allow-list enforcement,
spool/syslog/OT collectors (including a no-socket assertion for OT), CLI exit
codes and secret-free logs/status files.
