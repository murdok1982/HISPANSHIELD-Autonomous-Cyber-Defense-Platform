# HISPANSHIELD Edge Gateway Agent

Deployable, dependency-light agent that runs at an isolated site, collects
telemetry into a crash-safe SQLite queue and ships HMAC-signed batches to the
HISPANSHIELD core over HTTPS (mTLS-ready).

```bash
python3.12 -m pip install .
export HISPANSHIELD_ENROLL_TOKEN='hs_enroll...'   # one-time token
hispanshield-edge enroll --url https://core.example.com --name site-a
hispanshield-edge run --syslog-port 5514 --ot-spool /srv/ot-observations
hispanshield-edge status
```

* Config (including the shared key) lives in `edge-data/gateway.json`, mode `0600`.
* Queue and status files live next to the config (`edge-data/`).
* The agent never scans the network, never changes policy and never accepts an
  unsigned config bundle.

Full architecture, security properties, systemd hardening and troubleshooting:
[`../docs/edge-gateway.md`](../docs/edge-gateway.md).
