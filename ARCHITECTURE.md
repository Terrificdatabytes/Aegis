# Architecture and event contract

## Data flow

```text
Browser (session + CSRF) ──HTTP(S)── Master Flask / SQLite
                                    │       ▲
                     HMAC commands  │       │ HMAC registration + telemetry
                                    ▼       │
                                5 node agents
                           (Cloudflare quick tunnels)

Peer rehearsal: master arms destination with a 30-second one-use nonce;
master commands source → ONE fixed peer sandbox request with source identity;
destination rejects 401 and independently reports prevention to master.
```

Cloud mode runs one agent per Colab runtime. Local mode runs five independent agent processes on 6101–6105 and a master on 5000. The UI's role captions are presentation labels; every agent supports every scenario. No browser request ever uses an internal agent address.

## Frozen v1 event shape

Original required fields remain unchanged:

```json
{
  "node_id": "node-1",
  "event_type": "data_breach",
  "stage": "detected",
  "severity": "critical",
  "timestamp": "2026-10-10T10:00:00+00:00",
  "detail": "Synthetic export volume exceeded its sliding-window budget.",
  "control_applied": "Sliding-window volume guard",
  "event_id": "UUID for deduplication",
  "incident_id": "UUID shared across the three stages",
  "run_id": "UUID issued by master"
}
```

- `event_type`: `data_breach | identity_attack | virtualization_threat | heartbeat`.
- `stage`: `detected | analyzing | prevented`. A heartbeat uses `analyzing` by convention and does not enter the incident feed.
- `severity`: `low | medium | high | critical`.
- `timestamp`: timezone-aware ISO8601. Master also records `received_at` and monotonically increasing database `id`.
- `event_id`, `incident_id`, `run_id` are optional additive fields for manual compatibility; the agent supplies them for incident telemetry. Manual ingestion should omit `run_id` or use `manual`; unknown automated run IDs are acknowledged but dropped to prevent stale retries repopulating a reset log.
- `source_node` is an optional node ID for peer evidence. `node_id` always means the **reporting** node and must match the HMAC sender. Destination prevention therefore reports the destination `node_id` plus the actual `source_node`.
- Event detail/control text: 1–1000 characters. IDs: max 100. Master JSON payload limit: 16 KiB.
- UI shows the latest 300 ingested events sorted by origin timestamp (newest first); export includes the latest 300. Retained metrics scan at most 5,000 events. The store is not an audit archive. Keep clocks synchronized; origin timestamps are not trusted sequencing evidence across unsynchronized hosts.

## Endpoints

| Method / path | Authority | Function |
|---|---|---|
| Master `GET /health` | Public | Liveness |
| Master `GET /`, `POST /login` | Operator | Login / dashboard |
| Master `GET /api/state` | Session | Nodes, events, metrics, runs |
| Master `POST /api/run` | Session + CSRF | `{node_id, scenario}`; returns 202 and run ID |
| Master `POST /api/reset` | Session + CSRF | Reset connected agents, then clear log if all respond |
| Master `POST /api/logout` | Session + CSRF | End session |
| Master `POST /api/nodes/register` | Node HMAC | Register/refresh fixed node identity and tunnel URL |
| Master `POST /api/events` | Node HMAC | Validate, deduplicate, ingest; heartbeat refreshes liveness |
| Agent `GET /health` | Public | Synthetic-only node identity/liveness |
| Agent `POST /control/run`, `/control/reset` | Master HMAC | Scenario / policy reset |
| Agent `POST /control/arm-peer` | Master HMAC | One authorized destination-boundary rehearsal |
| Agent `POST /sandbox/data` | Master HMAC | Synthetic records / volume protection |
| Agent `POST /sandbox/auth` | Master HMAC | Fixed synthetic auth / lockout |
| Agent `POST /sandbox/token`, `/sandbox/redeem` | Master HMAC | Short-lived one-use tokens |
| Agent `POST /sandbox/connect` | Master HMAC | Fixed logical internal port; always deny before outbound I/O |
| Agent `POST /sandbox/peer-probe` | Armed nonce, peer identity | Reject unauthorized peer; emit once only if explicitly armed |

Probe tokens are non-secret authorization capabilities restricted to one run, one source, one destination, one use and 30 seconds. Unknown/unarmed requests return 401 without generating a success incident. No user-supplied arbitrary hostname, URL, password list or port is accepted by scenario controls.

## Transport authentication

Each node receives only its derived credential: `HMAC-SHA256(MASTER_SECRET, "cloud-demo:" + node_id)`. The root remains on the master. Headers are `X-Demo-Sender`, `X-Demo-Time`, `X-Demo-Nonce`, and `X-Demo-Signature`. Sign the newline-delimited sender, uppercase method, URL path, integer Unix time, random nonce, SHA256(raw body), using the per-node key. `common/security.py` is the canonical encoder/signer.

A 60-second clock window and 120-second nonce cache reject ordinary replay. Retries use a **new transport nonce but the same event ID**. HMAC does not encrypt traffic: cloud mode requires HTTPS. A compromised node can forge its own events and local master operations using its own symmetric key, but does not receive the keys for other nodes. This is not remote attestation.

Cloud URL registration accepts only HTTPS `*.trycloudflare.com`, standard TLS port, no credentials/path/query/fragment. Local mode accepts only each node's exact loopback port. Redirects are disabled. Named tunnels/custom domains require a deliberate explicit allowlist code change; do not simply remove validation.

## Concurrency, recovery and demo limitations

- One Gunicorn worker with 12 threads. In-process nonce caches and run locks **are not multi-worker safe**; do not increase worker count without a shared nonce/lock store.
- SQLite protected by a reentrant process lock. Run IDs are stored before commands are sent. Source and peer target are both reserved during a peer run. UI locks controls while running.
- Detector state is per node and resets at each scenario start. A sequence is repeatable, not a model of all attacks persisting simultaneously.
- 8-second heartbeat/re-registration; offline threshold 25 seconds. “Online” means recent outbound heartbeat, not a proven working inbound tunnel. Failed commands surface as failed runs.
- Node queue is memory-only, ordered, bounded to 2,000 events; retries have exponential backoff up to 16 seconds. Queue saturation/process loss can lose telemetry. The initial handoff queue is memory-only. No durability promise.
- Peer completion requires independent signed destination evidence; transport failures/timeouts do **not** count as blocked attacks. Other scenarios verify handler responses; queued telemetry can arrive slightly after run completion.
- Master restart marks interrupted runs failed/unknown, not completed. Agents re-register. Reset may partially reset reachable nodes if another is unavailable; in that case the master keeps the log and returns an error. Retry after reconnection.
- Render free service storage is ephemeral. Export before restarts/deployment. SQLite persistence on paid disks/shared databases is future work.
- Agent uses Werkzeug for the short demo session only. No persistent Colab hosting, MFA product, OS firewall, production SIEM, distributed clock authority, or hypervisor instrumentation is claimed.
