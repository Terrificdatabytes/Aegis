# Aegis · Cloud Security Demo

A runnable, synthetic distributed-cloud security lab based on `prompt.md`. A Flask/Tailwind command center orchestrates five Python agents and shows **Detected → Analysis → Prevented** with real enforcement outcomes.

## Start locally

Requires Python 3.11+ (no cloud accounts or Node.js needed to run).

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run_local.py
```

Open **http://127.0.0.1:5000** and enter the **temporary operator password printed in your terminal**. Five actual agent processes register within about 10 seconds. Click **Run full simulation**. Each launch generates new transport credentials; the local SQLite incident log remains until you reset it. Ctrl+C stops all six processes.

> Local mode binds the dashboard to all interfaces for live preview. Do not expose it as a production service. Agent ports bind only to loopback. No real credentials, customer records, scanning, or exploit payloads are used.

## What is implemented

- Responsive dark dashboard with five-node health, metrics, live 1-second polling, node selection, individual and full-sequence triggers, stage/severity filters, JSON export, policy explanations, reset, and operator login.
- SQLite event/registration/run storage, event validation, event IDs and deduplication, late-event suppression after reset, restart recovery for in-flight runs.
- Per-node HMAC-SHA256 credentials, timestamp checks, nonce replay rejection, operator CSRF protection, login throttling, strict tunnel URL allowlist and disabled outbound redirects.
- Shared Colab agent with automatic Cloudflare quick tunnel startup, registration, 8-second heartbeats, bounded event queue and ordered delivery retries.
- Three deterministic scenarios. The tests verify actual handler status codes, not pre-written success banners.
- Render Blueprint, reusable Colab notebook, setup guide, 30-minute run-of-show, and test suite.

| Scenario | Staged workload | Actual defense | Expected evidence |
|---|---|---|---|
| Data breach | 4 × 30-row exports against synthetic records | Per-actor 80 rows / 10s sliding-window guard | Third and fourth requests return 403; 60 rows released before detection, zero rows on denied requests |
| Identity attack | Fixed wrong synthetic password, then replay a freshly generated one-use token | 3 failures / 10s; 60s account lock; single-use token registry | 429 for locked requests; 403 on token reuse; `step_up_required` response flag |
| Virtualization threat | Exactly one authorized source-agent request to a registered peer's fixed sandbox route | Destination accepts master management identity only | Peer returns 401; signed destination telemetry is required before the master marks the run completed |

A full sequence creates **4 incidents / 12 events**: identity produces separate rate-limit and token-replay incidents. Metrics are counts in the retained log, **not** proof that all conceivable attacks are prevented.

## Important boundaries

**This is a demo, not production security infrastructure.** Virtualization means an application-level stand-in for segmentation, not hypervisor escape detection or a cloud firewall. The public tunnel is transport. The peer request is intentionally reachable but unauthorized. An additional logical `/sandbox/connect` route denies internal-service egress before any network operation; it is tested independently. Step-up is a denied-access flag, not an MFA enrollment/verification service. A source/destination host compromise defeats in-process keys and policies; these agents are assumed self-owned and trusted.

The first two staged workloads use Flask's in-process request client against the same authenticated handlers exposed over HTTP. Master → agent, node → master telemetry, and the peer-boundary scenario use real network requests. No events are preloaded.

## Repository

```text
master-server/     Flask, templates, compiled Tailwind, SQLite store
node-agent/        Shared agent and deterministic policy engine
scenarios/         Fixed synthetic workloads
common/            Stable event contract and HMAC helpers
colab/             Reusable node notebook
tests/            Python policy/API tests and Playwright workflow test
run_local.py       One command → master + five agents
run_scenario.py    Operator CLI (same backend as dashboard)
tools_node_key.py  Derive one node credential locally
tools_post_event.py Manual signed telemetry test
render.yaml        Render service blueprint
SETUP.md           Local, Render, Colab, Cloudflare instructions
RUN_OF_SHOW.md     30-minute presentation and failure fallbacks
ARCHITECTURE.md    APIs, state, trust boundaries, contract
PROGRESS.md        Implementation and validation status
```

## Test and develop

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests
# Optional UI test, against the running local demo:
npm ci
npx playwright install --with-deps chromium
# Set ADMIN_PASSWORD to the password printed by run_local.py, without committing it.
npm run test:ui
# Rebuild checked-in Tailwind utilities after changing classes:
npm run css
```

The browser test resets the local demo, runs all scenarios, checks signed destination evidence, tests filters/navigation/export and mobile overflow, and leaves its synthetic results visible. Set `DEMO_URL` for a different test URL. Do not run it against a demo whose incident log you need to retain.

**Cloud deployment is prepared, not performed.** Follow [SETUP.md](SETUP.md) using your accounts; rehearse on the actual cloud path before presenting. Free hosting/runtime availability is not guaranteed.

## Console design

All presentation uses Tailwind utilities. Run `npm run css` to rebuild `master-server/static/output.css` from `tailwind.input.css`; the source contains only local font-face declarations and Tailwind directives. IBM Plex fonts are self-hosted under `static/fonts/` (license included). No icon library, framework, runtime CSS CDN or custom dashboard stylesheet is needed.

`redesign/before-after.png` compares the original and rebuilt interface. Individual desktop, mobile and login screenshots are included. To repeat the visual checks against the running local server, set `ADMIN_PASSWORD` and run `node tests/redesign.cjs` after the normal UI test.
