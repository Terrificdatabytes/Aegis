# Setup: local rehearsal → Render → Colab + Cloudflare

## 1. Local rehearsal (recommended first)

From the extracted `cloud-security-demo` directory:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q tests
python run_local.py
```

On Windows use `.venv\Scripts\activate`. Open `http://127.0.0.1:5000`, enter the temporary terminal password, and wait for five online cards. Run a scenario or the full sequence. No tunnel or external account is needed. To use another master port, set `PORT` before launch. Node ports 6101–6105 must be free. Stop with Ctrl+C.

The `.env.example` is a **template only**. Python does not automatically load it. Supply values in the shell/service environment, or use a trusted environment loader locally. Never commit filled credentials. Local mode generates ephemeral secrets by default; `ADMIN_PASSWORD` may be supplied in the environment for repeatable UI tests. Use at least 12 characters.

## 2. Deploy the master on Render

This build includes deployment configuration; it has **not** been deployed to your account. Free-tier terms and availability can change. Review the provider documentation linked below before the live session.

1. Put this directory at the root of your own repository. Exclude `.env`, SQLite files, logs and `node_modules` (already covered by `.gitignore`). Check for secrets before pushing.
2. In Render, create a Web Service from that repository. Alternatively, create a Blueprint using `render.yaml`.
3. Select Python runtime and the free plan if available. Leave the root directory at the repository root; the agent/common/scenario modules are required by imports.
4. Build command:
   ```bash
   pip install -r requirements.txt
   ```
5. Start command:
   ```bash
   cd master-server && gunicorn 'app:create_app()' --bind 0.0.0.0:$PORT --workers 1 --threads 12 --timeout 120 --access-logfile -
   ```
6. Health check path: `/health`.
7. Set these environment variables in Render's environment UI:

   | Variable | Value |
   |---|---|
   | `MASTER_SECRET` | Random 32+ characters (recommended: 64 hex characters) |
   | `SESSION_SECRET` | Independent random 32+ characters |
   | `ADMIN_PASSWORD` | Unique 12+ character operator password |
   | `COOKIE_SECURE` | `1` |
   | `LOCAL_DEMO` | Leave unset |
   | `PYTHON_VERSION` | `3.11.11` (as in the Blueprint; use a supported 3.11+ version if needed) |

   The Blueprint generates the first two secrets; set the admin password yourself. You can generate independent secrets locally with `python -c "import secrets; print(secrets.token_hex(32))"`. Do not publish or paste them into a notebook cell.
8. Deploy, then open the assigned HTTPS URL. `/health` should return `{"status":"ok","mode":"cloud"}`. Sign in with your operator password.
9. Keep **one worker**. SQLite, nonce caches and run reservations are intentionally single-process for this small demo.
10. Test a signed manual event using `python tools_post_event.py` after deriving a node key below. It should appear as a **low severity manual test**, not as a successful attack prevention. Reset afterward.

**Free service caveats:** expect cold starts and ephemeral disk; no durable log is promised. Open and verify the service shortly before presenting, within provider rules. Do not add artificial keepalive traffic outside the live demo to evade platform limitations. Export useful events before stopping/redeploying.

## 3. Derive credentials for five nodes

Keep `MASTER_SECRET` on your trusted computer and Render only. Run locally, once per node:

```bash
python tools_node_key.py node-1
python tools_node_key.py node-2
python tools_node_key.py node-3
python tools_node_key.py node-4
python tools_node_key.py node-5
```

Enter the Render root secret at the hidden prompt. Each command prints **one different node credential**. Store them privately. Use the matching `NODE_NAME`; a node-1 key cannot register as node-2. Do not distribute `MASTER_SECRET` to Colab. To rotate all nodes, change the root, derive new keys, and restart agents. Rotating only `SESSION_SECRET` logs out operators.

## 4. Open five Colab notebooks

Upload/open `colab/node_template.ipynb` in Colab. Make five copies, with `NODE_NAME` set to `node-1` through `node-5`, one per runtime. Colab runtime quotas vary; if five simultaneous runtimes are unavailable, use fewer agents or local five-process mode. Do not evade service quotas using artificial activity or account workarounds.

### Notebook cell 1 — obtain the project

Upload **the provided project ZIP** and extract it. The included notebook automates this. Alternatively, clone your own repository using its actual URL. No repository URL is preconfigured.

```python
from google.colab import files
import io, zipfile
uploaded = files.upload()  # choose cloud-security-demo.zip
archive = next(iter(uploaded.values()))
with zipfile.ZipFile(io.BytesIO(archive)) as z:
    z.extractall('/content')  # only use the trusted project ZIP you created/downloaded
%cd /content/cloud-security-demo
!pip -q install -r node-agent/requirements.txt
```

### Notebook cell 2 — install cloudflared

On the ordinary x86-64 Linux Colab runtime:

```bash
!wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -O /tmp/cloudflared.deb
!dpkg -i /tmp/cloudflared.deb
!cloudflared --version
```

Use the matching official package for a different architecture. For reproducible presentations, pin and verify an official release rather than relying on `latest`. No Cloudflare account or tunnel token is needed for an ephemeral quick tunnel. Do not store tunnel tokens in source if adapting this to named tunnels.

### Notebook cell 3 — parameterize and launch

Use hidden inputs or Colab Secrets (key icon) rather than hardcoded credentials. The template uses `getpass` so the key is not printed into saved notebook output.

```python
import getpass, os, subprocess, sys
NODE_NAME = 'node-1'  # change in each notebook
MASTER_URL = input('Your Render HTTPS URL: ').strip().rstrip('/')
NODE_SECRET = getpass.getpass('Matching per-node credential: ')
env = {**os.environ, 'NODE_NAME': NODE_NAME, 'MASTER_URL': MASTER_URL,
       'NODE_SECRET': NODE_SECRET, 'AGENT_PORT': '6000', 'PYTHONUNBUFFERED': '1'}
env.pop('LOCAL_DEMO', None)
env.pop('PUBLIC_URL', None)
log = open('/content/agent.log', 'w')
agent_process = subprocess.Popen([sys.executable, 'node-agent/agent.py'], env=env,
                                 stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
print('Started node agent, PID', agent_process.pid)
```

The agent starts its loopback server, then runs:

```text
cloudflared tunnel --url http://127.0.0.1:6000 --no-autoupdate
```

It discovers the random `https://...trycloudflare.com` URL automatically, registers with Render and reports heartbeat every eight seconds. Repeat in all five notebooks. Cloud mode only allows quick-tunnel hostnames; custom domains require an explicit allowlist implementation. Quick tunnels may conflict with an existing cloudflared config file; use a fresh runtime or follow the official troubleshooting guide.

### Notebook cell 4 — verify

```python
print('Running:', agent_process.poll() is None)
print(open('/content/agent.log').read()[-4000:])
```

Open the dashboard. Expect five online cards after registration, usually within 10–30 seconds once the master is warm. A green card means recent telemetry; verify at least one actual scenario to test the reverse tunnel path. No real VM provisioning is involved.

### Notebook cell 5 — stop after the demo

```python
import os, signal
if agent_process.poll() is None:
    os.killpg(agent_process.pid, signal.SIGTERM)
log.close()
```

Then disconnect/delete the Colab runtime. Do not use these notebooks as unattended services. Restarting an agent generates a new quick-tunnel URL, which automatically replaces the old registration.

## 5. Cloud acceptance checklist

- [ ] All five node IDs online; distinct matching secrets, no shared root secret in notebooks.
- [ ] Source node dropdown changes the reporting node.
- [ ] Breach: 403 after 60 synthetic exported rows, critical incident visible.
- [ ] Identity: rate-limit incident plus token-replay incident, both prevented.
- [ ] Peer: destination differs from source; source sends one fixed request; destination produces signed 401 prevention evidence. At least two online nodes required.
- [ ] Full sequence completes with 4 detections, 4 preventions and 12 events from a clean reset.
- [ ] Stop one agent: card goes offline after about 25 seconds. Restart: re-registers.
- [ ] Export JSON and confirm source/reporting node, timestamps, incident IDs and control names.
- [ ] Reset clears telemetry and allows a repeat. Rehearse the fallback in `RUN_OF_SHOW.md`.

## Troubleshooting

| Symptom | Action |
|---|---|
| Startup refuses credentials | Master secret >=32 characters, admin password >=12; set actual env vars (not just `.env.example`) |
| 401 registration | Match NODE_NAME to derived key; ensure clocks within 60 seconds; root secret must match Render |
| 400 registration | HTTPS quick tunnel only in cloud mode; never send localhost or a custom domain without implementing an explicit allowlist |
| Agents online, scenario fails | Outbound heartbeat works but inbound tunnel may not. Inspect agent/cloudflared logs; run health/one scenario; restart affected agent |
| No tunnel URL in 60s | Verify cloudflared binary and network; inspect conflicting configuration; restart the runtime or use local mode |
| Render wakes slowly | Allow cold-start time before presenting; do not interpret a timeout as blocked traffic |
| Peer run fails | Need two reachable online nodes, no conflicting reserved run, and independent destination event within 15s. Failure is intentionally not counted as prevention |
| New events arrive after reset | Known run telemetry is dropped after reset; manual telemetry is not tied to runs. Stop manual posting during resets |
| Login loop in embedded preview | Open preview in a new browser tab if cross-site cookie policy blocks sessions. On Render HTTPS use `COOKIE_SECURE=1` |
| Log disappeared | Render free filesystem/runtime restarted. Use the exported JSON; do not claim durable audit storage |
| Cannot run five Colabs | Respect quota; present local five-agent mode or explain reduced node count |

## Provider reference links

These links are supplied for verification; the cloud path was not exercised in this workspace.

- Render Flask guide: https://render.com/docs/deploy-flask
- Render free services: https://render.com/docs/free
- Render Blueprint specification: https://render.com/docs/blueprint-spec
- Cloudflare quick tunnels: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
- Official cloudflared releases: https://github.com/cloudflare/cloudflared/releases
- Colab usage limitations: https://research.google.com/colaboratory/faq.html
