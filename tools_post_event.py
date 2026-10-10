"""Manually POST a signed synthetic test event. Run from repository root."""
import getpass
import os
import uuid
import requests
from common.contract import now, NODES
from common.security import encode, signed_headers
master = os.environ.get('MASTER_URL') or input('Your master HTTPS URL: ').rstrip('/')
node = os.environ.get('NODE_NAME', 'node-1')
if node not in NODES or not master.startswith('https://'):
    raise SystemExit('Use node-1..node-5 and your own HTTPS master URL.')
key = os.environ.get('NODE_SECRET') or getpass.getpass('Per-node secret (hidden): ')
event = {'node_id': node, 'event_type': 'data_breach', 'stage': 'detected', 'severity': 'low',
         'timestamp': now(), 'detail': 'Manual synthetic telemetry test; no scenario was executed.',
         'control_applied': 'Manual ingestion test', 'event_id': str(uuid.uuid4())}
body = encode(event)
response = requests.post(master.rstrip('/') + '/api/events', data=body,
                        headers=signed_headers(key, node, 'POST', '/api/events', body),
                        timeout=30, allow_redirects=False)
print(response.status_code, response.text)
response.raise_for_status()
