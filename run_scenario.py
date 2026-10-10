"""Operator CLI for the same safe scenario commands used by the dashboard."""
import argparse
import getpass
import os
import re
import time
import requests
from common.contract import NODES, SCENARIOS
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('scenario', choices=SCENARIOS)
p.add_argument('--node', choices=NODES, default='node-1')
p.add_argument('--master', default=os.environ.get('MASTER_URL', 'http://127.0.0.1:5000'))
a = p.parse_args()
if not (a.master.startswith('https://') or a.master.startswith('http://127.0.0.1:')):
    raise SystemExit('Use HTTPS or local loopback.')
password = os.environ.get('ADMIN_PASSWORD') or getpass.getpass('Operator password: ')
s = requests.Session()
url = a.master.rstrip('/')
r = s.post(url + '/login', data={'password': password}, timeout=30)
r.raise_for_status()
match = re.search(r'name="csrf-token" content="([^"]+)"', r.text)
if not match: raise SystemExit('Sign-in did not return an operator session.')
r = s.post(url + '/api/run', json={'node_id': a.node, 'scenario': a.scenario}, headers={'X-CSRF-Token': match[1]}, timeout=40)
r.raise_for_status()
run_id = r.json()['run_id']
for _ in range(90):
    response = s.get(url + '/api/state', timeout=30)
    response.raise_for_status()
    run = next((r for r in response.json()['runs'] if r['run_id'] == run_id), None)
    if run and run['status'] != 'running':
        print(run)
        raise SystemExit(0 if run['status'] == 'completed' else 1)
    time.sleep(1)
raise SystemExit('Timed out. Inspect the dashboard before retrying.')
