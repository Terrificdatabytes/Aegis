"""Launch an actual master and five agent processes. Secrets are ephemeral."""
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path
from common.security import node_key

ROOT = Path(__file__).resolve().parent

def main():
    master_secret = secrets.token_hex(32)
    password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
    port = int(os.environ.get('PORT', '5000'))
    env = {**os.environ, 'MASTER_SECRET': master_secret, 'ADMIN_PASSWORD': password,
           'SESSION_SECRET': secrets.token_hex(32), 'LOCAL_DEMO': '1', 'COOKIE_SECURE': '0',
           'PORT': str(port), 'DB_PATH': str(ROOT / 'local.sqlite3'), 'PYTHONUNBUFFERED': '1'}
    children = []
    def stop(*_):
        for process in children:
            if process.poll() is None: process.terminate()
        for process in children:
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        children.append(subprocess.Popen([sys.executable, 'app.py'], cwd=ROOT / 'master-server', env=env))
        for i in range(1, 6):
            node = f'node-{i}'
            node_env = {**env, 'MASTER_URL': f'http://127.0.0.1:{port}', 'NODE_NAME': node,
                        'NODE_SECRET': node_key(master_secret, node), 'AGENT_PORT': str(6100 + i),
                        'PUBLIC_URL': f'http://127.0.0.1:{6100 + i}'}
            for secret in ['MASTER_SECRET', 'ADMIN_PASSWORD', 'SESSION_SECRET']:
                node_env.pop(secret, None)
            children.append(subprocess.Popen([sys.executable, 'agent.py'], cwd=ROOT / 'node-agent', env=node_env))
        print(f'\nDashboard: http://127.0.0.1:{port}\nOperator password: {password}\nFive agents start automatically. Ctrl+C stops all.\n', flush=True)
        while all(p.poll() is None for p in children): time.sleep(1)
        raise RuntimeError('A demo process exited; check logs above.')
    finally: stop()

if __name__ == '__main__': main()
