import collections
import importlib
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from flask import Flask, request, jsonify
from common.contract import NODES, SCENARIOS, now
from common.security import Verifier, signed_headers, encode, valid_agent_url


class Detector:
    """Small deterministic policy engine, state isolated to each node."""
    def __init__(self, emit, clock=time.monotonic):
        self.emit, self.clock = emit, clock
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.volumes = collections.defaultdict(collections.deque)
            self.blocked = set()
            self.failures = collections.defaultdict(collections.deque)
            self.locked_until = {}
            self.tokens = {}
            self.reported = set()

    def incident(self, kind, severity, detail, control, analysis, run_id):
        incident_id = str(uuid.uuid4())
        for stage, text in [('detected', detail), ('analyzing', analysis), ('prevented', 'Request denied. ' + control + ' is enforced.')]:
            self.emit({'event_type': kind, 'stage': stage, 'severity': severity, 'timestamp': now(),
                       'detail': text, 'control_applied': control, 'incident_id': incident_id, 'run_id': run_id})
            # A short presentation delay, not a delayed enforcement decision.
            if os.environ.get('EVENT_STAGE_DELAY', '0.35') != '0': time.sleep(float(os.environ.get('EVENT_STAGE_DELAY', '0.35')))

    def data(self, actor, rows, run_id):
        with self.lock:
            if actor in self.blocked: return {'error': 'Actor blocked', 'released_rows': 0}, 403
            current = self.clock()
            window = self.volumes[actor]
            while window and current - window[0][0] >= 10: window.popleft()
            total = sum(r for _, r in window)
            if total + rows > 80:
                self.blocked.add(actor)
                self.incident('data_breach', 'critical', f'Abnormal synthetic export: {total + rows} requested rows in 10 seconds.',
                              'Sliding-window volume guard', f'Actor {actor}; limit 80 rows / 10s. This request would exceed the budget.', run_id)
                return {'error': 'Volume limit exceeded; actor blocked', 'released_rows': 0}, 403
            window.append((current, rows))
            return {'rows': [{'id': i, 'classification': 'SYNTHETIC', 'value': f'dummy-record-{i}'} for i in range(rows)], 'released_rows': rows}, 200

    def auth(self, account, password, run_id):
        with self.lock:
            current = self.clock()
            if self.locked_until.get(account, 0) > current:
                return {'error': 'Account locked for 60 seconds', 'step_up_required': True}, 429
            window = self.failures[account]
            while window and current-window[0] >= 10: window.popleft()
            if len(window) >= 3:
                self.locked_until[account] = current + 60
                self.incident('identity_attack', 'high', 'Rapid failed authentication pattern detected for sandbox demo-user.',
                              'Account rate limit + step-up gate', f'{len(window)} failures in 10s; anomaly score 90/100 (fixed rule-based score). Lock 60s; do not issue a session.', run_id)
                return {'error': 'Rate limit enforced', 'step_up_required': True, 'anomaly_score': 90}, 429
            # This is deliberately a sandbox endpoint; no real account exists.
            if password != 'synthetic-correct':
                window.append(current)
                return {'error': 'Invalid synthetic credential'}, 401
            return {'authenticated': True, 'sandbox': True}, 200

    def issue(self):
        with self.lock:
            token = secrets.token_urlsafe(24)
            self.tokens[token] = {'used': False, 'expires': self.clock() + 60}
            return {'token': token, 'expires_in': 60}, 200

    def redeem(self, token, run_id):
        with self.lock:
            entry = self.tokens.get(token)
            if not entry or entry['expires'] <= self.clock(): return {'error': 'Invalid or expired sandbox token'}, 401
            if entry['used']:
                if token not in self.reported:
                    self.reported.add(token)
                    self.incident('identity_attack', 'high', 'Previously redeemed sandbox token presented a second time.',
                                  'Single-use token registry', 'Token fingerprint matched a consumed nonce; reject reuse and require a fresh verification.', run_id)
                return {'error': 'Token replay denied', 'step_up_required': True}, 403
            entry['used'] = True
            return {'redeemed': True}, 200

    def connect(self, target, port, run_id):
        with self.lock:
            # Enforced BEFORE any socket/request operation. There is no peer-network client here.
            self.incident('virtualization_threat', 'high', f'Attempted synthetic peer access to {target}:{port} (logical service).',
                          'Application segmentation: deny peer egress', 'Policy: master → agent management only. Node → node internal-service access is denied. No outbound connection attempted.', run_id)
            return {'error': 'Peer route denied by application policy', 'outbound_connections': 0, 'scope': 'application-level, not hypervisor firewall'}, 403


def create_app(node_id, key, emit=None):
    if node_id not in NODES or len(key) < 32: raise ValueError('Valid NODE_NAME and NODE_SECRET required')
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 8192
    verifier, run_lock = Verifier(), threading.Lock()
    detector = Detector(emit or (lambda event: None))
    armed_probes = {}
    probe_lock = threading.Lock()
    app.extensions['detector'] = detector

    @app.before_request
    def authorize():
        if request.path == '/health' and request.method == 'GET': return None
        if request.method == 'POST' and not isinstance(request.get_json(silent=True), dict):
            return jsonify(error='JSON object required'), 400
        if request.path == '/sandbox/peer-probe': return None
        if not verifier.verify(key, request, 'master'):
            return jsonify(error='Master-only management boundary: invalid identity/signature or replay'), 401

    @app.get('/health')
    def health(): return jsonify(status='ok', node_id=node_id, synthetic_only=True)

    def payload(): return request.get_json(silent=True) or {}

    @app.post('/sandbox/data')
    def data():
        p = payload()
        if p.get('actor') not in ['baseline-reader', 'demo-reader'] or type(p.get('rows')) is not int or not 1 <= p['rows'] <= 40:
            return jsonify(error='Only fixed synthetic actors and 1–40 rows allowed'), 400
        body, code = detector.data(p['actor'], p['rows'], p.get('run_id', 'manual'))
        return jsonify(body), code

    @app.post('/sandbox/auth')
    def auth():
        p = payload()
        if p.get('account') != 'demo-user' or p.get('password') not in ['synthetic-wrong', 'synthetic-correct']:
            return jsonify(error='Only the fixed sandbox account and synthetic credentials allowed'), 400
        body, code = detector.auth(p['account'], p['password'], p.get('run_id', 'manual'))
        return jsonify(body), code

    @app.post('/sandbox/token')
    def token():
        body, code = detector.issue()
        return jsonify(body), code

    @app.post('/sandbox/redeem')
    def redeem():
        body, code = detector.redeem(str(payload().get('token', '')), payload().get('run_id', 'manual'))
        return jsonify(body), code

    @app.post('/sandbox/connect')
    def connect():
        p = payload()
        if p.get('target_node') not in NODES or p.get('logical_port') != 9000:
            return jsonify(error='Only registered synthetic nodes and logical port 9000 allowed'), 400
        body, code = detector.connect(p['target_node'], 9000, p.get('run_id', 'manual'))
        return jsonify(body), code

    @app.post('/control/arm-peer')
    def arm_peer():
        p = payload()
        if (p.get('source_node') not in NODES or p['source_node'] == node_id
                or any(not isinstance(p.get(k), str) or not 1 <= len(p[k]) <= 100
                       for k in ['run_id', 'incident_id', 'nonce'])):
            return jsonify(error='Invalid peer probe authorization'), 400
        with probe_lock:
            armed_probes.clear()  # One explicitly authorized synthetic probe at a time.
            armed_probes[p['nonce']] = {**p, 'expires': time.monotonic() + 30}
        return jsonify(ok=True)

    @app.post('/sandbox/peer-probe')
    def peer_probe_endpoint():
        # This single-purpose boundary can only report an explicitly armed probe.
        # Unknown traffic is rejected silently; it cannot manufacture incidents.
        p = payload()
        with probe_lock:
            nonce = p.get('nonce')
            armed = armed_probes.get(nonce) if isinstance(nonce, str) else None
            if (not armed or armed['expires'] < time.monotonic()
                    or p.get('run_id') != armed['run_id']
                    or request.headers.get('X-Demo-Sender') != armed['source_node']):
                return jsonify(error='Unarmed or expired probe'), 401
            if verifier.verify(key, request, 'master'):
                return jsonify(error='Expected a peer identity, not master'), 400
            del armed_probes[nonce]
        detector.emit({'event_type': 'virtualization_threat', 'stage': 'prevented',
            'severity': 'high', 'timestamp': now(), 'run_id': armed['run_id'],
            'incident_id': armed['incident_id'], 'source_node': armed['source_node'],
            'detail': f"Peer request from {armed['source_node']} reached {node_id} and was rejected with HTTP 401. No internal service was invoked.",
            'control_applied': 'Destination master-only HMAC boundary'})
        return jsonify(blocked=True, boundary='master-only', node_id=node_id, nonce=nonce), 401

    def execute_peer_probe(p):
        peer = p.get('peer', {})
        target = peer.get('node_id')
        if (target not in NODES or target == node_id
                or not valid_agent_url(peer.get('url', ''), target, os.environ.get('LOCAL_DEMO') == '1')
                or any(not isinstance(peer.get(k), str) or not 1 <= len(peer[k]) <= 100 for k in ['nonce', 'incident_id'])):
            raise ValueError('Invalid fixed peer target')
        for stage, detail in [('detected', f'Staged cross-node access from {node_id} toward {target}.'),
                              ('analyzing', 'One authorized harness probe will test the destination master-only boundary. Network reachability is expected; peer authorization is not.')]:
            detector.emit({'event_type': 'virtualization_threat', 'stage': stage, 'severity': 'high',
                'timestamp': now(), 'run_id': p['run_id'], 'incident_id': peer['incident_id'],
                'source_node': node_id, 'detail': detail, 'control_applied': 'Destination master-only HMAC boundary'})
        body = encode({'run_id': p['run_id'], 'nonce': peer['nonce']})
        path = '/sandbox/peer-probe'
        # One fixed request, no redirects, retries or arbitrary ports. Own key only.
        with requests.post(peer['url'] + path, data=body,
                headers=signed_headers(key, node_id, 'POST', path, body),
                timeout=(4, 6), allow_redirects=False, stream=True) as response:
            raw = next(response.iter_content(chunk_size=4097), b'')
            if len(raw) > 4096: raise RuntimeError('Oversized peer response')
            import json
            reply = json.loads(raw)
            if response.status_code != 401 or reply != {'blocked': True, 'boundary': 'master-only', 'node_id': target, 'nonce': peer['nonce']}:
                raise RuntimeError('Peer boundary not verified; transport errors are not prevention')
        return {'target': target, 'outbound_connections': 1, 'peer_status': 401,
                'scope': 'application authentication; not an OS firewall', 'verified': True}

    @app.post('/control/reset')
    def reset():
        if not run_lock.acquire(blocking=False): return jsonify(error='Scenario running'), 409
        try: detector.reset()
        finally: run_lock.release()
        return jsonify(ok=True)

    @app.post('/control/run')
    def run():
        p = payload()
        if p.get('scenario') not in SCENARIOS or not isinstance(p.get('run_id'), str) or len(p['run_id']) > 100:
            return jsonify(error='Invalid scenario or run id'), 400
        if not run_lock.acquire(blocking=False): return jsonify(error='Scenario running'), 409
        try:
            detector.reset()
            def call(path, data):
                body = encode({**data, 'run_id': p['run_id']})
                # The staged workload traverses actual Flask handlers and HMAC boundary.
                with app.test_client() as client:
                    response = client.post(path, data=body, headers=signed_headers(key, 'master', 'POST', path, body))
                    return {'status': response.status_code, 'body': response.get_json()}
            if p['scenario'] == 'virtualization_threat':
                result = importlib.import_module('scenarios.virtualization_threat').run(lambda: execute_peer_probe(p))
            else:
                result = importlib.import_module('scenarios.' + p['scenario']).run(call, node_id=node_id)
            return jsonify(result)
        finally: run_lock.release()

    return app


class Reporter:
    def __init__(self, master, node_id, key, public_url):
        self.master, self.node_id, self.key, self.public_url = master.rstrip('/'), node_id, key, public_url
        self.events = queue.Queue(maxsize=2000)
        self.stop = threading.Event()

    def post(self, path, payload):
        body = encode(payload)
        response = requests.post(self.master + path, data=body,
                                 headers=signed_headers(self.key, self.node_id, 'POST', path, body), timeout=(5, 10), allow_redirects=False)
        if not 200 <= response.status_code < 300: raise RuntimeError(f'Master returned {response.status_code}')

    def emit(self, event):
        self.events.put_nowait({**event, 'node_id': self.node_id, 'event_id': str(uuid.uuid4())})

    def registration_loop(self):
        while not self.stop.is_set():
            try:
                # Re-register every heartbeat: restores registry after Render restarts.
                self.post('/api/nodes/register', {'node_id': self.node_id, 'url': self.public_url})
                self.post('/api/events', {'node_id': self.node_id, 'event_type': 'heartbeat', 'stage': 'analyzing',
                          'severity': 'low', 'timestamp': now(), 'detail': 'Agent heartbeat', 'control_applied': 'Liveness monitor'})
            except Exception as exc: print(f'[{self.node_id}] heartbeat retry: {type(exc).__name__}', flush=True)
            self.stop.wait(8)

    def event_loop(self):
        while not self.stop.is_set():
            try: event = self.events.get(timeout=1)
            except queue.Empty: continue
            delay = 1
            while not self.stop.is_set():
                try:
                    self.post('/api/events', event)
                    break
                except Exception as exc:
                    print(f'[{self.node_id}] event delivery retry: {type(exc).__name__}', flush=True)
                    self.stop.wait(delay)
                    delay = min(delay * 2, 16)
            self.events.task_done()

    def start(self):
        for fn in [self.registration_loop, self.event_loop]: threading.Thread(target=fn, daemon=True).start()


def quick_tunnel(port):
    process = subprocess.Popen(['cloudflared', 'tunnel', '--url', f'http://127.0.0.1:{port}', '--no-autoupdate'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    urls = queue.Queue()
    def reader():
        for line in process.stdout:
            match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
            if match: urls.put(match.group(0))
    threading.Thread(target=reader, daemon=True).start()
    try: return process, urls.get(timeout=60)
    except queue.Empty:
        process.terminate()
        raise RuntimeError('No Cloudflare quick tunnel URL within 60 seconds; check cloudflared installation/configuration.')


def main():
    from werkzeug.serving import make_server
    node_id, key = os.environ.get('NODE_NAME', 'node-1'), os.environ.get('NODE_SECRET', '')
    master = os.environ.get('MASTER_URL', '')
    if not master.startswith('https://') and not (os.environ.get('LOCAL_DEMO') == '1' and master.startswith('http://127.0.0.1:')):
        raise RuntimeError('MASTER_URL must use HTTPS outside LOCAL_DEMO=1')
    port = int(os.environ.get('AGENT_PORT', '6000'))
    public_url = os.environ.get('PUBLIC_URL')
    pending = queue.Queue()
    app = create_app(node_id, key, pending.put_nowait)
    server = make_server('127.0.0.1', port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tunnel = None
    try:
        if not public_url: tunnel, public_url = quick_tunnel(port)
        reporter = Reporter(master, node_id, key, public_url)
        reporter.start()
        print(f'{node_id} listening; registered tunnel {public_url}', flush=True)
        while True:
            if tunnel and tunnel.poll() is not None: raise RuntimeError('Cloudflare tunnel exited; restart agent to obtain a new URL')
            try: reporter.emit(pending.get(timeout=1))
            except queue.Empty: pass
    except KeyboardInterrupt: pass
    finally:
        server.shutdown()
        if tunnel: tunnel.terminate()


if __name__ == '__main__': main()
