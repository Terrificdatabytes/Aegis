import functools
import os
import secrets
import sys
import threading
import time
import uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from flask import Flask, jsonify, request, render_template, session, redirect
from common.security import Verifier, node_key, signed_headers, encode, valid_agent_url
from common.contract import NODES, SCENARIOS, validate_event, now
from events.store import Store


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('SESSION_SECRET') or secrets.token_hex(32),
                      MASTER_SECRET=os.environ.get('MASTER_SECRET', ''), ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD', ''),
                      LOCAL_DEMO=os.environ.get('LOCAL_DEMO') == '1', DB_PATH=os.environ.get('DB_PATH', 'demo.sqlite3'),
                      MAX_CONTENT_LENGTH=16384, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1')
    if config: app.config.update(config)
    if len(app.config['MASTER_SECRET']) < 32 or len(app.config['ADMIN_PASSWORD']) < 12:
        raise RuntimeError('Set MASTER_SECRET (32+ characters) and ADMIN_PASSWORD (12+ characters).')
    store, verifier = Store(app.config['DB_PATH']), Verifier()
    app.extensions['store'] = store
    busy = set()
    busy_lock = threading.Lock()
    login_attempts = {}
    login_lock = threading.Lock()

    def admin(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get('admin'): return jsonify(error='Sign in required'), 401
            if request.method != 'GET' and not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), session.get('csrf', 'missing')):
                return jsonify(error='Invalid CSRF token'), 403
            return fn(*args, **kwargs)
        return wrapped

    def node_auth(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            node_id = request.headers.get('X-Demo-Sender', '')
            if node_id not in NODES or not verifier.verify(node_key(app.config['MASTER_SECRET'], node_id), request, node_id):
                return jsonify(error='Invalid signature, timestamp or replay'), 401
            request.demo_node = node_id
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def json_object_only():
        if request.path.startswith('/api/') and request.method == 'POST':
            if not isinstance(request.get_json(silent=True), dict):
                return jsonify(error='JSON object required'), 400

    @app.after_request
    def secure(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'"
        return response

    @app.get('/health')
    def health(): return jsonify(status='ok', mode='local' if app.config['LOCAL_DEMO'] else 'cloud')

    @app.get('/')
    def index():
        if not session.get('admin'): return render_template('login.html', local=app.config['LOCAL_DEMO'])
        return render_template('dashboard.html', csrf=session['csrf'], local=app.config['LOCAL_DEMO'])

    @app.post('/login')
    def login():
        # Ignore forwarded IP headers; prevent spoofing the rate-limit bucket.
        ip = request.remote_addr
        with login_lock:
            current = time.time()
            for addr in list(login_attempts):
                login_attempts[addr] = [t for t in login_attempts[addr] if current-t < 60]
                if not login_attempts[addr]: del login_attempts[addr]
            attempts = login_attempts.setdefault(ip, [])
            if len(attempts) >= 10: return render_template('login.html', error='Too many attempts. Wait one minute.'), 429
            attempts.append(current)
        if not secrets.compare_digest(request.form.get('password', ''), app.config['ADMIN_PASSWORD']):
            return render_template('login.html', error='Incorrect operator password.'), 401
        session.clear()
        session.update(admin=True, csrf=secrets.token_hex(24))
        return redirect('/')

    @app.post('/api/logout')
    @admin
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/api/state')
    @admin
    def state(): return jsonify(store.snapshot())

    @app.post('/api/nodes/register')
    @node_auth
    def register():
        data = request.get_json(silent=True) or {}
        if data.get('node_id') != request.demo_node or not valid_agent_url(data.get('url', ''), request.demo_node, app.config['LOCAL_DEMO']):
            return jsonify(error='Node identity or tunnel URL rejected'), 400
        store.register(request.demo_node, data['url'].rstrip('/'))
        return jsonify(ok=True)

    @app.post('/api/events')
    @node_auth
    def event():
        try:
            data = validate_event(request.get_json(silent=True))
            if data['node_id'] != request.demo_node: raise ValueError('Node identity mismatch')
        except ValueError as exc: return jsonify(error=str(exc)), 400
        store.touch(request.demo_node)
        # Heartbeats update liveness without flooding the incident feed.
        event_id = store.add(data) if data['event_type'] != 'heartbeat' else None
        return jsonify(ok=True, id=event_id), 201

    def agent_call(node, path, payload):
        body = encode(payload)
        headers = signed_headers(node_key(app.config['MASTER_SECRET'], node['node_id']), 'master', 'POST', path, body)
        response = requests.post(node['url'] + path, data=body, headers=headers, timeout=(5, 35), allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200: raise RuntimeError('Agent returned an unexpected response')
        return response.json()

    @app.post('/api/run')
    @admin
    def run():
        data = request.get_json(silent=True) or {}
        node_id, scenario = data.get('node_id'), data.get('scenario')
        if node_id not in NODES or scenario not in SCENARIOS: return jsonify(error='Invalid node or scenario'), 400
        node = next(n for n in store.snapshot()['nodes'] if n['node_id'] == node_id)
        if not node['online']: return jsonify(error='Node is offline. Connect an agent first.'), 409
        peer = None
        if scenario == 'virtualization_threat':
            peer = next((n for n in store.snapshot()['nodes'] if n['online'] and n['node_id'] != node_id), None)
            if not peer: return jsonify(error='Two online agents are required for the peer-boundary test.'), 409
        reserved = {node_id} | ({peer['node_id']} if peer else set())
        with busy_lock:
            if reserved & busy: return jsonify(error='This node already has a scenario running.'), 409
            busy.update(reserved)
        record = {'run_id': str(uuid.uuid4()), 'node_id': node_id, 'scenario': scenario, 'status': 'running', 'started_at': now()}
        if peer: record['target_node'] = peer['node_id']
        store.run(record)
        def worker():
            try:
                payload = {'scenario': scenario, 'run_id': record['run_id']}
                if peer:
                    nonce, incident_id = secrets.token_hex(24), str(uuid.uuid4())
                    agent_call(peer, '/control/arm-peer', {'run_id': record['run_id'], 'source_node': node_id, 'nonce': nonce, 'incident_id': incident_id})
                    payload['peer'] = {'node_id': peer['node_id'], 'url': peer['url'], 'nonce': nonce, 'incident_id': incident_id}
                result = agent_call(node, '/control/run', payload)
                if peer:
                    # A tunnel error or forged source result cannot count as prevention.
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        evidence = store.snapshot()['events']
                        if any(e.get('incident_id') == incident_id and e['node_id'] == peer['node_id'] and e['stage'] == 'prevented' for e in evidence):
                            break
                        time.sleep(0.1)
                    else: raise RuntimeError('Missing signed destination evidence; outcome inconclusive')
                if not isinstance(result, dict) or result.get('verified') is not True:
                    raise RuntimeError('Agent did not verify the scenario')
                record.update(status='completed', result=result)
            except Exception as exc:
                # Do not leak keys or signed headers to the UI.
                record.update(status='failed', error='Agent unavailable or rejected command: ' + type(exc).__name__)
            finally:
                record['finished_at'] = now()
                store.run(record)
                with busy_lock: busy.difference_update(reserved)
        threading.Thread(target=worker, daemon=True).start()
        return jsonify(record), 202

    @app.post('/api/reset')
    @admin
    def reset():
        with busy_lock:
            if busy: return jsonify(error='Wait for active runs before resetting.'), 409
            nodes = [n for n in store.snapshot()['nodes'] if n['online']]
            # Hold run lock so reset cannot race with a new scenario.
            failures = []
            for node in nodes:
                try: agent_call(node, '/control/reset', {})
                except Exception: failures.append(node['node_id'])
            if failures: return jsonify(error='Reset incomplete; unreachable agents: ' + ', '.join(failures)), 502
            store.reset()
        return jsonify(ok=True)

    return app


if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), threaded=True, use_reloader=False)
