import json
import sqlite3
import threading
from datetime import datetime, timezone
from common.contract import NODES, now


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS nodes(node_id TEXT PRIMARY KEY, url TEXT, last_seen TEXT, registered TEXT);
        CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, data TEXT NOT NULL);
        ''')
        # A process restart cannot safely resume an in-flight HTTP command.
        for row in self.db.execute('SELECT run_id,data FROM runs').fetchall():
            run = json.loads(row['data'])
            if run.get('status') == 'running':
                run.update(status='failed', error='Master restarted during this run; outcome unknown. Retry the scenario.')
                self.db.execute('UPDATE runs SET data=? WHERE run_id=?', (json.dumps(run), row['run_id']))
        self.db.commit()

    def register(self, node_id, url):
        with self.lock, self.db:
            self.db.execute('INSERT INTO nodes VALUES(?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET url=excluded.url,last_seen=excluded.last_seen', (node_id, url, now(), now()))

    def touch(self, node_id):
        with self.lock, self.db:
            self.db.execute('UPDATE nodes SET last_seen=? WHERE node_id=?', (now(), node_id))

    def add(self, event):
        with self.lock, self.db:
            # Check and insert share the reset lock. UUID run IDs are never reused.
            # Delayed/retried telemetry from a reset run must not resurrect the log.
            if event.get('run_id') and event['run_id'] != 'manual':
                run = self.db.execute('SELECT data FROM runs WHERE run_id=?', (event['run_id'],)).fetchone()
                if not run or event['node_id'] not in [json.loads(run[0])['node_id'], json.loads(run[0]).get('target_node')]:
                    return None
            cur = self.db.execute('INSERT OR IGNORE INTO events(event_id,data) VALUES(?,?)', (event.get('event_id'), json.dumps({**event, 'received_at': now()})))
            self.db.execute('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-5000 FROM events)')
            return cur.lastrowid if cur.rowcount else None

    def run(self, data):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO runs VALUES(?,?)', (data['run_id'], json.dumps(data)))
            self.db.execute('DELETE FROM runs WHERE run_id NOT IN (SELECT run_id FROM runs ORDER BY rowid DESC LIMIT 100)')

    def snapshot(self):
        with self.lock:
            rows = {r['node_id']: dict(r) for r in self.db.execute('SELECT * FROM nodes')}
            nodes = []
            for node_id in NODES:
                row = rows.get(node_id, {'node_id': node_id, 'url': None, 'last_seen': None})
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(row['last_seen'])).total_seconds() if row['last_seen'] else None
                nodes.append({**row, 'online': age is not None and age < 25, 'age_seconds': round(age) if age is not None else None})
            events = [{**json.loads(r['data']), 'id': r['id']} for r in self.db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 300')]
            counts = {'detected': 0, 'prevented': 0, 'critical': 0}
            # Metrics describe the bounded, retained log, not just the visible feed.
            for row in self.db.execute('SELECT data FROM events'):
                e = json.loads(row[0])
                if e['stage'] in counts: counts[e['stage']] += 1
                if e['severity'] == 'critical' and e['stage'] == 'detected': counts['critical'] += 1
            runs = [json.loads(r[0]) for r in self.db.execute('SELECT data FROM runs ORDER BY rowid DESC LIMIT 12')]
            return {'nodes': nodes, 'events': events, 'metrics': counts, 'runs': runs, 'server_time': now()}

    def reset(self):
        with self.lock, self.db:
            self.db.execute('DELETE FROM events')
            self.db.execute('DELETE FROM runs')
