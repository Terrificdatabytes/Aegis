import importlib.util
import sys
import time
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'master-server'))
from common.contract import now, validate_event
from common.security import node_key, signed_headers, encode, valid_agent_url
from app import create_app as master_app
spec = importlib.util.spec_from_file_location('agent', ROOT / 'node-agent/agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
SECRET, PASSWORD = 'm' * 64, 'operator-password-long'
KEY = node_key(SECRET, 'node-1')

@pytest.fixture(autouse=True)
def no_delay(monkeypatch): monkeypatch.setenv('EVENT_STAGE_DELAY', '0')

@pytest.fixture
def master(): return master_app({'TESTING': True, 'MASTER_SECRET': SECRET, 'ADMIN_PASSWORD': PASSWORD, 'DB_PATH': ':memory:', 'LOCAL_DEMO': True})

def signed(client, path, data, key=KEY, sender='node-1'):
    body = encode(data)
    return client.post(path, data=body, headers=signed_headers(key, sender, 'POST', path, body))

def login(client):
    assert client.post('/login', data={'password': PASSWORD}).status_code == 302
    with client.session_transaction() as s: return s['csrf']

def event(**extra):
    return {'node_id': 'node-1', 'event_type': 'data_breach', 'stage': 'detected', 'severity': 'critical', 'timestamp': now(), 'detail': 'Synthetic anomaly', 'control_applied': 'Volume guard', 'event_id': 'one', **extra}

@pytest.mark.parametrize('scenario,incidents', [('data_breach',1), ('identity_attack',2)])
def test_scenarios_traverse_signed_handlers(scenario, incidents):
    emitted = []
    app = agent.create_app('node-1', KEY, emitted.append)
    with app.test_client() as c:
        response = signed(c, '/control/run', {'scenario': scenario, 'run_id': 'test'}, sender='master')
        assert response.status_code == 200 and response.json['verified']
    assert len(emitted) == incidents * 3
    for i in range(incidents):
        group = emitted[i*3:(i+1)*3]
        assert [e['stage'] for e in group] == ['detected', 'analyzing', 'prevented']
        assert len({e['incident_id'] for e in group}) == 1


def test_volume_block_releases_no_rows():
    emitted=[]
    d=agent.Detector(emitted.append)
    assert d.data('demo-reader',40,'r')[1] == 200
    assert d.data('demo-reader',40,'r')[1] == 200
    body,code=d.data('demo-reader',1,'r')
    assert code==403 and body['released_rows']==0
    assert d.data('demo-reader',1,'r')[1]==403
    d.reset()
    assert d.data('demo-reader',1,'r')[1]==200


def test_sliding_window_expires():
    clock=[0]
    d=agent.Detector(lambda e:None,clock=lambda:clock[0])
    d.data('demo-reader',40,'r');d.data('demo-reader',40,'r')
    clock[0]=10
    assert d.data('demo-reader',40,'r')[1]==200


def test_identity_lock_and_expiry():
    clock=[0]
    d=agent.Detector(lambda e:None,clock=lambda:clock[0])
    for _ in range(3): assert d.auth('demo-user','synthetic-wrong','r')[1]==401
    assert d.auth('demo-user','synthetic-correct','r')[1]==429
    clock[0]=61
    assert d.auth('demo-user','synthetic-correct','r')[1]==200


def test_token_single_use_and_expiry():
    clock=[0]
    d=agent.Detector(lambda e:None,clock=lambda:clock[0])
    token=d.issue()[0]['token']
    assert d.redeem(token,'r')[1]==200
    assert d.redeem(token,'r')[1]==403
    other=d.issue()[0]['token'];clock[0]=61
    assert d.redeem(other,'r')[1]==401


def test_peer_identity_denied_before_detector():
    emitted=[]
    app=agent.create_app('node-2',node_key(SECRET,'node-2'),emitted.append)
    with app.test_client() as c:
        # Another node cannot use its own key to reach a target node's management or sandbox API.
        assert signed(c,'/sandbox/connect',{'target_node':'node-2','logical_port':9000},sender='node-1').status_code==401
    assert emitted==[]


def test_segmentation_no_network(monkeypatch):
    def forbidden(*args,**kwargs):raise AssertionError('No peer traffic should be sent')
    monkeypatch.setattr(agent.requests,'post',forbidden)
    assert agent.Detector(lambda e:None).connect('node-2',9000,'r')==({'error':'Peer route denied by application policy','outbound_connections':0,'scope':'application-level, not hypervisor firewall'},403)


def test_hmac_replay_and_body_tampering(master):
    body=encode({'node_id':'node-1','url':'http://127.0.0.1:6101'})
    headers=signed_headers(KEY,'node-1','POST','/api/nodes/register',body)
    with master.test_client() as c:
        assert c.post('/api/nodes/register',data=body,headers=headers).status_code==200
        assert c.post('/api/nodes/register',data=body,headers=headers).status_code==401
        headers=signed_headers(KEY,'node-1','POST','/api/nodes/register',body)
        assert c.post('/api/nodes/register',data=body+b' ',headers=headers).status_code==401


def test_signed_timestamp_and_path(master):
    body=encode(event())
    headers=signed_headers(KEY,'node-1','POST','/api/events',body)
    headers['X-Demo-Time']='0'
    with master.test_client() as c:
        assert c.post('/api/events',data=body,headers=headers).status_code==401
        headers=signed_headers(KEY,'node-1','POST','/other',body)
        assert c.post('/api/events',data=body,headers=headers).status_code==401


def test_event_ingest_validation_dedup_and_heartbeat(master):
    with master.test_client() as c:
        assert signed(c,'/api/events',event()).status_code==201
        assert signed(c,'/api/events',event()).status_code==201
        assert signed(c,'/api/events',event(stage='bad')).status_code==400
        assert signed(c,'/api/events',event(node_id='node-2')).status_code==400
        assert signed(c,'/api/events',event(event_type='heartbeat',event_id='heart')).status_code==201
    assert len(master.extensions['store'].snapshot()['events'])==1


def test_login_csrf_and_offline_run(master):
    with master.test_client() as c:
        assert c.get('/api/state').status_code==401
        assert c.post('/api/events',json=event()).status_code==401
        csrf=login(c)
        assert c.get('/api/state').status_code==200
        assert c.post('/api/run',json={'node_id':'node-1','scenario':'data_breach'}).status_code==403
        assert c.post('/api/run',json={'node_id':'node-1','scenario':'data_breach'},headers={'X-CSRF-Token':csrf}).status_code==409
        assert c.post('/api/reset',json={},headers={'X-CSRF-Token':csrf}).status_code==200


def test_run_worker_completion(master, monkeypatch):
    class Response:
        status_code=200
        def raise_for_status(self):pass
        def json(self):return {'verified':True}
    monkeypatch.setattr('app.requests.post',lambda *a,**k:Response())
    master.extensions['store'].register('node-1','http://127.0.0.1:6101')
    with master.test_client() as c:
        csrf=login(c)
        result=c.post('/api/run',json={'node_id':'node-1','scenario':'data_breach'},headers={'X-CSRF-Token':csrf})
        assert result.status_code==202
    for _ in range(100):
        runs=master.extensions['store'].snapshot()['runs']
        if runs[0]['status']!='running':break
        time.sleep(.01)
    assert runs[0]['status']=='completed'


def test_online_timeout(master):
    store=master.extensions['store']
    store.register('node-1','http://127.0.0.1:6101')
    assert store.snapshot()['nodes'][0]['online']
    store.db.execute("UPDATE nodes SET last_seen='2000-01-01T00:00:00+00:00'")
    assert not store.snapshot()['nodes'][0]['online']

@pytest.mark.parametrize('url', ['http://169.254.169.254','https://evil.example','https://x.trycloudflare.com.evil.test','https://a:b@x.trycloudflare.com','https://x.trycloudflare.com/path','https://x.trycloudflare.com:443/?x=1'])
def test_registration_url_restricts_targets(url): assert not valid_agent_url(url,'node-1')


def test_url_modes():
    assert valid_agent_url('https://abc.trycloudflare.com','node-1')
    assert valid_agent_url('http://127.0.0.1:6101','node-1',True)
    assert not valid_agent_url('http://127.0.0.1:6102','node-1',True)
    assert not valid_agent_url('http://127.0.0.1:6101','node-1')

@pytest.mark.parametrize('field,value',[('timestamp','not-time'),('severity','bad'),('detail',''),('node_id','node-99'),('timestamp','2026-01-01T00:00:00')])
def test_event_contract(field,value):
    with pytest.raises(ValueError):validate_event(event(**{field:value}))


def test_login_rate_limit(master):
    with master.test_client() as c:
        for _ in range(10):assert c.post('/login',data={'password':'bad'}).status_code==401
        assert c.post('/login',data={'password':PASSWORD}).status_code==429


def test_late_event_after_reset_is_acknowledged_but_dropped(master):
    store=master.extensions['store']
    store.run({'run_id':'old-run','node_id':'node-1','status':'completed'})
    with master.test_client() as c:
        assert signed(c,'/api/events',event(run_id='old-run')).status_code==201
        assert len(store.snapshot()['events'])==1
        store.reset()
        assert signed(c,'/api/events',event(run_id='old-run')).status_code==201
        assert store.snapshot()['events']==[]


def test_inflight_run_marked_failed_after_restart(tmp_path):
    from events.store import Store
    path=str(tmp_path/'restart.sqlite3')
    s=Store(path)
    s.run({'run_id':'r','node_id':'node-1','status':'running'})
    s.db.close()
    new=Store(path)
    assert new.snapshot()['runs'][0]['status']=='failed'


def test_non_object_json_rejected(master):
    with master.test_client() as c:
        assert c.post('/api/nodes/register',json=['bad']).status_code==400
    with agent.create_app('node-1',KEY).test_client() as c:
        assert c.post('/control/run',json=['bad']).status_code==400


def test_actual_peer_boundary_harness(monkeypatch):
    monkeypatch.setenv('LOCAL_DEMO','1')
    source_events,dest_events=[],[]
    src=agent.create_app('node-1',KEY,source_events.append)
    dest_key=node_key(SECRET,'node-2')
    dest=agent.create_app('node-2',dest_key,dest_events.append)
    nonce='a'*48
    with dest.test_client() as c:
        assert signed(c,'/control/arm-peer',{'run_id':'run','incident_id':'incident','source_node':'node-1','nonce':nonce},key=dest_key,sender='master').status_code==200
    calls=[]
    def post(url,**kwargs):
        calls.append(url)
        assert kwargs['allow_redirects'] is False
        with dest.test_client() as c:
            r=c.post('/sandbox/peer-probe',data=kwargs['data'],headers=kwargs['headers'])
        class Response:
            status_code=r.status_code
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,chunk_size):yield r.data
        return Response()
    monkeypatch.setattr(agent.requests,'post',post)
    with src.test_client() as c:
        r=signed(c,'/control/run',{'scenario':'virtualization_threat','run_id':'run','peer':{'node_id':'node-2','url':'http://127.0.0.1:6102','nonce':nonce,'incident_id':'incident'}},sender='master')
        assert r.status_code==200 and r.json['verified'] and r.json['peer_status']==401
    assert len(calls)==1
    assert [e['stage'] for e in source_events]==['detected','analyzing']
    assert [e['stage'] for e in dest_events]==['prevented']
    assert dest_events[0]['source_node']=='node-1'
    with dest.test_client() as c:
        assert signed(c,'/sandbox/peer-probe',{'run_id':'run','nonce':nonce},sender='node-1').status_code==401
    assert len(dest_events)==1


def test_source_does_not_claim_prevention_on_peer_transport_failure(monkeypatch):
    monkeypatch.setenv('LOCAL_DEMO','1')
    def fail(*a,**k): raise agent.requests.ConnectionError('synthetic unreachable peer')
    monkeypatch.setattr(agent.requests,'post',fail)
    events=[]
    src=agent.create_app('node-1',KEY,events.append)
    src.config['TESTING']=True
    with src.test_client() as c:
        with pytest.raises(agent.requests.ConnectionError):
            signed(c,'/control/run',{'scenario':'virtualization_threat','run_id':'r','peer':{'node_id':'node-2','url':'http://127.0.0.1:6102','nonce':'n','incident_id':'i'}},sender='master')
    assert not any(e['stage']=='prevented' for e in events)


def test_wrong_node_cannot_report_for_a_registered_run(master):
    store=master.extensions['store']
    store.run({'run_id':'r','node_id':'node-1','target_node':'node-2','status':'running'})
    with master.test_client() as c:
        response=signed(c,'/api/events',event(node_id='node-3',run_id='r'),key=node_key(SECRET,'node-3'),sender='node-3')
        assert response.status_code==201
    assert store.snapshot()['events']==[]
