NAME = 'data_breach'


def run(call, node_id='node-1'):
    normal = call('/sandbox/data', {'actor': 'baseline-reader', 'rows': 5})
    samples = [call('/sandbox/data', {'actor': 'demo-reader', 'rows': 30}) for _ in range(4)]
    assert normal['status'] == 200
    assert [s['status'] for s in samples] == [200, 200, 403, 403]
    return {'requests': 5, 'rows_released_to_demo_actor': 60, 'blocked_requests': 2, 'control': 'Sliding-window volume guard', 'verified': True}
