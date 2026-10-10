NAME = 'identity_attack'


def run(call, node_id='node-1'):
    attempts = [call('/sandbox/auth', {'account': 'demo-user', 'password': 'synthetic-wrong'}) for _ in range(6)]
    issued = call('/sandbox/token', {})
    token = issued['body']['token']
    first = call('/sandbox/redeem', {'token': token})
    replay = call('/sandbox/redeem', {'token': token})
    assert attempts[3]['status'] == 429 and all(a['status'] == 429 for a in attempts[3:])
    assert first['status'] == 200 and replay['status'] == 403
    return {'failed_logins': 3, 'rate_limited_requests': 3, 'token_replay_blocked': True, 'step_up_required': True, 'verified': True}
