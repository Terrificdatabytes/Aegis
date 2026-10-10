"""Safe authentication-abuse and one-time-token replay scenario.

The login portion models a rapid failed-login burst against one explicitly
sandboxed account. It is *not* credential stuffing: there is no stolen
credential list and the endpoint accepts only a fixed synthetic password.
The replay portion redeems a newly minted sandbox one-time token, then resends
the same token. No real user, password, session, or service is involved.
"""
NAME = 'identity_attack'


def run(call, node_id='node-1'):
    # Exercise the real sandbox auth handler with its one fixed wrong password.
    attempts = [
        call('/sandbox/auth', {
            'account': 'demo-user',
            'password': 'synthetic-wrong',
        })
        for _ in range(6)
    ]
    assert [r['status'] for r in attempts[:3]] == [401, 401, 401], \
        'Only the first three fixed synthetic failures should reach credential checking'
    assert [r['status'] for r in attempts[3:]] == [429, 429, 429], \
        'Rate limit should activate and persist after the threshold'
    assert attempts[3]['body'].get('step_up_required') is True
    assert attempts[3]['body'].get('anomaly_score') == 90, \
        'This value is the demo’s fixed rule-based score, not an ML score'

    # The token is minted by the sandbox itself; keep it local to this run.
    issued = call('/sandbox/token', {})
    assert issued['status'] == 200
    token = issued['body'].get('token')
    assert isinstance(token, str) and token
    assert issued['body'].get('expires_in') == 60

    legitimate_use = call('/sandbox/redeem', {'token': token})
    replay = call('/sandbox/redeem', {'token': token})
    assert legitimate_use['status'] == 200, 'First one-time-token use should pass'
    assert replay['status'] == 403, 'Replaying the consumed token must be denied'
    assert replay['body'].get('step_up_required') is True

    # Never return or log the transient token to the dashboard.
    return {
        'verified': True,
        'scenario_scope': 'fixed-account failed-login burst plus sandbox one-time-token replay',
        'credential_stuffing_simulated': False,
        'failed_login_attempts': 3,
        'rate_limited_follow_up_attempts': 3,
        'account_lock_seconds': 60,
        'token_reuse_denied': True,
        'step_up_required': True,
        'control': 'Authentication rate limit and single-use token registry',
    }
