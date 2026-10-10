"""Single-request peer-boundary scenario between two self-owned demo agents.

Sends exactly one request to the destination's fixed, pre-armed demonstration
route. The target rejects a source-node identity with HTTP 401 and independently
reports signed evidence. This is a real application-authentication check across
the agents, but it is NOT a VM escape, hypervisor exploit, port scan, or OS/cloud
network-firewall test. No protected internal service is invoked.
"""
NAME = 'virtualization_threat'


def run(peer_probe):
    # The master/agent harness arms the exact peer and nonce before this call.
    # It raises on timeout, redirects, unexpected responses, or missing proof;
    # a network failure must never be labelled a successful defense.
    result = peer_probe()
    assert isinstance(result, dict) and result.get('verified') is True
    assert result.get('peer_status') == 401, 'Destination must reject the peer identity'
    assert result.get('outbound_connections') == 1, 'Exactly one controlled request is expected'
    assert result.get('scope') == 'application authentication; not an OS firewall'
    assert result.get('target') in {f'node-{i}' for i in range(1, 6)}
    return {
        **result,
        'scenario_scope': 'one fixed peer request; destination application authentication only',
        'hypervisor_attack_simulated': False,
        'control': 'Destination master-only HMAC boundary',
    }
