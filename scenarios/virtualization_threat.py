"""One real request between self-owned agents; no scan or exploit payload."""
NAME = 'virtualization_threat'


def run(peer_probe):
    result = peer_probe()
    assert result['peer_status'] == 401 and result['outbound_connections'] == 1
    return result
