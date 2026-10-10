"""Three-chapter multi-tenancy threat scenario between self-owned demo agents,
labelled 'virtualization_threat' for wire compatibility with the dashboard
and master-server (see contract.py's SCENARIOS and events/schema.json).

What this models: threats specific to sharing virtualized/cloud infrastructure
with other tenants. It is NOT a VM escape or hypervisor exploit (no guest/host
boundary exists in this demo), no port scan, and no OS/cloud network-firewall
test. All steps hit only this demo's own fixed, pre-armed/sandboxed routes.

Chapter 1 — lateral pivot: one signed request from this node to a peer's
internal route. The peer's master-only HMAC boundary has to reject it and
report that evidence itself (a source-reported success wouldn't count).

Chapter 2 — replay the pivot: a real attacker who gets blocked once retries.
This replays the exact same probe (same nonce) a second time. The peer's
armed-probe registry is single-use, so this must now fail differently
(nothing armed left to match), proving the boundary isn't just lucky once.

Chapter 3 — noisy neighbor: a single-tenant workload that suddenly demands
far more memory than this node's normal ~50-60MB footprint — the resource-
contention threat multi-tenant/virtualized platforms defend against with
quotas. The spike is real and measured (an isolated child process actually
allocates and holds the memory briefly, then frees it), not a client-claimed
number, and the detector blocks the actor once the spike is confirmed
abnormal.
"""
import time

NAME = 'virtualization_threat'


def run(peer_probe, call, node_id='node-1'):
    timeline = []

    # --- Chapter 1: initial lateral-pivot attempt ---------------------------
    started = time.time()
    result = peer_probe()
    first_elapsed = round(time.time() - started, 3)

    assert isinstance(result, dict) and result.get('verified') is True
    assert result.get('peer_status') == 401, 'Destination must reject the peer identity'
    assert result.get('outbound_connections') == 1, 'Exactly one controlled request is expected per attempt'
    assert result.get('scope') == 'application authentication; not an OS firewall'
    target = result.get('target')
    assert target in {f'node-{i}' for i in range(1, 6)}
    timeline.append({
        'step': f'initial pivot attempt to {target}',
        'outcome': 'blocked',
        'http_status': result.get('peer_status'),
        'seconds': first_elapsed,
    })

    # --- Chapter 2: replay the same pivot attempt ---------------------------
    replay_started = time.time()
    replay_blocked = False
    try:
        peer_probe()
    except RuntimeError:
        replay_blocked = True
    replay_elapsed = round(time.time() - replay_started, 3)
    assert replay_blocked, 'Replaying a consumed pivot attempt must be rejected, not repeated'
    timeline.append({
        'step': f'replayed pivot attempt to {target}',
        'outcome': 'blocked (single-use probe already consumed)',
        'seconds': replay_elapsed,
    })

    # --- Chapter 3: noisy-neighbor resource spike ---------------------------
    # A baseline read confirms normal node workload is small, then a single
    # actor demands a far larger share of memory than any legitimate demo
    # workload needs — the real noisy-neighbor signal on shared infrastructure.
    baseline = call('/sandbox/workload', {'actor': 'baseline-reader', 'mb': 40})
    assert baseline['status'] == 200, 'A normal-sized workload request should be allowed'
    baseline_peak = baseline['body'].get('peak_rss_mb')
    assert isinstance(baseline_peak, (int, float)), 'Agent must report a real measured peak, not a placeholder'

    spike_started = time.time()
    spike = call('/sandbox/workload', {'actor': 'demo-reader', 'mb': 2048})
    spike_elapsed = round(time.time() - spike_started, 3)
    assert spike['status'] == 403, 'A 2GB single-actor request must be denied as abnormal resource consumption'
    peak_rss_mb = spike['body'].get('peak_rss_mb')
    assert isinstance(peak_rss_mb, (int, float)) and peak_rss_mb > 0, \
        'The spike must be really measured by the OS, not reported from the unvalidated client request'
    requested_mb = spike['body'].get('requested_mb')
    assert requested_mb == 2048, 'The full 2048MB request must reach the detector, not be silently downsized'

    # The actor stays blocked on a follow-up, independent of size requested.
    follow_up = call('/sandbox/workload', {'actor': 'demo-reader', 'mb': 1})
    assert follow_up['status'] == 403 and follow_up['body'].get('peak_rss_mb') == 0, \
        'Actor must stay blocked until the operator resets the agent; no further allocation should even be attempted'

    timeline.append({
        'step': 'noisy-neighbor resource spike (2048MB requested)',
        'outcome': 'blocked after measurement',
        'measured_peak_rss_mb': peak_rss_mb,
        'baseline_peak_rss_mb': baseline_peak,
        'seconds': spike_elapsed,
    })

    return {
        **result,
        'scenario_scope': (
            'lateral-movement pivot plus replay, and a measured noisy-neighbor resource spike; '
            'destination application authentication and per-node resource quota only'
        ),
        'hypervisor_attack_simulated': False,
        'control': 'Destination master-only HMAC boundary + single-use probe registry + per-actor resource quota',
        'attempts_blocked': 3,
        'round_trip_seconds': first_elapsed,
        'measured_peak_rss_mb': peak_rss_mb,
        'baseline_peak_rss_mb': baseline_peak,
        'evidence_trail': timeline,
        'narrative': (
            f"A simulated lateral-pivot attempt from this node to {target}'s internal route was "
            f"rejected with HTTP 401 by the peer's master-only HMAC boundary in {first_elapsed}s; "
            f"retrying the identical attempt was independently rejected by the peer's single-use "
            f"probe registry. Separately, a single actor demanded {requested_mb}MB against a normal "
            f"demo workload's ~{baseline_peak}MB footprint; an isolated child process really "
            f"allocated and held the memory, measured at {peak_rss_mb}MB peak RSS, "
            f"before the actor was blocked from further workload requests — the noisy-neighbor "
            f"resource-contention threat multi-tenant platforms guard against with quotas."
        ),
    }
