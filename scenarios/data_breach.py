"""Synthetic anomalous-export scenario.

Models the *behavioral signal* of a compromised/abused data reader attempting
bulk exfiltration. Every record is synthetic; this is not an unauthorized real
data breach. Existing node-agent policy enforces its 80-row / 10-second budget.
The three staged calls release 80 dummy rows before the next chunk is blocked:
this control detects excessive volume, not stolen credentials or data sensitivity.
"""
NAME = 'data_breach'


def run(call, node_id='node-1'):
    # Establish a small expected-use baseline and check the data really is dummy.
    baseline = call('/sandbox/data', {'actor': 'baseline-reader', 'rows': 5})
    assert baseline['status'] == 200, 'Synthetic baseline request should be allowed'
    records = baseline['body'].get('rows', [])
    assert len(records) == 5 and all(r.get('classification') == 'SYNTHETIC' for r in records), \
        'Baseline must contain only labelled synthetic records'

    # A single synthetic reader increases its export in plausible chunks.
    chunks = [20, 25, 35]
    results = [call('/sandbox/data', {'actor': 'demo-reader', 'rows': rows}) for rows in chunks]
    assert all(r['status'] == 200 for r in results), 'Requests up to the exact budget should pass'
    assert all(r['body'].get('released_rows') == rows for r, rows in zip(results, chunks))
    released_before_detection = sum(r['body']['released_rows'] for r in results)
    assert released_before_detection == 80

    # The next chunk would exceed the sliding-window allowance (100 > 80).
    blocked = call('/sandbox/data', {'actor': 'demo-reader', 'rows': 20})
    assert blocked['status'] == 403, 'Over-budget export must be denied'
    assert blocked['body'].get('released_rows') == 0, 'Denied chunk must disclose no rows'

    # Verify that the actor remains blocked until the operator resets the agent.
    follow_up = call('/sandbox/data', {'actor': 'demo-reader', 'rows': 1})
    assert follow_up['status'] == 403 and follow_up['body'].get('released_rows') == 0
    return {
        'verified': True,
        'scenario_scope': 'synthetic anomalous export; not a real data breach',
        'baseline_rows': 5,
        'export_chunks': chunks,
        'rows_released_before_detection': released_before_detection,
        'blocked_chunks': 2,
        'denied_rows_released': 0,
        'control': 'Sliding-window volume guard',
    }
