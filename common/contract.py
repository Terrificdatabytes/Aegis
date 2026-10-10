from datetime import datetime, timezone

NODES = ['node-' + str(i) for i in range(1, 6)]
SCENARIOS = ['data_breach', 'identity_attack', 'virtualization_threat']
STAGES = ['detected', 'analyzing', 'prevented']


def now():
    return datetime.now(timezone.utc).isoformat()


def validate_event(data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    if data.get('node_id') not in NODES:
        raise ValueError('Unknown node')
    if data.get('event_type') not in SCENARIOS + ['heartbeat']:
        raise ValueError('Unknown event type')
    if data.get('stage') not in STAGES:
        raise ValueError('Invalid stage')
    if data.get('severity') not in ['low', 'medium', 'high', 'critical']:
        raise ValueError('Invalid severity')
    for field in ['detail', 'control_applied']:
        if not isinstance(data.get(field), str) or not 1 <= len(data[field]) <= 1000:
            raise ValueError('Invalid ' + field)
    try:
        parsed = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('Timezone required')
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError('Invalid ISO8601 timestamp')
    if 'source_node' in data and data['source_node'] not in NODES:
        raise ValueError('Invalid source_node')
    for field in ['incident_id', 'event_id', 'run_id']:
        if field in data and (not isinstance(data[field], str) or len(data[field]) > 100):
            raise ValueError('Invalid ' + field)
    return data
