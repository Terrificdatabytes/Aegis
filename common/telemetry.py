"""Versioned, bounded resource measurements. Values are observations, not alerts."""
import math
from datetime import datetime
from common.contract import NODES

FIELDS = ['cpu_percent', 'ram_percent', 'ram_used_bytes', 'ram_total_bytes',
          'process_cpu_percent', 'process_rss_bytes', 'cpu_count']


def validate_sample(data):
    if not isinstance(data, dict) or data.get('node_id') not in NODES:
        raise ValueError('Invalid telemetry node')
    if data.get('scope') != 'runtime-host':
        raise ValueError('Invalid telemetry scope')
    try:
        stamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        if stamp.tzinfo is None: raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError('Invalid telemetry timestamp')
    for field in FIELDS:
        value = data.get(field)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('Invalid ' + field)
    if data['cpu_percent'] > 100 or data['ram_percent'] > 100:
        raise ValueError('Utilization outside 0–100')
    if type(data['cpu_count']) is not int or not 1 <= data['cpu_count'] <= 65536 or data['ram_used_bytes'] > data['ram_total_bytes'] or data['ram_total_bytes'] <= 0:
        raise ValueError('Invalid capacity')
    if data['process_cpu_percent'] > data['cpu_count'] * 100 + 1:
        raise ValueError('Invalid process CPU')
    return {k: data[k] for k in FIELDS + ['node_id', 'timestamp', 'scope']}
