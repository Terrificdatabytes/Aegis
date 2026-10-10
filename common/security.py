"""HMAC transport authentication. TLS is still required outside local demo mode."""
import hashlib
import hmac
import json
import secrets
import threading
import time
from urllib.parse import urlparse


def node_key(secret, node_id):
    return hmac.new(secret.encode(), ('cloud-demo:' + node_id).encode(), hashlib.sha256).hexdigest()


def encode(data):
    return json.dumps(data, separators=(',', ':'), sort_keys=True).encode()


def signed_headers(key, sender, method, path, body=b''):
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    message = '\n'.join([sender, method.upper(), path, stamp, nonce, hashlib.sha256(body).hexdigest()])
    signature = hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {'X-Demo-Sender': sender, 'X-Demo-Time': stamp, 'X-Demo-Nonce': nonce,
            'X-Demo-Signature': signature, 'Content-Type': 'application/json'}


class Verifier:
    def __init__(self):
        self.seen = {}
        self.lock = threading.Lock()

    def verify(self, key, request, expected_sender):
        sender = request.headers.get('X-Demo-Sender', '')
        stamp = request.headers.get('X-Demo-Time', '')
        nonce = request.headers.get('X-Demo-Nonce', '')
        signature = request.headers.get('X-Demo-Signature', '')
        try:
            if sender != expected_sender or abs(time.time() - int(stamp)) > 60 or len(nonce) != 32:
                return False
        except (ValueError, TypeError):
            return False
        message = '\n'.join([sender, request.method, request.path, stamp, nonce,
                             hashlib.sha256(request.get_data()).hexdigest()])
        expected = hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False
        with self.lock:
            self.seen = {k: v for k, v in self.seen.items() if v > time.time() - 120}
            identity = (sender, nonce)
            if identity in self.seen:
                return False
            self.seen[identity] = time.time()
        return True


def valid_agent_url(url, node_id, local=False):
    try:
        p = urlparse(url)
        if p.username or p.password or p.query or p.fragment or p.path not in ('', '/'):
            return False
        if local:
            return p.scheme == 'http' and p.hostname == '127.0.0.1' and p.port == 6100 + int(node_id.split('-')[1])
        return (p.scheme == 'https' and p.hostname and p.hostname.endswith('.trycloudflare.com')
                and p.hostname != 'trycloudflare.com' and p.port in (None, 443))
    except (ValueError, AttributeError):
        return False
