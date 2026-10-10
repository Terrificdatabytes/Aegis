"""Generate one per-node credential without putting the root secret on Colab."""
import getpass
import sys
from common.security import node_key
from common.contract import NODES
node = sys.argv[1] if len(sys.argv) > 1 else 'node-1'
if node not in NODES: raise SystemExit('Use node-1 through node-5')
secret = getpass.getpass('Master secret (hidden): ')
if len(secret) < 32: raise SystemExit('Master secret must be at least 32 characters')
print(node_key(secret, node))
