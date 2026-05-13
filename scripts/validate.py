import sys
from pathlib import Path

if not Path('web/db/index.json').exists():
    print('missing index.json')
    sys.exit(1)

print('ok')
