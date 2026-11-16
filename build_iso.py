"""Build one neutral NoCloud ISO and verify what the ISO actually contains."""
import base64
import hashlib
from pathlib import Path
import subprocess

FILES = ('meta-data', 'network-config', 'neutral.txt', 'user-data')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def contents(guest):
    encoded = base64.b64encode(guest).decode('ascii')
    return {
        'meta-data': b'instance-id: iid-neutral-iso-readiness\nlocal-hostname: iso-readiness\n',
        'network-config': b'config: disabled\n',
        'neutral.txt': b'Neutral offline ISO readiness probe v1\n',
        'user-data': f'''#cloud-config
users: []
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false
write_files:
  - path: /run/neutral-iso-readiness.sh
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: {encoded}
runcmd:
  - [/bin/bash, /run/neutral-iso-readiness.sh]
'''.encode('ascii'),
    }


def build(work, guest, invoke=subprocess.check_output):
    payload = contents(guest)
    seed = work / 'seed'
    seed.mkdir(mode=0o700)
    for name in FILES:
        (seed / name).write_bytes(payload[name])
    invoke(['genisoimage', '-quiet', '-output', 'seed.iso', '-volid', 'cidata',
            '-rock', *FILES], cwd=seed, stderr=subprocess.DEVNULL, timeout=30)
    iso = seed / 'seed.iso'
    listing = invoke(['isoinfo', '-R', '-i', str(iso), '-f'], timeout=10)
    if sorted(listing.splitlines()) != sorted(f'/{name}'.encode() for name in FILES):
        raise ValueError('ISO inventory mismatch')
    for name in FILES:
        actual = invoke(['isoinfo', '-R', '-i', str(iso), '-x', f'/{name}'], timeout=10)
        if actual != payload[name]:
            raise ValueError('ISO payload mismatch')
    data = iso.read_bytes()
    if not 0 < len(data) <= 2 * 1024**2 or len(data) % 2048:
        raise ValueError('ISO size mismatch')
    manifest = ''.join(f'{sha(payload[name])}  {name}\n' for name in FILES).encode('ascii')
    iso.rename(work / 'seed.iso')
    (work / 'seed.iso').chmod(0o400)
    return sha(data), sha(manifest)
