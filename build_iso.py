"""Build one neutral NoCloud ISO and verify what the ISO actually contains."""
import base64
import hashlib
import inspect
import re
from pathlib import Path
import subprocess

ACL_VERSION = '2.3.2-1build1.1'
ACL_FILE = 'acl.deb'
ISO_LIMIT = 2 * 1024**2
FILES = (ACL_FILE, 'meta-data', 'network-config', 'neutral.txt', 'user-data')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_dependencies(expression, installed, compare):
    if not expression.strip():
        return
    for clause in expression.split(','):
        satisfied = False
        for alternative in clause.split('|'):
            match = re.fullmatch(
                r'\s*([a-z0-9][a-z0-9+.-]*)(?::(amd64|any|native))?'
                r'(?:\s*\((<<|<=|=|>=|>>)\s*([^\s()]+)\))?\s*', alternative)
            if match is None:
                raise ValueError('unsupported dependency syntax')
            name, qualifier, operator, required = match.groups()
            version = installed(name)
            if version is not None and (operator is None or compare(version, operator, required)):
                satisfied = True
        if not satisfied:
            raise ValueError('unsatisfied dependency')


def manifest_dependencies(expression, manifest, invoke=subprocess.check_output):
    packages = dict(line.split() for line in manifest.splitlines() if line.strip())

    def installed(name):
        return packages.get(name + ':amd64', packages.get(name))

    def compare(version, operator, required):
        try:
            invoke(['dpkg', '--compare-versions', version, operator, required], timeout=10)
            return True
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 1:
                raise
            return False

    check_dependencies(expression, installed, compare)


def verified_acl(metadata, package, invoke=subprocess.check_output, manifest=None):
    fields = {}
    for line in metadata.splitlines():
        match = re.fullmatch(r'(Package|Version|Architecture|SHA256|Depends|Pre-Depends): (.*)', line)
        if match:
            key, value = match.groups()
            if key in fields:
                raise ValueError('ambiguous APT package metadata')
            fields[key] = value
    with package.open('rb') as stream:
        data = stream.read(ISO_LIMIT + 1)
    if not 0 < len(data) <= ISO_LIMIT:
        raise ValueError('ACL package size mismatch')
    if {key: fields.get(key) for key in ('Package', 'Architecture', 'Version', 'SHA256')} != {
            'Package': 'acl', 'Architecture': 'amd64', 'Version': ACL_VERSION, 'SHA256': sha(data)}:
        raise ValueError('APT package metadata mismatch')
    expected = {'Package': 'acl', 'Architecture': 'amd64', 'Version': ACL_VERSION}
    for key, value in expected.items():
        if invoke(['dpkg-deb', '-f', str(package), key], timeout=10).strip() != value.encode('ascii'):
            raise ValueError('DEB metadata mismatch')
    if manifest is None:
        raise ValueError('guest package manifest required')
    for key in ('Depends', 'Pre-Depends'):
        archive = invoke(['dpkg-deb', '-f', str(package), key], timeout=10).decode().strip()
        if archive != fields.get(key, ''):
            raise ValueError('dependency metadata mismatch')
        manifest_dependencies(archive, manifest, invoke)
    return data


def contents(guest, acl):
    guest = guest.replace(b'@ACL_SHA256@', sha(acl).encode('ascii'))
    guest = guest.replace(b'@ACL_VERSION@', ACL_VERSION.encode('ascii'))
    guest = guest.replace(b'@DEPENDENCY_CHECK@', inspect.getsource(check_dependencies).encode('ascii'))
    encoded = base64.b64encode(guest).decode('ascii')
    return {
        ACL_FILE: acl,
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


def build(work, guest, acl, invoke=subprocess.check_output):
    payload = contents(guest, acl)
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
    if not 0 < len(data) <= ISO_LIMIT or len(data) % 2048:
        raise ValueError('ISO size mismatch')
    manifest = ''.join(f'{sha(payload[name])}  {name}\n' for name in FILES).encode('ascii')
    iso.rename(work / 'seed.iso')
    (work / 'seed.iso').chmod(0o400)
    return sha(data), sha(manifest)
