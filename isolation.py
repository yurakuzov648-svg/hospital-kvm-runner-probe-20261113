"""Allowlisted QEMU configuration and bounded, exact serial evidence."""
import re

QEMU = '/usr/bin/qemu-system-x86_64'


def qemu_args():
    # No host paths other than the two local disk backends.
    return [QEMU, '-no-user-config', '-nodefaults', '-machine', 'q35,usb=off',
            '-accel', 'kvm', '-cpu', 'host', '-smp', '2', '-m', '2048',
            '-nic', 'none', '-display', 'none', '-monitor', 'none',
            '-parallel', 'none', '-serial', 'stdio', '-no-reboot',
            '-drive', 'file=guest.img,if=virtio,format=qcow2',
            '-drive', 'file=seed.iso,media=cdrom,format=raw,readonly=on']


def verify_launch(actual):
    if actual != qemu_args():
        raise ValueError('unexpected QEMU argv')


def verify_serial(data, iso_hash, files_hash):
    marker = ('ISO_DIAG_OK ubuntu=24.04 arch=x86_64 network=loopback '
              'devices=expected readonly=erofs uid_gid=verified '
              f'iso={iso_hash} files={files_hash}').encode('ascii')
    lines = data.splitlines()
    candidates = [(i, line) for i, line in enumerate(lines)
                  if line.startswith((b'ISO_DIAG_OK', b'ISO_DIAG_FAIL'))]
    if len(candidates) != 1:
        return None
    index, line = candidates[0]
    if line != marker:
        if re.fullmatch(rb'ISO_DIAG_FAIL (ENV|TOOLS|TOOLS_MISSING|TOOLS_VISUDO|ACL_BOOTSTRAP|NETWORK|DEVICES|ISO|IDENTITY|SHUTDOWN)', line):
            return line
        return None
    shutdowns = [i for i, value in enumerate(lines)
                 if re.fullmatch(rb'\[\s*[0-9]+\.[0-9]+\] reboot: Power down', value)]
    return marker if len(shutdowns) == 1 and shutdowns[0] > index else None
