#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
stage=ENV
exec 3>/dev/ttyS0
trap 'rc=$?; if (( rc != 0 )); then printf "ISO_DIAG_FAIL %s\n" "$stage" >&3; systemctl poweroff --no-block || :; fi' EXIT
exec >/dev/null 2>&1
cd /
. /etc/os-release
[[ "$ID:$VERSION_ID:$(uname -m):$(id -u)" == ubuntu:24.04:x86_64:0 ]]
[[ $(getconf _NPROCESSORS_ONLN) == 2 ]]

stage=TOOLS
for tool in bash python3 sudo visudo chown chgrp chmod stat find mount umount findmnt id getent groupadd groupdel useradd userdel runuser ip getfacl pgrep timeout lsblk sha256sum systemctl; do
  command -v "$tool" >/dev/null
done
visudo -c

stage=NETWORK
links=$(ls -1 /sys/class/net)
routes4=$(ip -4 route show table all)
routes6=$(ip -6 route show table all)
[[ $links == lo ]]
for routes in "$routes4" "$routes6"; do
  while IFS= read -r route; do
    [[ -z $route || ( $route != default* && " $route " == *" dev lo "* ) ]]
  done <<< "$routes"
done

stage=DEVICES
python3 -I - <<'PY'
from pathlib import Path

def require(ok):
    if not ok:
        raise SystemExit(1)

# q35 onboard chipset + one virtio disk. A newly enumerated PCI device
# outside this exact inventory requires review of the image and machine.
pci = []
for device in Path('/sys/bus/pci/devices').iterdir():
    pci.append(tuple((device / field).read_text().strip()
                     for field in ('vendor', 'device', 'class')))
fixed = [('0x8086', '0x29c0', '0x060000'), ('0x8086', '0x2918', '0x060100'),
         ('0x8086', '0x2922', '0x010601'), ('0x8086', '0x2930', '0x0c0500')]
require(any(sorted(pci) == sorted(fixed + [('0x1af4', disk, '0x010000')])
            for disk in ('0x1001', '0x1042')))
for path in ('/sys/bus/usb/devices', '/sys/bus/virtio/drivers/virtio_console',
             '/sys/bus/virtio/drivers/vmw_vsock_virtio_transport'):
    p = Path(path)
    if p.is_dir():
        require(not any(child.is_symlink() for child in p.iterdir()
                        if child.name not in ('module',)))
for path in ('/dev/virtio-ports', '/dev/vsock', '/run/docker.sock', '/var/run/docker.sock'):
    p = Path(path)
    require(not p.exists() and not p.is_symlink())
# Reject network/shared or unexpected filesystem types anywhere in the mount table.
allowed = {'sysfs', 'proc', 'udev', 'devtmpfs', 'tmpfs', 'devpts', 'cgroup2',
           'pstore', 'securityfs', 'debugfs', 'tracefs', 'configfs', 'bpf',
           'hugetlbfs', 'mqueue', 'autofs', 'fusectl', 'binfmt_misc', 'ramfs',
           'efivarfs', 'ext4', 'vfat', 'iso9660'}
mounts = Path('/proc/self/mountinfo').read_text().splitlines()
require(bool(mounts))
require(all(line.split(' - ', 1)[1].split()[0] in allowed for line in mounts))
PY
agents=$(systemctl list-units --all --no-legend --no-pager 'qemu-guest-agent*' 'spice-vdagent*')
agent_files=$(systemctl list-unit-files --no-legend --no-pager 'qemu-guest-agent*' 'spice-vdagent*')
[[ -z $agents && -z $agent_files ]]
blocks=$(lsblk --nodeps --noheadings --raw --output NAME,TYPE,RO)
[[ $(printf '%s\n' "$blocks" | sort) == $'sr0 rom 1\nvda disk 0' ]]
[[ $(findmnt -n -o FSTYPE --mountpoint /run) == tmpfs ]]
[[ ! -L /run && $(stat -c '%u:%g:%a' /run) == 0:0:755 ]]

stage=ISO
media=/media/ha-iso-readiness
mkdir -- "$media"
mount -t iso9660 -o ro,nodev,nosuid,noexec /dev/sr0 "$media"
options=$(findmnt -n -o SOURCE,FSTYPE,OPTIONS --mountpoint "$media")
read -r source fstype flags <<< "$options"
[[ $source == /dev/sr0 && $fstype == iso9660 ]]
for flag in ro nodev nosuid noexec; do [[ ,$flags, == *",$flag,"* ]]; done
[[ $(ls -1A "$media") == $'meta-data\nnetwork-config\nneutral.txt\nuser-data' ]]
iso_hash=$(sha256sum /dev/sr0)
iso_hash=${iso_hash%% *}
manifest() { (cd "$media" && sha256sum meta-data network-config neutral.txt user-data); }
files=$(manifest)
files_hash=$(printf '%s\n' "$files" | sha256sum)
files_hash=${files_hash%% *}
python3 -I - "$media" <<'PY'
import errno
import os
import sys

fd = os.open(sys.argv[1], os.O_DIRECTORY | os.O_NOFOLLOW)
# No truncation even if misconfigured. The disposable probe must be absent.
for name, flags in [('neutral.txt', os.O_WRONLY),
                    ('unexpected-write-probe', os.O_WRONLY | os.O_CREAT | os.O_EXCL)]:
    try:
        handle = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise SystemExit(1)
    else:
        os.close(handle)
        raise SystemExit(1)
os.close(fd)
PY
[[ $(manifest) == "$files" ]]
umount "$media"
rmdir -- "$media"

stage=IDENTITY
[[ $(getent -s files passwd 65534) == nobody:*:65534:* ]]
absent() {
  local rc=0
  getent "$1" "$2" || rc=$?
  [[ $rc == 2 ]]
}
for name in qa 20000 20001; do absent passwd "$name"; done
for name in qa docker 20000 20001; do absent group "$name"; done
entry=$(getent passwd 65534)
[[ $entry == nobody:*:65534:* && $(id -u nobody) == 65534 ]]
groupadd -g 20000 qa
groupadd -g 20001 docker
useradd -M -d /nonexistent -s /usr/sbin/nologin -u 20000 -g qa -G docker qa
[[ $(runuser -u qa -- id -u) == 20000 ]]
[[ $(runuser -u qa -- id -g) == 20000 ]]
[[ $(runuser -u qa -- id -G) == '20000 20001' ]]
userdel qa
groupdel docker
groupdel qa
absent passwd 20000
absent passwd qa
absent group 20000
absent group 20001
absent group qa
absent group docker

stage=SHUTDOWN
printf 'ISO_DIAG_OK ubuntu=24.04 arch=x86_64 network=loopback devices=expected readonly=erofs uid_gid=verified iso=%s files=%s\n' "$iso_hash" "$files_hash" >&3
systemctl poweroff --no-block
