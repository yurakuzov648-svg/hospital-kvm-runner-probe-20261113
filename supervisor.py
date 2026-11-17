from __future__ import annotations
from contextlib import ExitStack
from dataclasses import dataclass
import os
import errno
import pathlib
import re
import secrets
import select
import signal
import stat
import sys
import time

from isolation import qemu_args, verify_launch, verify_serial
from build_iso import sha

BUDGET = 1200
FINALIZATION_RESERVE = 30
STOP_REMAINING = 20
SERIAL_REMAINING = 13
CLEANUP_REMAINING = 2
REAP_REMAINING = 1
CLEANUP_STOP_RESERVE = 3
TERM_GRACE = 5
CLEANUP_TERM_GRACE = 1
SERIAL_LIMIT = 8 * 1024 * 1024
SERIAL_CHUNK = 64 * 1024
RMDIR = '/usr/bin/rmdir' if sys.platform.startswith('linux') else '/bin/rmdir'
RM = '/usr/bin/rm' if sys.platform.startswith('linux') else '/bin/rm'
POLL_INTERVAL = 0.05
BOOT_FAILED = 20
INCOMPLETE = 21
DEADLINE_EXCEEDED = 22
STOP_UNCONFIRMED = 23
SERIAL_LIMIT_EXCEEDED = 24
CLEANUP_UNCONFIRMED = 25
OWNERSHIP_BLOCKED = 26
CANCEL_SIGNALS = {signal.SIGTERM, signal.SIGINT}
cancelled = False
cancel_signal = None


def cancel(signum, frame):
    global cancelled, cancel_signal
    cancelled = True
    if cancel_signal is None:
        cancel_signal = signum


class Child:
    """An unreaped direct child owns its PID and isolated process group."""

    def __init__(self, task, close_fds=()):
        self.rc = None
        self.control_lost = False
        self.usage = None
        self.observed_at = None
        self.pid = os.fork()
        self.pgid = self.pid
        if self.pid == 0:
            try:
                for fd in close_fds:
                    os.close(fd)
                os.setsid()
                for signum in CANCEL_SIGNALS:
                    signal.signal(signum, signal.SIG_DFL)
                with open(os.devnull, 'r+b', buffering=0) as sink:
                    for fd in (0, 1, 2):
                        os.dup2(sink.fileno(), fd)
                code = task()
            except OSError as exc:
                code = exc.errno if 0 < (exc.errno or 0) < 125 else 125
            except BaseException:
                code = 125
            os._exit(code)

    def poll(self):
        if self.rc is None:
            try:
                pid, status, usage = os.wait4(self.pid, os.WNOHANG)
            except OSError as exc:
                if exc.errno == errno.ECHILD:
                    self.control_lost = True
                raise
            if pid:
                self.observed_at = time.monotonic()
                self.rc = os.waitstatus_to_exitcode(status)
                self.usage = usage
        return self.rc

    def send(self, signum):
        # Never signal a reaped PID. Before setsid(), signal the child itself.
        if self.rc is not None or self.control_lost:
            return
        try:
            os.killpg(self.pgid, signum)
        except ProcessLookupError:
            try:
                os.kill(self.pid, signum)
            except ProcessLookupError:
                pass


def wait_child(child, limit, honor_cancel=False):
    while time.monotonic() < limit:
        if honor_cancel and cancelled:
            return None
        rc = child.poll()
        if rc is not None:
            return rc if child.observed_at < limit else None
        time.sleep(max(0, min(POLL_INTERVAL, limit - time.monotonic())))
    return None


def stop_child(child, limit, grace=TERM_GRACE):
    try:
        child.send(signal.SIGTERM)
        rc = wait_child(child, min(limit, time.monotonic() + grace))
        if rc is not None:
            return rc
    except (OSError, ChildProcessError):
        pass
    try:
        child.send(signal.SIGKILL)
        return wait_child(child, limit)
    except (OSError, ChildProcessError):
        return None


def run_phase(task, cutoff, reap_limit, close_fds=()):
    if time.monotonic() >= cutoff:
        return None, True
    child = Child(task, close_fds)
    rc = wait_child(child, cutoff)
    if rc is not None:
        return rc, True
    if child.rc is None:
        child.send(signal.SIGKILL)
        wait_child(child, reap_limit)
    # Late evidence cannot pass the phase, but still confirms reaping.
    return None, child.rc is not None


def collect_serial(child, fd, cutoff):
    data = bytearray()
    eof = False
    os.set_blocking(fd, False)
    while not cancelled and time.monotonic() < cutoff:
        rc = child.poll()
        if rc is not None and child.observed_at >= cutoff:
            break
        if eof:
            if rc is not None:
                return (rc if time.monotonic() < cutoff else None), data, False
            time.sleep(max(0, min(POLL_INTERVAL, cutoff - time.monotonic())))
            continue
        ready, _, _ = select.select([fd], [], [], max(0, min(POLL_INTERVAL, cutoff - time.monotonic())))
        if ready:
            try:
                chunk = os.read(fd, min(SERIAL_CHUNK, SERIAL_LIMIT - len(data) + 1))
            except BlockingIOError:
                continue
            if len(chunk) > SERIAL_LIMIT - len(data):
                return None, data, True
            data.extend(chunk)
            eof = not chunk
    return None, data, False


class ControlBlocked(Exception):
    pass


def directory_fd(path, dir_fd=None):
    return os.open(path, getattr(os, 'O_PATH', os.O_RDONLY) |
                   os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def checked_directory(path, *, private, dir_fd=None):
    try:
        if not os.path.isabs(path) or str(pathlib.Path(path).resolve(strict=True)) != path:
            raise ControlBlocked('parent_noncanonical_path')
        entry = os.lstat(path)
        if not stat.S_ISDIR(entry.st_mode):
            raise ControlBlocked('parent_invalid_type')
        name = path if dir_fd is None else os.path.basename(path)
        fd = directory_fd(name, dir_fd)
        try:
            require_directory_identity(path, fd, private)
        except BaseException:
            os.close(fd)
            raise
        return fd
    except OSError:
        raise ControlBlocked('parent_access_error') from None


def require_directory_identity(path, fd, private):
    info = os.fstat(fd)
    entry = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or not stat.S_ISDIR(entry.st_mode):
        raise ControlBlocked('parent_invalid_type')
    if info.st_uid != os.geteuid():
        raise ControlBlocked('parent_unexpected_owner')
    mode = stat.S_IMODE(info.st_mode)
    if (private and mode != 0o700) or (not private and (mode & 0o7022 or mode & 0o300 != 0o300)):
        raise ControlBlocked('parent_unsafe_mode')
    if not os.path.samestat(info, entry):
        raise ControlBlocked('parent_inode_mismatch')
    return info


def identity_token(info):
    return f'{info.st_dev}:{info.st_ino}'


def mountinfo_point(line):
    before, separator, after = line.partition(b' - ')
    fields = before.split(b' ')
    filesystem = after.split(b' ')
    if (not separator or len(fields) < 6 or len(filesystem) != 3 or
            not all(fields) or not all(filesystem) or b'\0' in line or b'\t' in line or
            not fields[0].isdigit() or not fields[1].isdigit() or
            not re.fullmatch(rb'[0-9]+:[0-9]+', fields[2])):
        raise ControlBlocked('mount_inventory_unavailable')
    for field in (fields[5], filesystem[2]):
        options = field.split(b',')
        if options[0] not in (b'ro', b'rw') or not all(options):
            raise ControlBlocked('mount_inventory_unavailable')

    root, mount = fields[3:5]
    for path in (root, mount):
        if not path.startswith(b'/') or re.search(rb'\\(?!040|011|012|134)', path):
            raise ControlBlocked('mount_inventory_unavailable')
    # Decode exactly once: an escaped backslash can precede literal digits.
    return re.sub(rb'\\(040|011|012|134)',
                  lambda match: bytes([int(match[1], 8)]), mount)


def require_no_workspace_mounts(work):
    # Includes bind mounts, even when st_dev is shared with the parent.
    prefix = os.fsencode(work)
    with open('/proc/self/mountinfo', 'rb') as mounts:
        inventory = mounts.read()
    if not inventory.endswith(b'\n'):
        raise ControlBlocked('mount_inventory_unavailable')
    for line in inventory[:-1].split(b'\n'):
        mount = mountinfo_point(line)
        if mount == prefix or mount.startswith(prefix + b'/'):
            raise ControlBlocked('unexpected_workspace_mount')


def rollback_empty(base, base_fd, created):
    for path, identity in reversed(created):
        if identity is None:
            return False
        with ExitStack() as descriptors:
            fd = checked_directory(path, private=True)
            descriptors.callback(os.close, fd)
            require_directory_identity(base, base_fd, private=False)
            parent, parent_identity = created[0]
            if (not os.path.samestat(parent_identity, os.lstat(parent)) or
                    not os.path.samestat(identity, os.fstat(fd))):
                return False
            require_no_workspace_mounts(created[0][0])
            os.rmdir(path)
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                return False
            current = os.fstat(fd)
            if not os.path.samestat(identity, current) or current.st_nlink != 0:
                return False
    return True


def create_workspace(descriptors, log):
    base = os.environ.get('RUNNER_TEMP', '')
    name = 'offline-iso-readiness.' + secrets.token_hex(8)
    parent = os.path.join(base, name)
    work = os.path.join(parent, 'vm')
    created = []
    base_fd = checked_directory(base, private=False)
    descriptors.callback(os.close, base_fd)
    try:
        for path, owner_fd in ((parent, base_fd), (work, None)):
            owner_fd = parent_fd if owner_fd is None else owner_fd
            if cancelled:
                raise ControlBlocked('workspace_create_cancelled')
            basename = os.path.basename(path)
            os.mkdir(basename, 0o700, dir_fd=owner_fd)
            created.append((path, None))
            identity = os.stat(basename, dir_fd=owner_fd, follow_symlinks=False)
            created[-1] = path, identity
            fd = checked_directory(path, private=True, dir_fd=owner_fd)
            descriptors.callback(os.close, fd)
            if not os.path.samestat(identity, os.fstat(fd)):
                raise ControlBlocked('parent_inode_mismatch')
            if path == parent:
                parent_fd, parent_identity = fd, identity
            require_no_workspace_mounts(parent)
        if cancelled:
            raise ControlBlocked('workspace_create_cancelled')
        return work, (fd, parent_fd, identity, parent_identity, base_fd)
    except (OSError, ControlBlocked) as exc:
        try:
            confirmed = rollback_empty(base, base_fd, created)
        except (OSError, ControlBlocked):
            confirmed = False
        log.append('BOOTSTRAP_ROLLBACK=' + ('confirmed' if confirmed else 'unconfirmed'))
        if not confirmed:
            log.append('CLEANUP_STATUS=unconfirmed REASON=bootstrap_rollback')
        if isinstance(exc, ControlBlocked):
            raise
        log.append(f'BOOTSTRAP_ERRNO={exc.errno if isinstance(exc.errno, int) and 0 < exc.errno < 256 else 0}')
        raise ControlBlocked('workspace_create_error') from None


def pin_work(name, parent_token, work_token, descriptors):
    if not re.fullmatch(r'offline-iso-readiness\.[0-9a-f]{16}', name):
        raise ControlBlocked('unsafe_work_path')
    base = os.environ.get('RUNNER_TEMP', '')
    base_fd = checked_directory(base, private=False)
    descriptors.callback(os.close, base_fd)
    parent = os.path.join(base, name)
    parent_fd = checked_directory(parent, private=True, dir_fd=base_fd)
    descriptors.callback(os.close, parent_fd)
    parent_identity = os.fstat(parent_fd)
    if identity_token(parent_identity) != parent_token:
        raise ControlBlocked('parent_inode_mismatch')
    work = os.path.join(parent, 'vm')
    fd = checked_directory(work, private=True, dir_fd=parent_fd)
    descriptors.callback(os.close, fd)
    identity = os.fstat(fd)
    if identity_token(identity) != work_token:
        raise ControlBlocked('unsafe_work_identity')
    require_no_workspace_mounts(parent)
    return work, (fd, parent_fd, identity, parent_identity, base_fd)


def recheck_workspace(work, pinned):
    fd, parent_fd, identity, parent_identity, base_fd = pinned
    parent = os.path.dirname(work)
    base = os.path.dirname(parent)
    if str(pathlib.Path(parent).resolve(strict=True)) != parent:
        raise ControlBlocked('parent_noncanonical_path')
    base_identity = require_directory_identity(base, base_fd, private=False)
    if not os.path.samestat(parent_identity, require_directory_identity(parent, parent_fd, private=True)):
        raise ControlBlocked('parent_inode_mismatch')
    if (not os.path.samestat(identity, os.fstat(fd)) or
            not os.path.samestat(identity, os.lstat(work))):
        raise ControlBlocked('work_path_changed')
    require_no_workspace_mounts(parent)
    return base_identity


def clean_work(work, pinned, cutoff, verify_limit, log):
    fd, parent_fd, identity, parent_identity, base_fd = pinned
    parent = os.path.dirname(work)
    base = os.path.dirname(parent)
    close_fds = (fd, parent_fd, base_fd)
    run_limit = cutoff - CLEANUP_STOP_RESERVE
    if time.monotonic() >= run_limit:
        log.append('CLEANUP_STATUS=unconfirmed REASON=budget_before_rm')
        return DEADLINE_EXCEEDED

    def remove():
        os.chdir('/')
        if (not os.path.samestat(base_identity, os.lstat(base)) or
                not os.path.samestat(parent_identity, os.lstat(os.path.dirname(work))) or
                not os.path.samestat(identity, os.lstat(work))):
            return 126
        require_no_workspace_mounts(parent)
        os.execve(RM, ['rm', '-rf', '--one-file-system', '--', work], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

    try:
        base_identity = recheck_workspace(work, pinned)
        if time.monotonic() >= run_limit:
            log.append('CLEANUP_STATUS=unconfirmed REASON=budget_before_rm')
            return DEADLINE_EXCEEDED
        rm = Child(remove, close_fds)
        try:
            rc = wait_child(rm, run_limit)
        except (OSError, ChildProcessError):
            rc = None
        if rc is None:
            if rm.rc is None:
                stop_child(rm, cutoff, CLEANUP_TERM_GRACE)
            reap = 'confirmed' if rm.rc is not None else 'unconfirmed'
            log.append(f'CLEANUP_STATUS=unconfirmed REASON=rm_budget RM_REAP={reap}')
            if rm.rc is not None:
                log.append(f'RM_EXIT_CODE={rm.rc}')
            return DEADLINE_EXCEEDED if rm.rc is not None else CLEANUP_UNCONFIRMED
        log.append(f'RM_EXIT_CODE={rc} RM_REAP=confirmed')
        if rc != 0:
            log.append('CLEANUP_STATUS=unconfirmed REASON=rm_exit')
            return INCOMPLETE

        def verify_absent():
            try:
                os.lstat(work)
            except FileNotFoundError:
                return 0
            return 126

        rc, _ = run_phase(verify_absent, cutoff, verify_limit, close_fds)
        if rc != 0:
            log.append('CLEANUP_STATUS=unconfirmed REASON=absence_check')
            return DEADLINE_EXCEEDED if rc is None else INCOMPLETE
        current = os.fstat(fd)
        if not os.path.samestat(identity, current) or current.st_nlink != 0:
            log.append('CLEANUP_STATUS=unconfirmed REASON=original_inode_retained')
            return INCOMPLETE
        if time.monotonic() >= cutoff:
            log.append('CLEANUP_STATUS=unconfirmed REASON=identity_check_budget')
            return DEADLINE_EXCEEDED

        def remove_parent():
            if (not os.path.samestat(base_identity, os.lstat(base)) or
                    not os.path.samestat(parent_identity, os.lstat(parent))):
                return 126
            require_no_workspace_mounts(parent)
            # The executable itself atomically refuses nonempty directories.
            os.execve(RMDIR, ['rmdir', '--', parent], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

        # Keep rm's existing cutoffs. An rm that consumes the reserve cannot pass.
        parent_limit = cutoff - 1.0
        if time.monotonic() >= parent_limit:
            log.append('CLEANUP_STATUS=unconfirmed REASON=rmdir_budget_before_start')
            return DEADLINE_EXCEEDED
        rmdir = Child(remove_parent, close_fds)
        try:
            rc = wait_child(rmdir, parent_limit)
        except (OSError, ChildProcessError):
            rc = None
        if rc is None:
            if rmdir.rc is None:
                stop_child(rmdir, cutoff, grace=0.35)
            reap = 'confirmed' if rmdir.rc is not None else 'unconfirmed'
            log.append(f'CLEANUP_STATUS=unconfirmed REASON=rmdir_budget RMDIR_REAP={reap}')
            if rmdir.rc is not None:
                log.append(f'RMDIR_EXIT_CODE={rmdir.rc}')
            return DEADLINE_EXCEEDED if rmdir.rc is not None else CLEANUP_UNCONFIRMED
        log.append(f'RMDIR_EXIT_CODE={rc} RMDIR_REAP=confirmed')
        if rc != 0:
            log.append('CLEANUP_STATUS=unconfirmed REASON=parent_remove_error')
            return INCOMPLETE
        def verify_parent_absent():
            try:
                os.lstat(parent)
            except FileNotFoundError:
                return 0
            return 126

        rc, _ = run_phase(verify_parent_absent, cutoff, verify_limit, close_fds)
        if rc != 0:
            log.append('CLEANUP_STATUS=unconfirmed REASON=parent_path_retained')
            return DEADLINE_EXCEEDED if rc is None else INCOMPLETE
        current = os.fstat(parent_fd)
        if not os.path.samestat(parent_identity, current) or current.st_nlink != 0:
            log.append('CLEANUP_STATUS=unconfirmed REASON=parent_inode_retained')
            return INCOMPLETE
        if time.monotonic() >= cutoff:
            log.append('CLEANUP_STATUS=unconfirmed REASON=identity_check_budget')
            return DEADLINE_EXCEEDED
        log.append('WORKSPACE_PARENT_REMOVAL=confirmed')
    except ControlBlocked as exc:
        log.append(f'CLEANUP_STATUS=unconfirmed REASON={exc.args[0]}')
        return OWNERSHIP_BLOCKED
    except (OSError, ChildProcessError):
        log.append('CLEANUP_STATUS=unconfirmed REASON=supervision_error')
        return CLEANUP_UNCONFIRMED
    log.append('CLEANUP=confirmed')
    return 0


def supervise(work, iso_hash, files_hash, started, deadline, log, pinned):
    boot_limit = deadline - FINALIZATION_RESERVE
    stop_limit = deadline - STOP_REMAINING
    serial_limit = deadline - SERIAL_REMAINING
    cleanup_limit = deadline - CLEANUP_REMAINING
    reap_limit = deadline - REAP_REMAINING

    close_fds = (*pinned[:2], pinned[4])

    code = INCOMPLETE
    overflow = False
    data = b''
    if not cancelled and time.monotonic() < boot_limit:
        read_fd, write_fd = os.pipe()

        def boot():
            os.close(read_fd)
            os.dup2(write_fd, 1)
            os.close(write_fd)
            os.chdir(work)
            if sha(pathlib.Path('seed.iso').read_bytes()) != iso_hash:
                return INCOMPLETE
            argv = qemu_args()
            verify_launch(argv)
            os.execve(argv[0], argv, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

        try:
            try:
                qemu = Child(boot, close_fds)
            finally:
                os.close(write_fd)
            log.append('QEMU_CONFIG=fixed_kvm_no_nic_single_disk_readonly_iso')
            try:
                qemu_rc, data, overflow = collect_serial(qemu, read_fd, boot_limit)
            except (OSError, ChildProcessError, ValueError):
                log.append('SERIAL_STATUS=read_error')
                qemu_rc = None
            if overflow:
                log.append('SERIAL_LIMIT_EXCEEDED')
        finally:
            os.close(read_fd)
        if qemu_rc is None:
            log.append('QEMU_BOOT=not_confirmed_before_cutoff')
            if qemu.rc is None:
                log.append('QEMU_STOP=requested')
                qemu_rc = stop_child(qemu, stop_limit)
            else:
                qemu_rc = qemu.rc if qemu.observed_at < stop_limit else None
            if qemu_rc is None:
                # One final nonblocking observation distinguishes a
                # late reap from a process whose stop is still unknown.
                try:
                    qemu_rc = qemu.poll()
                except (OSError, ChildProcessError):
                    pass
                if qemu_rc is None:
                    log.append('CLEANUP_STATUS=unconfirmed QEMU_REAP=unconfirmed')
                    return STOP_UNCONFIRMED
                log.append('QEMU_STOP_BUDGET=exceeded QEMU_REAP=confirmed_late')
                code = STOP_UNCONFIRMED
            else:
                code = SERIAL_LIMIT_EXCEEDED if overflow else (INCOMPLETE if cancelled else BOOT_FAILED)
        else:
            code = 0 if qemu_rc == 0 else BOOT_FAILED
        log.append(f'QEMU_EXIT_CODE={qemu_rc} QEMU_REAP=confirmed VM_WALL_SECONDS={time.monotonic() - started:.3f}')
        log.append(f'QEMU_PEAK_RSS_KIB={qemu.usage.ru_maxrss}')

    if code == 0 and not cancelled:
        read_fd, write_fd = os.pipe()
        try:
            def serial():
                evidence = verify_serial(data, iso_hash, files_hash)
                if evidence is None:
                    return BOOT_FAILED
                return 0 if os.write(write_fd, evidence) == len(evidence) else INCOMPLETE

            rc, reaped = run_phase(serial, serial_limit, serial_limit + REAP_REMAINING, close_fds)
            if rc is None:
                log.append('VM_DEADLINE=serial_budget_exhausted')
                if not reaped:
                    log.append('CLEANUP_STATUS=unconfirmed')
                    return DEADLINE_EXCEEDED
                code = DEADLINE_EXCEEDED
            elif rc != 0:
                log.append(f'SERIAL_CHECK_EXIT_CODE={rc}')
                code = BOOT_FAILED
            else:
                # Child is reaped and writes at most 512 bytes. Nonblocking
                # read also guards against an unexpected missing message.
                os.set_blocking(read_fd, False)
                try:
                    evidence = os.read(read_fd, 512)
                except BlockingIOError:
                    evidence = b''
                if evidence:
                    log.append(evidence.decode('ascii'))
                    if not evidence.startswith(b'ISO_DIAG_OK '):
                        code = BOOT_FAILED
                else:
                    code = BOOT_FAILED
        finally:
            os.close(write_fd)
            os.close(read_fd)

    cleanup_code = clean_work(work, pinned, cleanup_limit, reap_limit, log)
    if code in (STOP_UNCONFIRMED, SERIAL_LIMIT_EXCEEDED):
        return code
    return cleanup_code or code


def decide(code, started, deadline):
    signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
    # This timestamp is the decision point. The pending check may
    # conservatively include cancellation immediately after it.
    decision_at = time.monotonic()
    pending = signal.sigpending()
    interrupted = cancelled or bool(pending & CANCEL_SIGNALS)
    # Preserve the more specific unconfirmed-stop failure at the deadline.
    if code not in (STOP_UNCONFIRMED, SERIAL_LIMIT_EXCEEDED, CLEANUP_UNCONFIRMED, OWNERSHIP_BLOCKED):
        if decision_at >= deadline:
            code = DEADLINE_EXCEEDED
        elif interrupted:
            code = INCOMPLETE
    return code, decision_at - started


def publish(code, elapsed, log):
    result = {
        0: 'OFFLINE_ISO_READY',
        BOOT_FAILED: 'OFFLINE_ISO_FAILED',
        STOP_UNCONFIRMED: 'QEMU_STOP_UNCONFIRMED',
        SERIAL_LIMIT_EXCEEDED: 'SERIAL_LIMIT_EXCEEDED',
        CLEANUP_UNCONFIRMED: 'CLEANUP_UNCONFIRMED',
        OWNERSHIP_BLOCKED: 'BLOCK',
    }.get(code, 'VM_TEST_INCOMPLETE')
    preparation_failed = any(line.startswith('PREPARATION_POLICY_CODE=') for line in log)
    if preparation_failed:
        result = 'VM_TEST_INCOMPLETE'
    if code == DEADLINE_EXCEEDED and not preparation_failed:
        log.append('VM_DEADLINE=exceeded')
    log.append(f'EXIT_CODE={code} RESULT={result} elapsed_seconds={elapsed!r}')
    print('\n'.join(log), flush=True)


def run(name, iso_hash, files_hash, parent_token, work_token, started, deadline, log):
    with ExitStack() as descriptors:
        try:
            work, pinned = pin_work(name, parent_token, work_token, descriptors)
            code = supervise(work, iso_hash, files_hash, started, deadline, log, pinned)
        except ControlBlocked as exc:
            log.append(f'CLEANUP_STATUS=unconfirmed REASON={exc.args[0]}')
            code = OWNERSHIP_BLOCKED
        except (OSError, ValueError):
            log.append('CLEANUP_STATUS=unconfirmed REASON=identity_or_supervision_error')
            code = INCOMPLETE
        return decide(code, started, deadline)


@dataclass(frozen=True)
class PreparationOutcome:
    # observed_rc is wait4 evidence: negative means signal, never 128+signal.
    observed_rc: int | None
    termination: str
    policy_code: int
    cancellation: bool
    stopped: bool


def preparation_outcome(rc, stopped, *, termination=None):
    kind = termination or ('unknown' if rc is None else 'signal' if rc < 0 else 'exit')
    policy = INCOMPLETE if rc is None else (128 - rc if rc < 0 else rc)
    if not stopped and policy == 0:
        policy = INCOMPLETE
    if cancelled:
        policy = 128 + cancel_signal
    return PreparationOutcome(rc, kind, policy, cancelled, stopped)


def prepare_workspace(work, pinned, script, bundle, log):
    if cancelled:
        return preparation_outcome(None, True, termination='not_started')
    try:
        read_fd, write_fd = os.pipe()
    except OSError:
        log.append('PREPARATION_FAILURE=pipe_failed')
        return preparation_outcome(None, True, termination='not_started')

    try:
        os.set_blocking(read_fd, False)
    except OSError:
        os.close(write_fd)
        os.close(read_fd)
        log.append('PREPARATION_FAILURE=pipe_failed')
        return preparation_outcome(None, True, termination='not_started')

    def prepare():
        os.close(read_fd)
        os.chdir(work)
        os.set_inheritable(write_fd, True)
        prefix = f"printf B >&{write_fd} || exit 125; exec {write_fd}>&-\n"
        os.execve('/bin/bash', ['bash', '-c', prefix + script, 'prepare', work, bundle], os.environ)

    def outcome(rc, stopped):
        try:
            ack = os.read(read_fd, 2)
        except OSError:
            ack = b''
        if ack != b'B':
            log.append('PREPARATION_FAILURE=bash_start_unconfirmed')
            return preparation_outcome(None, stopped, termination='unknown')
        return preparation_outcome(rc, stopped)

    try:
        try:
            child = Child(prepare, (*pinned[:2], pinned[4]))
        except OSError as exc:
            log.append('PREPARATION_FAILURE=fork_failed')
            number = exc.errno
            if isinstance(number, int) and 0 < number < 256:
                log.append(f'PREPARATION_FORK_ERRNO={number}')
            return preparation_outcome(None, True, termination='not_started')
        finally:
            os.close(write_fd)
        try:
            while not cancelled:
                rc = child.poll()
                if rc is not None:
                    return outcome(rc, rc >= 0)
                time.sleep(POLL_INTERVAL)
            # Only a cooperative normal shell exit attests foreground quiescence.
            if child.rc is None:
                os.kill(child.pid, cancel_signal)
            rc = wait_child(child, time.monotonic() + 5)
            if rc is not None and rc >= 0:
                return outcome(rc, True)
        except (OSError, ChildProcessError):
            log.append('PREPARATION_FAILURE=observation_error')
        # Best effort stop; forced stop never grants rollback.
        stop_child(child, time.monotonic() + 2, grace=0.5)
        log.append('CLEANUP_STATUS=unconfirmed REASON=preparation_stop')
        return outcome(child.rc, False)
    finally:
        os.close(read_fd)


PREPARATION_FIELDS = (
    'QEMU_VERSION', 'KVM_API_VERSION', 'VERIFIED_IMAGE_SHA256',
    'HOST_ISO_SHA256', 'HOST_FILE_MANIFEST_SHA256',
)
PREPARATION_RECEIPT = re.compile(
    rb'QEMU_VERSION=([0-9]{1,4}(?:\.[0-9]{1,4}){2}(?:-rc[0-9]{1,4})?)\n'
    rb'KVM_API_VERSION=(12)\n'
    rb'VERIFIED_IMAGE_SHA256=([0-9a-f]{64})\n'
    rb'HOST_ISO_SHA256=([0-9a-f]{64})\n'
    rb'HOST_FILE_MANIFEST_SHA256=([0-9a-f]{64})\n'
)
PREPARATION_RECEIPT_LIMIT = 384


def read_preparation_receipt(work):
    fd = os.open(os.path.join(work, 'preparation.receipt'),
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ControlBlocked('preparation_receipt_invalid')
        payload = stream.read(PREPARATION_RECEIPT_LIMIT + 1)
    match = PREPARATION_RECEIPT.fullmatch(payload)
    if len(payload) > PREPARATION_RECEIPT_LIMIT or match is None:
        raise ControlBlocked('preparation_receipt_invalid')
    return dict(zip(PREPARATION_FIELDS, (value.decode('ascii') for value in match.groups())))


PREPARATION_STAGES = frozenset({
    'disk_preflight', 'apt_update', 'apt_install', 'qemu_version', 'kvm_access',
    'image_download', 'image_signature', 'image_hash', 'image_format',
    'iso_build', 'receipt_write',
})


def failed_preparation_stage(work_fd, exit_code):
    try:
        fd = os.open('preparation.failure', os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=work_fd)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return 'unknown'
            payload = stream.read(65)
    except OSError:
        return 'unknown'
    match = re.fullmatch(rb'([a-z_]{1,32}) ([1-9][0-9]{0,2})\n', payload)
    if match is None or not 1 <= exit_code <= 255 or int(match[2]) != exit_code:
        return 'unknown'
    stage = match[1].decode('ascii')
    return stage if stage in PREPARATION_STAGES else 'unknown'


def run_workflow(script, bundle, log):
    started = time.monotonic()
    with ExitStack() as descriptors:
        try:
            work, pinned = create_workspace(descriptors, log)
        except (ControlBlocked, OSError) as exc:
            reason = exc.args[0] if isinstance(exc, ControlBlocked) else 'parent_access_error'
            log.append(f'RESULT=BLOCK REASON={reason}')
            code = 128 + cancel_signal if cancelled else OWNERSHIP_BLOCKED
            return code, time.monotonic() - started

        outcome = prepare_workspace(work, pinned, script, bundle, log)
        code = outcome.policy_code
        stage = (failed_preparation_stage(pinned[0], outcome.observed_rc)
                 if outcome.stopped and outcome.termination == 'exit' and outcome.observed_rc != 0
                 else 'unknown')
        log.append(f'PREPARATION_TERMINATION={outcome.termination}')
        if outcome.termination == 'exit':
            log.append(f'PREPARATION_EXIT_CODE={outcome.observed_rc}')
        elif outcome.termination == 'signal':
            log.append(f'PREPARATION_SIGNAL={-outcome.observed_rc}')
        if not outcome.stopped:
            if cancelled:
                code = 128 + cancel_signal
            log.append('PREPARATION_CANCELLED=' + ('yes' if cancelled else 'no'))
            log.append('PREP_STAGE=unknown')
            log.append(f'PREPARATION_POLICY_CODE={code}')
            log.append('CLEANUP_STATUS=unconfirmed REASON=preparation_stop')
            return code, time.monotonic() - started
        if cancelled:
            code = 128 + cancel_signal
        if code == 0:
            try:
                evidence = read_preparation_receipt(work)
            except (ControlBlocked, OSError):
                log.append('PREPARATION_FAILURE=receipt_invalid')
                code = INCOMPLETE
        if code == 0:
            try:
                recheck_workspace(work, pinned)
            except (ControlBlocked, OSError):
                log.append('PREPARATION_FAILURE=workspace_recheck')
                code = OWNERSHIP_BLOCKED
        if cancelled:
            code = 128 + cancel_signal
        if code != 0:
            log.append(f'PREP_STAGE={stage}')
            cutoff = time.monotonic() + 10
            rollback = clean_work(work, pinned, cutoff, cutoff + REAP_REMAINING, log)
            log.append('PREPARATION_ROLLBACK=' + ('confirmed' if rollback == 0 else 'unconfirmed'))
            if cancelled:
                code = 128 + cancel_signal
            log.append(f'PREPARATION_POLICY_CODE={code}')
            log.append('PREPARATION_CANCELLED=' + ('yes' if cancelled else 'no'))
            return code, time.monotonic() - started

        log.append('PREPARATION_CANCELLED=' + ('yes' if cancelled else 'no'))
        log.extend(f'{key}={evidence[key]}' for key in PREPARATION_FIELDS)
        log.append(f'PREP_SECONDS={time.monotonic() - started:.3f}')
        started = time.monotonic()
        deadline = started + BUDGET
        code = supervise(work, evidence['HOST_ISO_SHA256'], evidence['HOST_FILE_MANIFEST_SHA256'],
                         started, deadline, log, pinned)
        return decide(code, started, deadline)


def write_preparation_failure(stage, code):
    """Best-effort diagnostic only; no existing filesystem object is opened."""
    if stage not in PREPARATION_STAGES or not re.fullmatch(r'[1-9][0-9]{0,2}', code):
        return False
    if not 1 <= int(code) <= 255:
        return False
    payload = f'{stage} {code}\n'.encode('ascii')
    if len(payload) > 64:
        return False
    try:
        fd = os.open('preparation.failure', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return False
            # One bounded record. Partial writes fail closed in the reader.
            return os.write(fd, payload) == len(payload)
        finally:
            os.close(fd)
    except OSError:
        return False


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--write-preparation-failure':
        sys.exit(0 if write_preparation_failure(*sys.argv[2:]) else 1)
    for signum in CANCEL_SIGNALS:
        signal.signal(signum, cancel)
    log = []
    try:
        if sys.argv[1:] != ['--prepare-and-run']:
            raise ValueError('invalid invocation')
        code, elapsed = run_workflow(sys.stdin.read(), str(pathlib.Path(__file__).resolve().parent), log)
    except (OSError, ValueError, ControlBlocked):
        log.append('CLEANUP_STATUS=unconfirmed REASON=supervision_error')
        code, elapsed = INCOMPLETE, 0
    publish(code, elapsed, log)
    sys.exit(code)
