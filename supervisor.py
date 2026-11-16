from contextlib import ExitStack
import os
import pathlib
import re
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


def cancel(signum, frame):
    global cancelled
    cancelled = True


class Child:
    """An unreaped direct child owns its PID and isolated process group."""

    def __init__(self, task, close_fds=()):
        self.rc = None
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
            pid, status, usage = os.wait4(self.pid, os.WNOHANG)
            if pid:
                self.observed_at = time.monotonic()
                self.rc = os.waitstatus_to_exitcode(status)
                self.usage = usage
        return self.rc

    def send(self, signum):
        # Never signal a reaped PID. Before setsid(), signal the child itself.
        if self.rc is not None:
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
        return rc, False
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


def require_safe_parent(parent, fd):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            str(pathlib.Path(parent).resolve(strict=True)) != parent or
            not os.path.samestat(info, os.lstat(parent))):
        raise ControlBlocked('unsafe_parent')


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


def pin_work(work, created_identity, descriptors):
    runner_temp = os.environ.get('RUNNER_TEMP')
    if (not os.path.isabs(work) or os.path.normpath(work) != work or
            not runner_temp or os.path.dirname(work) != runner_temp or
            not re.fullmatch(r'offline-iso-readiness\.[A-Za-z0-9]{8}', os.path.basename(work))):
        raise ControlBlocked('unsafe_work_path')
    parent = os.path.dirname(work)
    parent_fd = directory_fd(parent)
    descriptors.callback(os.close, parent_fd)
    require_safe_parent(parent, parent_fd)
    fd = directory_fd(os.path.basename(work), dir_fd=parent_fd)
    descriptors.callback(os.close, fd)
    identity = os.fstat(fd)
    if (identity.st_uid != os.geteuid() or not identity.st_nlink or
            stat.S_IMODE(identity.st_mode) != 0o700 or
            f'{identity.st_dev}:{identity.st_ino}' != created_identity or
            not os.path.samestat(identity, os.lstat(work))):
        raise ControlBlocked('unsafe_work_identity')
    require_no_workspace_mounts(work)
    return fd, parent_fd, identity


def clean_work(work, pinned, cutoff, verify_limit, log):
    fd, parent_fd, identity = pinned
    close_fds = (fd, parent_fd)
    run_limit = cutoff - CLEANUP_STOP_RESERVE
    if time.monotonic() >= run_limit:
        log.append('CLEANUP_STATUS=unconfirmed REASON=budget_before_rm')
        return DEADLINE_EXCEEDED

    def remove():
        os.chdir('/')
        if (not os.path.samestat(parent_identity, os.lstat(os.path.dirname(work))) or
                not os.path.samestat(identity, os.lstat(work))):
            return 126
        require_no_workspace_mounts(work)
        os.execve(RM, ['rm', '-rf', '--one-file-system', '--', work], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

    try:
        require_safe_parent(os.path.dirname(work), parent_fd)
        if (not os.path.samestat(identity, os.fstat(fd)) or
                not os.path.samestat(identity, os.lstat(work))):
            raise ControlBlocked('work_path_changed')
        parent_identity = os.fstat(parent_fd)
        require_no_workspace_mounts(work)
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

    close_fds = pinned[:2]

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
    if code == DEADLINE_EXCEEDED:
        log.append('VM_DEADLINE=exceeded')
    log.append(f'EXIT_CODE={code} RESULT={result} elapsed_seconds={elapsed!r}')
    print('\n'.join(log), flush=True)


def run(work, iso_hash, files_hash, created_identity, started, deadline, log):
    with ExitStack() as descriptors:
        try:
            pinned = pin_work(work, created_identity, descriptors)
            code = supervise(work, iso_hash, files_hash, started, deadline, log, pinned)
        except ControlBlocked as exc:
            log.append(f'CLEANUP_STATUS=unconfirmed REASON={exc.args[0]}')
            code = OWNERSHIP_BLOCKED
        except (OSError, ValueError):
            log.append('CLEANUP_STATUS=unconfirmed REASON=identity_or_supervision_error')
            code = INCOMPLETE
        return decide(code, started, deadline)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--check-parent':
        with ExitStack() as descriptors:
            try:
                fd = directory_fd(sys.argv[2])
                descriptors.callback(os.close, fd)
                require_safe_parent(sys.argv[2], fd)
            except ControlBlocked as exc:
                print(f'RESULT=BLOCK REASON={exc.args[0]}')
                sys.exit(OWNERSHIP_BLOCKED)
            except OSError:
                print('RESULT=BLOCK REASON=parent_check_error')
                sys.exit(OWNERSHIP_BLOCKED)
        sys.exit(0)

    started = time.monotonic()
    deadline = started + BUDGET
    for signum in CANCEL_SIGNALS:
        signal.signal(signum, cancel)
    log = []
    code, elapsed = run(*sys.argv[1:], started, deadline, log)
    publish(code, elapsed, log)
    sys.exit(code)
