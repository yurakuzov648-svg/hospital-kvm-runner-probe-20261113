from contextlib import ExitStack
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from build_iso import FILES, build, contents, sha
from isolation import qemu_args, verify_launch, verify_serial
import supervisor

ROOT = Path(__file__).resolve().parent
ISO = 'a' * 64
FILES_HASH = 'b' * 64
MARKER = (f'ISO_DIAG_OK ubuntu=24.04 arch=x86_64 network=loopback devices=expected '
          f'readonly=erofs uid_gid=verified iso={ISO} files={FILES_HASH}').encode()
DOWN = b'[ 2.000] reboot: Power down'


def birth(work):
    info = work.stat()
    return f'{info.st_dev}:{info.st_ino}'


def fixture_work(parent):
    parent = Path(parent).resolve() / 'offline-iso-readiness.1234abcd1234abcd'
    parent.mkdir(mode=0o700)
    work = parent / 'vm'
    work.mkdir(mode=0o700)
    return work


def fixture_rm(parent, body=None):
    if body is None and sys.platform != 'darwin':
        return supervisor.RM
    path = parent / 'fixture-rm'
    if body is None:
        # BSD rm uses -x. Production still requires GNU --one-file-system.
        body = ("import os, sys\nassert sys.argv[2] == '--one-file-system'\n"
                "os.execv('/bin/rm', ['rm', '-rf', '-x', '--', sys.argv[-1]])\n")
    path.write_text(f'#!{sys.executable}\n' + body)
    path.chmod(0o700)
    return str(path)


class Readiness(unittest.TestCase):
    def test_allowlist(self):
        argv = qemu_args()
        verify_launch(argv)
        for option in ('-netdev', '-fsdev', '-virtfs', '-chardev', '-qmp', '-device'):
            with self.subTest(option=option), self.assertRaises(ValueError):
                verify_launch(argv + [option, 'unexpected'])

    def test_serial_positive(self):
        self.assertEqual(verify_serial(b'ignored\r\n' + MARKER + b'\r\n' + DOWN,
                                       ISO, FILES_HASH), MARKER)

    def test_serial_negative(self):
        for data in (MARKER, DOWN + b'\n' + MARKER, MARKER + b'\n' + MARKER,
                     MARKER + b'\n' + DOWN + b'\n' + DOWN,
                     MARKER.replace(ISO.encode(), b'c' * 64) + b'\n' + DOWN,
                     MARKER.replace(FILES_HASH.encode(), b'c' * 64) + b'\n' + DOWN,
                     b'ISO_DIAG_FAIL ISO private text',
                     MARKER + b'\nISO_DIAG_FAIL SHUTDOWN\n' + DOWN):
            with self.subTest(data=data):
                self.assertIsNone(verify_serial(data, ISO, FILES_HASH))
        self.assertEqual(verify_serial(b'ISO_DIAG_FAIL ISO', ISO, FILES_HASH), b'ISO_DIAG_FAIL ISO')

    def test_iso_creation_and_rejection(self):
        payload = contents(b'guest stub\n')
        for defect in (None, 'extra', 'tampered', 'unaligned'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)

                def fake(args, **kwargs):
                    if args[0] == 'genisoimage':
                        self.assertEqual([p.name for p in sorted(kwargs['cwd'].iterdir())], list(FILES))
                        (kwargs['cwd'] / 'seed.iso').write_bytes(b'i' * (2047 if defect == 'unaligned' else 2048))
                        return b''
                    if '-f' in args:
                        extra = '/extra\n' if defect == 'extra' else ''
                        return (''.join(f'/{name}\n' for name in FILES) + extra).encode()
                    name = args[-1][1:]
                    return b'changed' if defect == 'tampered' else payload[name]

                if defect:
                    with self.assertRaises(ValueError):
                        build(work, b'guest stub\n', fake)
                else:
                    iso, manifest = build(work, b'guest stub\n', fake)
                    self.assertEqual(iso, sha(b'i' * 2048))
                    self.assertRegex(manifest, r'^[a-f0-9]{64}$')
                    self.assertEqual((work / 'seed.iso').stat().st_mode & 0o777, 0o400)

    def fake_run(self, data, fault='', producer=None, rm_body=None):
        with tempfile.TemporaryDirectory() as tmp:
            work = fixture_work(tmp)
            (work / 'seed.iso').write_bytes(b'iso')
            fake = Path(tmp) / 'fake-qemu'
            fake.write_text(f'#!{sys.executable}\n' +
                            (producer or f'import os\nos.write(1, {data!r})\n'))
            fake.chmod(0o700)
            rm = fixture_rm(work.parent.parent, rm_body)
            code = f'''
import os
import time
import supervisor
supervisor.qemu_args = lambda: [{str(fake)!r}]
supervisor.verify_launch = lambda args: None
os.environ['RUNNER_TEMP'] = {str(work.parent.parent)!r}
if supervisor.sys.platform == 'darwin':
    supervisor.require_no_workspace_mounts = lambda work: None
if supervisor.sys.platform == 'darwin':
    import os
    from pathlib import Path
    from types import SimpleNamespace
    original_fstat = os.fstat
    work = Path({str(work)!r})
    identities = [(path, path.stat()) for path in (work, work.parent)]
    def linux_unlink_result(fd):
        info = original_fstat(fd)
        if any(os.path.samestat(info, identity) and not path.exists() for path, identity in identities):
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_nlink=0)
        return info
    supervisor.os.fstat = linux_unlink_result
supervisor.RM = {rm!r}
if {fault!r} == 'cleanup':
    supervisor.RM = '/usr/bin/false'
if {fault!r} in ('fast', 'rm_hang'):
    original_stop = supervisor.stop_child
    supervisor.stop_child = lambda child, limit, grace=0.05: original_stop(child, limit, grace)
    if {fault!r} == 'rm_hang':
        supervisor.FINALIZATION_RESERVE = 0.8
        supervisor.STOP_REMAINING = 0.7
        supervisor.SERIAL_REMAINING = 0.6
        supervisor.CLEANUP_REMAINING = 0.1
        supervisor.REAP_REMAINING = 0.05
        supervisor.CLEANUP_STOP_RESERVE = 0.25
        supervisor.CLEANUP_TERM_GRACE = 0.05
if {fault!r} == 'deadline':
    supervisor.time.monotonic = lambda: 1200
log = []
started = 0 if {fault!r} == 'deadline' else time.monotonic()
rc, elapsed = supervisor.run({work.parent.name!r}, {sha(b'iso')!r}, {FILES_HASH!r}, {birth(work.parent)!r}, {birth(work)!r},
                          started, started + (1.5 if {fault!r} == 'rm_hang' else 1200), log)
supervisor.publish(rc, elapsed, log)
raise SystemExit(rc)
'''
            run = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                 capture_output=True, text=True, timeout=5)
            return run, work.exists()

    def test_mock_lifecycle(self):
        good = MARKER.replace(ISO.encode(), sha(b'iso').encode()) + b'\n' + DOWN
        for serial, fault, expected in ((good, '', 0), (b'ISO_DIAG_FAIL ISO', '', 20),
                                         (good, 'cleanup', 21), (good, 'deadline', 22),
                                         (b'x' * 1, '', 20)):
            with self.subTest(fault=fault, expected=expected):
                run, exists = self.fake_run(serial, fault)
                self.assertEqual(run.returncode, expected, run.stderr)
                self.assertEqual('RESULT=OFFLINE_ISO_READY' in run.stdout, expected == 0)
                self.assertEqual(exists, bool(fault))

    def good_serial(self):
        return MARKER.replace(ISO.encode(), sha(b'iso').encode()) + b'\n' + DOWN + b'\n'

    def check_serial_size(self, offset, expected):
        good = self.good_serial()
        count = supervisor.SERIAL_LIMIT + offset - len(good)
        producer = f'import sys\nsys.stdout.buffer.write({good!r} + b"x" * {count})\n'
        run, exists = self.fake_run(b'', producer=producer)
        self.assertEqual(run.returncode, expected, run.stdout)
        self.assertFalse(exists)
        self.assertEqual('SERIAL_LIMIT_EXCEEDED' in run.stdout, expected == 24)
        self.assertEqual('OFFLINE_ISO_READY' in run.stdout, expected == 0)

    def test_serial_under_limit(self):
        self.check_serial_size(-1, 0)

    def test_serial_exact_limit(self):
        self.check_serial_size(0, 0)

    def test_serial_over_limit(self):
        self.check_serial_size(1, 24)

    def test_continuous_serial_forces_kill_and_reap(self):
        producer = """
import os, signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    try:
        os.write(1, b'x' * 65536)
    except BrokenPipeError:
        pass
"""
        run, exists = self.fake_run(b'', fault='fast', producer=producer)
        self.assertEqual(run.returncode, 24, run.stdout)
        self.assertIn('QEMU_EXIT_CODE=-9 QEMU_REAP=confirmed', run.stdout)
        self.assertNotIn('OFFLINE_ISO_READY', run.stdout)
        self.assertFalse(exists)

    def test_rm_direct_success(self):
        run, exists = self.fake_run(self.good_serial(), rm_body=
            'import shutil, sys\nshutil.rmtree(sys.argv[-1])\n')
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn('RM_EXIT_CODE=0 RM_REAP=confirmed', run.stdout)
        self.assertFalse(exists)

    def test_rm_zero_without_removing(self):
        run, exists = self.fake_run(self.good_serial(), rm_body='pass\n')
        self.assertEqual(run.returncode, 21, run.stdout)
        self.assertIn('REASON=absence_check', run.stdout)
        self.assertTrue(exists)

    def test_rm_hangs_and_is_reaped_after_kill(self):
        run, exists = self.fake_run(self.good_serial(), fault='rm_hang', rm_body=
            'import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)\n')
        self.assertEqual(run.returncode, 22, run.stdout)
        self.assertIn('REASON=rm_budget RM_REAP=confirmed', run.stdout)
        self.assertIn('RM_EXIT_CODE=-9', run.stdout)
        self.assertTrue(exists)

    def test_rm_unconfirmed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(supervisor, 'Child') as child, \
                patch.object(supervisor, 'wait_child', return_value=None), \
                patch.object(supervisor, 'stop_child', return_value=None) as stop:
            child.return_value.rc = None
            log = []
            work = fixture_work(tmp)
            with ExitStack() as descriptors, patch.dict(os.environ, RUNNER_TEMP=str(work.parent.parent)), \
                    patch.object(supervisor, 'require_no_workspace_mounts'):
                _, pinned = supervisor.pin_work(work.parent.name, birth(work.parent), birth(work), descriptors)
                rc = supervisor.clean_work(str(work), pinned, supervisor.time.monotonic() + 10,
                                           supervisor.time.monotonic() + 11, log)
            stop.assert_called_once()
            self.assertEqual(rc, 25)
            self.assertIn('CLEANUP_STATUS=unconfirmed REASON=rm_budget RM_REAP=unconfirmed', log)

    def test_deadline_during_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(supervisor, 'Child') as child, \
                patch.object(supervisor, 'wait_child', return_value=0), \
                patch.object(supervisor, 'run_phase', return_value=(None, False)):
            child.return_value.rc = 0
            log = []
            work = fixture_work(tmp)
            with ExitStack() as descriptors, patch.dict(os.environ, RUNNER_TEMP=str(work.parent.parent)), \
                    patch.object(supervisor, 'require_no_workspace_mounts'):
                _, pinned = supervisor.pin_work(work.parent.name, birth(work.parent), birth(work), descriptors)
                rc = supervisor.clean_work(str(work), pinned, supervisor.time.monotonic() + 10,
                                           supervisor.time.monotonic() + 11, log)
            self.assertEqual(rc, 22)
            self.assertIn('CLEANUP_STATUS=unconfirmed REASON=absence_check', log)

    def test_reap_at_cutoff_fails(self):
        from unittest.mock import Mock
        child = Mock()
        child.poll.return_value = 0
        child.observed_at = 1180
        with patch.object(supervisor.time, 'monotonic', return_value=1179):
            self.assertIsNone(supervisor.wait_child(child, 1180))

    def test_pending_cancellation_and_decision_boundary(self):
        import signal
        with patch.object(supervisor.signal, 'pthread_sigmask'), \
                patch.object(supervisor.signal, 'sigpending', return_value={signal.SIGTERM}), \
                patch.object(supervisor.time, 'monotonic', return_value=1199):
            self.assertEqual(supervisor.decide(0, 0, 1200), (21, 1199))
        with patch.object(supervisor.signal, 'pthread_sigmask'), \
                patch.object(supervisor.signal, 'sigpending', return_value=set()), \
                patch.object(supervisor.time, 'monotonic', return_value=1200):
            self.assertEqual(supervisor.decide(0, 0, 1200), (22, 1200))

    def test_unconfirmed_qemu_preserves_tree(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(supervisor, 'Child') as child, \
                patch.object(supervisor, 'collect_serial', return_value=(None, b'', False)), \
                patch.object(supervisor, 'stop_child', return_value=None):
            child.return_value.rc = None
            child.return_value.poll.return_value = None
            start = supervisor.time.monotonic()
            work = fixture_work(tmp)
            with ExitStack() as descriptors, patch.dict(os.environ, RUNNER_TEMP=str(work.parent.parent)), \
                    patch.object(supervisor, 'require_no_workspace_mounts'):
                _, pinned = supervisor.pin_work(work.parent.name, birth(work.parent), birth(work), descriptors)
                self.assertEqual(supervisor.supervise(str(work), ISO, FILES_HASH, start, start + 1200, [], pinned), 23)
            self.assertTrue(work.exists())


class CleanupIdentity(unittest.TestCase):
    def setUp(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.parent = Path(base.name).resolve()
        self.work = fixture_work(self.parent)
        self.created_identity = birth(self.work)
        self.parent_identity = birth(self.work.parent)
        self.renamed = self.parent / 'original'
        self.log = []
        self.descriptors = ExitStack()
        self.addCleanup(self.descriptors.close)
        self.descriptors.enter_context(patch.dict(os.environ, RUNNER_TEMP=str(self.parent)))
        self.descriptors.enter_context(patch.object(supervisor, 'RM', fixture_rm(self.parent)))
        if sys.platform == 'darwin':
            self.descriptors.enter_context(patch.object(supervisor, 'require_no_workspace_mounts'))
        _, self.pinned = self.pin(self.descriptors)

    def pin(self, descriptors):
        return supervisor.pin_work(self.work.parent.name, self.parent_identity,
                                   self.created_identity, descriptors)

    def clean(self):
        cutoff = supervisor.time.monotonic() + 10
        return supervisor.clean_work(str(self.work), self.pinned, cutoff, cutoff + 1, self.log)

    def fake_rm(self, body):
        path = self.parent / 'fake-rm'
        path.write_text(f'#!{sys.executable}\n' + body)
        path.chmod(0o700)
        return patch.object(supervisor, 'RM', str(path))

    def test_original_inode_removed(self):
        from types import SimpleNamespace
        real_fstat = os.fstat
        observed = []

        def fstat(fd):
            info = real_fstat(fd)
            if (fd == self.pinned[0] and not self.work.exists() or
                    fd == self.pinned[1] and not self.work.parent.exists()):
                observed.append(info.st_nlink)
                if sys.platform == 'darwin':
                    # Darwin keeps directory link counts after rmdir with an open fd.
                    return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_nlink=0)
            return info

        with patch.object(supervisor.os, 'fstat', side_effect=fstat):
            self.assertEqual(self.clean(), 0, self.log)
        self.assertFalse(self.work.parent.exists())
        self.assertIn('WORKSPACE_PARENT_REMOVAL=confirmed', self.log)
        self.assertEqual(len(observed), 2)
        if sys.platform != 'darwin':
            self.assertEqual(observed, [0, 0])
        self.assertFalse(self.work.exists())

    def test_rename_before_rm(self):
        self.work.rename(self.renamed)
        with patch.object(supervisor, 'Child') as child:
            self.assertNotEqual(self.clean(), 0)
        child.assert_not_called()
        self.assertGreater(os.fstat(self.pinned[0]).st_nlink, 0)

    def test_rename_and_replace_before_rm(self):
        self.work.rename(self.renamed)
        self.work.mkdir()
        marker = self.work / 'keep'
        marker.touch()
        with patch.object(supervisor, 'Child') as child:
            self.assertNotEqual(self.clean(), 0)
        child.assert_not_called()
        self.assertTrue(marker.exists())

    def test_rm_zero_with_original_present(self):
        with self.fake_rm('pass\n'):
            self.assertNotEqual(self.clean(), 0)
        self.assertGreater(os.fstat(self.pinned[0]).st_nlink, 0)

    def test_rm_zero_with_missing_path_and_retained_inode(self):
        with self.fake_rm(f'import os, sys\nos.rename(sys.argv[-1], {str(self.renamed)!r})\n'):
            self.assertNotEqual(self.clean(), 0)
        self.assertFalse(self.work.exists())
        self.assertIn('CLEANUP_STATUS=unconfirmed REASON=original_inode_retained', self.log)

    def test_creation_identity_mismatch_blocks_before_fork(self):
        self.work.rename(self.renamed)
        self.work.mkdir(mode=0o700)
        with ExitStack() as stack, patch.object(supervisor, 'Child') as child:
            with self.assertRaisesRegex(supervisor.ControlBlocked, 'unsafe_work_identity'):
                self.pin(stack)
        child.assert_not_called()
        self.assertTrue(self.work.exists())

    def test_preflight_creates_private_workspace_under_0755_base(self):
        self.parent.chmod(0o755)
        with ExitStack() as stack:
            work, pinned = supervisor.create_workspace(stack, [])
            private = Path(work).parent
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(work).stat().st_mode & 0o777, 0o700)
            self.assertEqual(self.parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(os.fstat(pinned[0]).st_ino, Path(work).stat().st_ino)

    def test_unsafe_parent_mode_blocks_cleanup(self):
        self.parent.chmod(0o770)
        with ExitStack() as stack:
            with self.assertRaisesRegex(supervisor.ControlBlocked, 'parent_unsafe_mode'):
                self.pin(stack)

    def test_symlink_work_and_parent_are_rejected(self):
        self.work.rename(self.renamed)
        self.work.symlink_to(self.renamed, target_is_directory=True)
        with ExitStack() as stack, self.assertRaisesRegex(supervisor.ControlBlocked, 'parent_noncanonical_path'):
            self.pin(stack)
        with patch.object(supervisor, 'Child') as child:
            self.assertNotEqual(self.clean(), 0)
        child.assert_not_called()

        alias = self.parent / 'alias'
        alias.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            supervisor.directory_fd(str(alias))
        nested = self.parent / 'nested'
        nested.mkdir(mode=0o700)
        redirected = str(alias / 'nested')
        with self.assertRaisesRegex(supervisor.ControlBlocked, 'parent_noncanonical_path'):
            supervisor.checked_directory(redirected, private=True)

    def test_workspace_must_be_generated_direct_child(self):
        for path in (self.parent / 'other', self.parent / 'nested' / self.work.name):
            with self.subTest(path=path.name), ExitStack() as stack, \
                    self.assertRaisesRegex(supervisor.ControlBlocked, 'unsafe_work_path'):
                supervisor.pin_work(str(path), self.parent_identity, self.created_identity, stack)

    def test_mount_inventory_blocks_vm_and_cleanup(self):
        with patch.object(supervisor, 'require_no_workspace_mounts',
                          side_effect=supervisor.ControlBlocked('unexpected_workspace_mount')), \
                patch.object(supervisor, 'Child') as child:
            with ExitStack() as stack, self.assertRaisesRegex(supervisor.ControlBlocked, 'unexpected_workspace_mount'):
                self.pin(stack)
            self.assertEqual(self.clean(), supervisor.OWNERSHIP_BLOCKED)
        child.assert_not_called()
        self.assertTrue(self.work.exists())

    def test_parent_diagnostics_are_fixed(self):
        plain = self.parent / 'file'
        plain.touch()
        with self.assertRaisesRegex(supervisor.ControlBlocked, '^parent_invalid_type$'):
            supervisor.checked_directory(str(plain), private=False)
        with patch.object(supervisor.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(supervisor.ControlBlocked, '^parent_unexpected_owner$'):
                supervisor.checked_directory(str(self.parent), private=False)
        with patch.object(supervisor, 'directory_fd', side_effect=PermissionError(errno.EACCES, 'fixture text')):
            with self.assertRaisesRegex(supervisor.ControlBlocked, '^parent_access_error$'):
                supervisor.checked_directory(str(self.parent), private=False)

    def test_replaced_private_parent_is_rejected(self):
        self.work.parent.rename(self.renamed)
        self.work.parent.mkdir(mode=0o700)
        self.work.mkdir(mode=0o700)
        with ExitStack() as stack, self.assertRaisesRegex(supervisor.ControlBlocked, 'parent_inode_mismatch'):
            self.pin(stack)
        with patch.object(supervisor, 'Child') as child:
            self.assertEqual(self.clean(), supervisor.OWNERSHIP_BLOCKED)
        child.assert_not_called()
        self.assertTrue(self.work.is_dir())

    def test_workspace_creation_error_is_classified(self):
        real_mkdir = os.mkdir

        def mkdir(name, *args, **kwargs):
            if name == 'vm':
                raise OSError(errno.EIO, 'synthetic untrusted text')
            return real_mkdir(name, *args, **kwargs)

        before = set(self.parent.iterdir())
        log = []
        with self.linux_links(), ExitStack() as stack, patch.object(supervisor.os, 'mkdir', side_effect=mkdir):
            with self.assertRaisesRegex(supervisor.ControlBlocked, '^workspace_create_error$'):
                supervisor.create_workspace(stack, log)
        self.assertEqual(set(self.parent.iterdir()), before)
        self.assertIn('BOOTSTRAP_ROLLBACK=confirmed', log)
        self.assertIn(f'BOOTSTRAP_ERRNO={errno.EIO}', log)

    def linux_links(self):
        # Darwin retains nonzero link counts for unlinked open directories.
        # Model Linux only after the known path actually disappears.
        from contextlib import nullcontext
        from types import SimpleNamespace
        if sys.platform != 'darwin':
            return nullcontext()
        real_fstat = os.fstat
        checked = supervisor.checked_directory
        paths = {birth(self.work): self.work, birth(self.work.parent): self.work.parent}
        stack = ExitStack()

        def remember(path, **kwargs):
            fd = checked(path, **kwargs)
            paths[supervisor.identity_token(real_fstat(fd))] = Path(path)
            return fd

        def fstat(fd):
            info = real_fstat(fd)
            path = paths.get(supervisor.identity_token(info))
            if path is not None and not path.exists():
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_nlink=0)
            return info

        stack.enter_context(patch.object(supervisor, 'checked_directory', side_effect=remember))
        stack.enter_context(patch.object(supervisor.os, 'fstat', side_effect=fstat))
        return stack

    def test_bootstrap_rolls_back_after_work_is_created(self):
        before = set(self.parent.iterdir())
        log = []
        actual = self.work.name
        checked = supervisor.checked_directory
        calls = []

        def fail_once(path, **kwargs):
            fd = checked(path, **kwargs)
            if Path(path).name == actual and not calls:
                calls.append(path)
                os.close(fd)
                raise OSError(errno.EIO)
            return fd

        # Record the work identity when rollback reopens the known inode.
        with patch.object(supervisor, 'checked_directory', side_effect=fail_once):
            with self.linux_links(), ExitStack() as stack:
                with self.assertRaisesRegex(supervisor.ControlBlocked, '^workspace_create_error$'):
                    supervisor.create_workspace(stack, log)
        self.assertEqual(set(self.parent.iterdir()), before)
        self.assertIn('BOOTSTRAP_ROLLBACK=confirmed', log)

    @staticmethod
    def preparation_fields():
        return {
            'QEMU_VERSION': '8.2.2',
            'KVM_API_VERSION': '12',
            'VERIFIED_IMAGE_SHA256': 'a' * 64,
            'HOST_ISO_SHA256': 'b' * 64,
            'HOST_FILE_MANIFEST_SHA256': 'c' * 64,
        }

    @staticmethod
    def write_receipt(fields, target='preparation.receipt', extra=''):
        import shlex
        payload = ''.join(f'{key}={value}\n' for key, value in fields.items()) + extra
        return f'printf %s {shlex.quote(payload)} > {target}'

    def test_preparation_fork_failure_rolls_back_or_reports_unconfirmed(self):
        for persistent in (False, True):
            with self.subTest(persistent=persistent), self.linux_links():
                before = set(self.parent.iterdir())
                original_fork = os.fork
                attempts = []
                log = []

                def fork():
                    attempts.append(1)
                    if len(attempts) == 1 or persistent:
                        self.assertEqual(len(set(self.parent.iterdir()) - before), 1)
                        raise OSError(errno.EAGAIN, 'synthetic secret')
                    return original_fork()

                sentinel = self.parent / 'unexpected-bash'
                with patch.object(supervisor.os, 'fork', side_effect=fork), \
                        patch.object(supervisor, 'supervise') as boot:
                    code, _ = supervisor.run_workflow(f'touch "{sentinel}"', str(ROOT), log)
                self.assertEqual(code, supervisor.INCOMPLETE, log)
                self.assertFalse(sentinel.exists())
                boot.assert_not_called()
                self.assertIn('PREPARATION_FAILURE=fork_failed', log)
                self.assertIn(f'PREPARATION_FORK_ERRNO={errno.EAGAIN}', log)
                self.assertIn(f'PREPARATION_EXIT_CODE={supervisor.INCOMPLETE}', log)
                self.assertNotIn('synthetic secret', '\n'.join(log))
                if persistent:
                    self.assertIn('PREPARATION_ROLLBACK=unconfirmed', log)
                    parent, = set(self.parent.iterdir()) - before
                    self.assertTrue((parent / 'vm').is_dir())
                else:
                    self.assertIn('PREPARATION_ROLLBACK=confirmed', log)
                    self.assertEqual(set(self.parent.iterdir()), before)

    def test_preparation_poll_error_does_not_roll_back(self):
        before = set(self.parent.iterdir())
        log = []
        with patch.object(supervisor, 'Child') as child, patch.object(supervisor, 'clean_work') as cleanup, \
                patch.object(supervisor, 'supervise') as boot:
            child.return_value.poll.side_effect = OSError(errno.EIO, 'raw diagnostic')
            code, _ = supervisor.run_workflow('', str(ROOT), log)
        self.assertEqual(code, supervisor.INCOMPLETE)
        self.assertIn('CLEANUP_STATUS=unconfirmed REASON=preparation_supervision', log)
        self.assertNotIn('raw diagnostic', '\n'.join(log))
        child.assert_called_once()
        cleanup.assert_not_called()
        boot.assert_not_called()
        parent, = set(self.parent.iterdir()) - before
        self.assertTrue((parent / 'vm').is_dir())

    def test_receipt_publishes_all_five_values_with_mock_vm(self):
        import contextlib
        import io
        evidence = self.preparation_fields()
        before = set(self.parent.iterdir())
        log = []
        out = io.StringIO()
        script = 'echo SYNTHETIC_RAW_OUTPUT; echo SYNTHETIC_RAW_ERROR >&2; ' + self.write_receipt(evidence)
        with self.linux_links(), patch.object(supervisor, 'decide', side_effect=lambda code, *_: (code, 1.0)), \
                patch.object(supervisor, 'supervise', side_effect=self.clean_mock_vm) as boot, \
                contextlib.redirect_stdout(out):
            code, elapsed = supervisor.run_workflow(script, str(ROOT), log)
            supervisor.publish(code, elapsed, log)
        self.assertEqual(code, 0, log)
        self.assertEqual(boot.call_args.args[1:3], (evidence['HOST_ISO_SHA256'], evidence['HOST_FILE_MANIFEST_SHA256']))
        self.assertEqual(set(self.parent.iterdir()), before)
        for key, value in evidence.items():
            self.assertIn(f'{key}={value}', out.getvalue().splitlines())
        self.assertNotIn('SYNTHETIC_RAW', out.getvalue())

    def clean_mock_vm(self, work, iso_hash, files_hash, started, deadline, log, pinned):
        return supervisor.clean_work(work, pinned, deadline - 2, deadline - 1, log)

    def test_receipt_rejects_missing_invalid_and_injected_fields(self):
        evidence = self.preparation_fields()
        cases = []
        for key, invalid in (('QEMU_VERSION', '8.2.2 unexpected'), ('KVM_API_VERSION', '13'),
                             ('VERIFIED_IMAGE_SHA256', 'A' * 64)):
            cases.append(({k: v for k, v in evidence.items() if k != key}, ''))
            cases.append(({**evidence, key: invalid}, ''))
        cases.append((evidence, 'SYNTHETIC_INJECTED=secret\n'))
        cases.append((evidence, 'X' * supervisor.PREPARATION_RECEIPT_LIMIT))
        for fields, extra in cases:
            with self.subTest(fields=list(fields), extra=bool(extra)), self.linux_links(), \
                    patch.object(supervisor, 'supervise') as boot:
                before = set(self.parent.iterdir())
                log = []
                code, _ = supervisor.run_workflow(self.write_receipt(fields, extra=extra), str(ROOT), log)
                self.assertEqual(code, supervisor.INCOMPLETE, log)
                self.assertIn('PREPARATION_FAILURE=receipt_invalid', log)
                self.assertIn('PREPARATION_ROLLBACK=confirmed', log)
                self.assertFalse(any(line.startswith(tuple(evidence)) for line in log))
                self.assertNotIn('SYNTHETIC_INJECTED', '\n'.join(log))
                self.assertEqual(set(self.parent.iterdir()), before)
                boot.assert_not_called()

    def test_preparation_failures_roll_back_and_preserve_codes(self):
        for script, expected in (('exit 37', 37), ('touch synthetic-media; exit 38', 38),
                                 ('printf invalid > preparation.receipt', supervisor.INCOMPLETE)):
            with self.subTest(script=script), self.linux_links(), patch.object(supervisor, 'supervise') as boot:
                before = set(self.parent.iterdir())
                log = []
                code, _ = supervisor.run_workflow(script, str(ROOT), log)
                self.assertEqual(code, expected, log)
                self.assertIn('PREPARATION_ROLLBACK=confirmed', log)
                self.assertEqual(set(self.parent.iterdir()), before)
                boot.assert_not_called()

    def test_workspace_changed_during_preparation_blocks_boot(self):
        before = set(self.parent.iterdir())
        log = []
        script = (
            'cd ..; mv vm detached; mkdir -m 700 vm; '
            + self.write_receipt(self.preparation_fields(), 'vm/preparation.receipt')
        )
        with patch.object(supervisor, 'supervise') as boot:
            code, _ = supervisor.run_workflow(script, str(ROOT), log)
        self.assertEqual(code, supervisor.OWNERSHIP_BLOCKED)
        self.assertIn('PREPARATION_FAILURE=workspace_recheck', log)
        self.assertIn('PREPARATION_ROLLBACK=unconfirmed', log)
        boot.assert_not_called()
        parent, = set(self.parent.iterdir()) - before
        self.assertTrue((parent / 'vm').is_dir())
        self.assertTrue((parent / 'detached').is_dir())

    def test_preparation_handles_real_int_and_term(self):
        import signal
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum), self.linux_links(), \
                    patch.object(supervisor, 'cancelled', False), \
                    patch.object(supervisor, 'cancel_signal', None), \
                    patch.object(supervisor, 'supervise') as boot:
                before = set(self.parent.iterdir())
                old = signal.signal(signum, supervisor.cancel)
                try:
                    number = int(signum)
                    script = (f"trap 'exit {128 + number}' {number}; "
                              f'touch synthetic-media; kill -{number} "$PPID"; sleep 0.2')
                    log = []
                    code, _ = supervisor.run_workflow(script, str(ROOT), log)
                finally:
                    signal.signal(signum, old)
                self.assertEqual(code, 128 + number, log)
                self.assertIn('PREPARATION_ROLLBACK=confirmed', log)
                self.assertEqual(set(self.parent.iterdir()), before)
                boot.assert_not_called()

    def test_unconfirmed_preparation_leaves_workspace(self):
        before = set(self.parent.iterdir())
        log = []
        with patch.object(supervisor, 'prepare_workspace', return_value=(143, False)), \
                patch.object(supervisor, 'clean_work') as cleanup:
            code, _ = supervisor.run_workflow('', str(ROOT), log)
        self.assertEqual(code, 143)
        self.assertEqual(len(set(self.parent.iterdir()) - before), 1)
        self.assertIn('CLEANUP_STATUS=unconfirmed REASON=preparation_stop', log)
        cleanup.assert_not_called()

    def test_rmdir_absent_and_nonzero_exit_fail(self):
        for program, code in ((str(self.parent / 'missing-rmdir'), 2), ('/usr/bin/false', 1)):
            with self.subTest(program=program), self.linux_links(), patch.object(supervisor, 'RMDIR', program):
                self.assertEqual(self.clean(), supervisor.INCOMPLETE)
                self.assertIn(f'RMDIR_EXIT_CODE={code} RMDIR_REAP=confirmed', self.log)
                self.assertTrue(self.work.parent.exists())
            if not self.work.exists():
                self.work.mkdir(mode=0o700)
                self.pin_replacement_fixture()

    def pin_replacement_fixture(self):
        self.created_identity = birth(self.work)
        _, self.pinned = self.pin(self.descriptors)

    def test_rmdir_zero_without_removal_is_rejected(self):
        with self.linux_links(), patch.object(supervisor, 'RMDIR', '/usr/bin/true'):
            self.assertEqual(self.clean(), supervisor.INCOMPLETE)
        self.assertIn('CLEANUP_STATUS=unconfirmed REASON=parent_path_retained', self.log)

    def test_rmdir_hang_is_killed_and_reaped(self):
        rm = self.parent / 'hung-rmdir'
        rm.write_text(f'#!{sys.executable}\nimport signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)\n')
        rm.chmod(0o700)
        cutoff = supervisor.time.monotonic() + 2
        with self.linux_links(), patch.object(supervisor, 'RMDIR', str(rm)), \
                patch.object(supervisor, 'CLEANUP_STOP_RESERVE', 1.5):
            self.assertEqual(supervisor.clean_work(str(self.work), self.pinned, cutoff, cutoff + 1,
                                                   self.log), supervisor.DEADLINE_EXCEEDED)
        self.assertIn('RMDIR_EXIT_CODE=-9', self.log)
        self.assertTrue(self.work.parent.exists())

    def test_rmdir_late_and_unconfirmed_wait4_fail(self):
        from unittest.mock import Mock
        for rc, expected in ((0, supervisor.DEADLINE_EXCEEDED), (None, supervisor.CLEANUP_UNCONFIRMED)):
            with self.subTest(rc=rc), self.linux_links():
                child = supervisor.Child
                calls = []
                fake = Mock(rc=rc)

                def spawn(task, fds=()):
                    if task.__name__ == 'remove_parent':
                        return fake
                    return child(task, fds)

                wait = supervisor.wait_child

                def observe(process, cutoff, honor_cancel=False):
                    if process is fake:
                        calls.append(cutoff)
                        return None
                    return wait(process, cutoff, honor_cancel)

                self.log.clear()
                with patch.object(supervisor, 'Child', side_effect=spawn), \
                        patch.object(supervisor, 'wait_child', side_effect=observe):
                    self.assertEqual(self.clean(), expected, self.log)
                self.assertTrue(calls)
                self.assertTrue(self.work.parent.exists())
                self.work.mkdir(mode=0o700)
                self.pin_replacement_fixture()

    def test_nonempty_parent_blocks_cleanup_without_removing_foreign_file(self):
        marker = self.work.parent / 'keep'
        marker.touch()
        real_fstat = os.fstat

        def fstat(fd):
            info = real_fstat(fd)
            if sys.platform == 'darwin' and fd == self.pinned[0] and not self.work.exists():
                from types import SimpleNamespace
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_nlink=0)
            return info

        with patch.object(supervisor.os, 'fstat', side_effect=fstat):
            self.assertEqual(self.clean(), supervisor.INCOMPLETE)
        self.assertFalse(self.work.exists())
        self.assertTrue(marker.is_file())
        self.assertIn('CLEANUP_STATUS=unconfirmed REASON=parent_remove_error', self.log)

    def test_stat_errors_block(self):
        for name in ('fstat', 'lstat'):
            with self.subTest(name=name), patch.object(supervisor.os, name, side_effect=OSError(errno.EIO)), \
                    patch.object(supervisor, 'Child') as child:
                self.assertNotEqual(self.clean(), 0)
                child.assert_not_called()

    def test_post_rm_fstat_error(self):
        original = os.fstat
        def fstat(fd):
            info = original(fd)
            if fd == self.pinned[0] and not self.work.exists():
                raise OSError(errno.EIO)
            return info

        with patch.object(supervisor.os, 'fstat', side_effect=fstat):
            self.assertNotEqual(self.clean(), 0)
        self.assertFalse(self.work.exists())

    def test_descriptors_close_in_child_and_after_decision(self):
        for fd in self.pinned[:2]:
            self.assertFalse(os.get_inheritable(fd))

        def check():
            for fd in self.pinned[:2]:
                try:
                    os.fstat(fd)
                except OSError as exc:
                    if exc.errno == errno.EBADF:
                        continue
                return 1
            return 0

        cutoff = supervisor.time.monotonic() + 2
        self.assertEqual(supervisor.run_phase(check, cutoff, cutoff + 1, self.pinned[:2])[0], 0)
        seen = []
        def observe_decision(code, started, deadline):
            for fd in seen:
                os.fstat(fd)
            return code, 0

        def observe_run(*args):
            seen.extend((*args[-1][:2], args[-1][4]))
            return 0

        with patch.object(supervisor, 'supervise', side_effect=observe_run), \
                patch.object(supervisor, 'decide', side_effect=observe_decision):
            self.assertEqual(supervisor.run(self.work.parent.name, ISO, FILES_HASH, self.parent_identity,
                                            self.created_identity, 0, 1200, []), (0, 0))
        self.assertEqual(len(seen), 3)
        for fd in seen:
            with self.assertRaises(OSError) as raised:
                os.fstat(fd)
            self.assertEqual(raised.exception.errno, errno.EBADF)


class WorkspaceMountInventory(unittest.TestCase):
    @staticmethod
    def mount(path):
        return b'22 21 8:1 /fixture ' + path + b' rw - ext4 /dev/synthetic rw\n'

    def check(self, contents, work='/tmp/probe', reason=None):
        from unittest.mock import mock_open
        with patch('builtins.open', mock_open(read_data=contents)) as opened:
            if reason is None:
                supervisor.require_no_workspace_mounts(work)
            else:
                with self.assertRaisesRegex(supervisor.ControlBlocked, reason):
                    supervisor.require_no_workspace_mounts(work)
            opened.assert_called_once_with('/proc/self/mountinfo', 'rb')

    def test_root_and_nested_same_device_mounts_rejected(self):
        for path in (b'/tmp/probe', b'/tmp/probe/nested'):
            with self.subTest(path=path):
                self.check(self.mount(b'/tmp') + self.mount(path), reason='unexpected_workspace_mount')

    def test_escaped_mount_rejected(self):
        self.check(self.mount(b'/tmp/probe\\040space/sub'), '/tmp/probe space', 'unexpected_workspace_mount')

    def test_sibling_and_ancestor_are_outside_scope(self):
        self.check(self.mount(b'/') + self.mount(b'/tmp/probe-other'))

    def test_missing_or_malformed_mount_inventory_fails_closed(self):
        for contents in (b'', b'corrupt\n'):
            self.check(contents, reason='mount_inventory_unavailable')
        with patch('builtins.open', side_effect=OSError(errno.EIO)), self.assertRaises(OSError):
            supervisor.require_no_workspace_mounts('/tmp/probe')

    def test_malformed_mandatory_fields_reject_entire_inventory(self):
        valid = self.mount(b'/')
        for record in (
            b'x y z / relative rw - ext4\n',
            b'x 21 8:1 / /tmp rw - ext4 none rw\n',
            b'22 +21 8:1 / /tmp rw - ext4 none rw\n',
            b'22 21 8: / /tmp rw - ext4 none rw\n',
            b'22 21 8:1:2 / /tmp rw - ext4 none rw\n',
            b'22 21 8:1 relative /tmp rw - ext4 none rw\n',
            b'22 21 8:1 / relative rw - ext4 none rw\n',
            b'22 21 8:1 / /tmp - ext4 none rw\n',
            b'22 21 8:1 / /tmp bogus - ext4 none rw\n',
            b'22 21 8:1 / /tmp rw ext4 none rw\n',
            b'22 21 8:1 / /tmp rw -  none rw\n',
            b'22 21 8:1 / /tmp rw - ext4  rw\n',
            b'22 21 8:1 / /tmp rw - ext4 none\n',
            b'22 21 8:1 / /tmp rw - ext4 none bogus\n',
            b'22 21 8:1 / /tmp rw - ext4 none rw extra\n',
            b'22 21 8:1 / /tmp rw - ext4 none rw',
            b'\n',
        ):
            with self.subTest(record=record):
                self.check(valid + record, reason='mount_inventory_unavailable')

    def test_malformed_option_lists_on_either_side(self):
        for invalid in (b'rw,', b',rw', b'rw,,nosuid', b''):
            for mount_options, super_options in ((invalid, b'rw'), (b'rw', invalid)):
                with self.subTest(mount_options=mount_options, super_options=super_options):
                    row = b'22 21 8:1 / /tmp %s - ext4 none %s\n' % (mount_options, super_options)
                    self.check(row, reason='mount_inventory_unavailable')

    def test_audit_counterexample_between_valid_nonworkspace_records(self):
        self.check(
            self.mount(b'/') +
            b'22 21 8:1 / /tmp rw, - ext4 none rw,\n' +
            self.mount(b'/tmp/probe-other'),
            reason='mount_inventory_unavailable',
        )

    def test_option_lists_allow_flags_and_opaque_values(self):
        self.check(
            b'21 1 8:1 / / rw - ext4 /dev/synthetic rw\n'
            b'22 21 8:1 /volume /tmp/probe-other rw,nosuid,nodev - ext4 '
            b'/dev/synthetic rw,errors=remount-ro,commit=30\n'
            b'23 21 0:32 / /overlay ro,nodev - overlay overlay '
            b'rw,lowerdir=/a:/b,upperdir=/c/with\134backslash,workdir=/d\n'
        )
        self.check(
            b'22 21 8:1 /volume /tmp/probe/nested rw,nosuid,nodev - ext4 '
            b'/dev/synthetic rw,errors=remount-ro,commit=30\n',
            reason='unexpected_workspace_mount',
        )

    def test_invalid_path_escapes_rejected_in_root_and_mountpoint(self):
        for path in (rb'/broken\999', rb'/broken\141', rb'/broken\04',
                     b'/broken\\', rb'/broken\q', b'/raw\ttab'):
            for root, point in ((path, b'/tmp'), (b'/', path)):
                with self.subTest(root=root, point=point):
                    line = b'22 21 8:1 ' + root + b' ' + point + b' rw - ext4 none rw\n'
                    self.check(self.mount(b'/') + line, reason='mount_inventory_unavailable')

    def test_valid_kernel_style_records(self):
        self.check(
            b'90 12 0:32 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/layers\n'
            b'91 90 0:45 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n'
            b'92 90 8:1 /bound\\040subdir /tmp/probe-other ro,relatime '
            b'master:1 propagate_from:2 - ext4 /dev/synthetic rw,errors=remount-ro\n'
            b'93 90 0:99 / /tmp/opaque rw future_tag:literal - fuse.example none rw,user_id=0\n'
        )

    def test_all_supported_path_escapes_decode_once(self):
        raw = rb'/tmp/probe\040space\011tab\012line\134040/sub'
        expected = b'/tmp/probe space\ttab\nline\\040/sub'
        self.assertEqual(supervisor.mountinfo_point(self.mount(raw).rstrip(b'\n')), expected)
        workspace = os.fsdecode(expected.rsplit(b'/', 1)[0])
        self.check(self.mount(raw), work=workspace, reason='unexpected_workspace_mount')


if __name__ == '__main__':
    unittest.main()
