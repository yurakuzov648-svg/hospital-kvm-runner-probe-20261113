# Hospital Analytics — Trust Boundary Decision

**Historical decision record.** The original proposal was READY_FOR_TRUST_DECISION. At that point the preceding package retained BLOCK. The trusted-host model was subsequently accepted for local implementation. This record does not authorize a run.

## Decision requested

Trust the single disposable GitHub-hosted Ubuntu host, its OS and runner services, the approved and byte-verified workflow and supervisor, and privileged host preparation. Run only the reviewed steps on that host. Treat the Ubuntu guest as an isolated environment with deliberately limited host interaction. Its permitted channels are its own temporary virtual disk, the read-only neutral ISO and the bounded serial output pipe. Keep the guest without NIC, shared folders, guest agent, host management sockets and passthrough.

A hostile process with the runner UID and its passwordless sudo authorization constitutes compromise of the trusted host and is outside this trial's acceptance scope. Root ownership, ACLs and a separate UID provide no assurance against that compromise. The public experiment uses neutral content only. Hospital Analytics code, Q5/Q6 drivers, medical data and secrets stay outside it.

[GitHub runner administrative privileges](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges)

## Proposed patch

The patch removes the unconditional same-UID exclusivity block. Preflight still requires a real, canonical, runner-owned 0700 parent. A successful parent check exits directly. The workflow creates the work directory with mktemp and captures device/inode immediately; the supervisor checks that identity, the generated name under RUNNER_TEMP, owner, mode and the pinned FD before guest startup. Preserve the existing preparation failure behavior, which leaves uncertain resources for disposal of the runner.

The active baseline had no workspace mount inspection in the supervisor. The proposed diff fills that gap: it reads the Linux mount table at pinning and before removal (including in the removal child), rejects mounts on or below the workspace, and uses GNU rm with --one-file-system as defense in depth. The latter does not detect same-device bind mounts on its own. The filesystem checks are fail-closed, including on unreadable or malformed inventory. Verification of the parent path and original inode immediately before exec rejects observed replacements. The existing wait4, original inode link-count check, path absence check and stop/deadline procedure remain in force. Cleanup uses the runner UID. The patch adds no sudo grants, privileged service or privileged removal.

## Regression plan after approval

- Repeat the prior serial size, forced stop, reap, deadline and cleanup cases. Adapt the fixture API to pass the creation identity and RUNNER_TEMP. Use GNU rm on Linux. Record platform-specific skips or stubs explicitly.
- Replace the unconditional same-UID-block assertions with a valid parent preflight exit-0 case and unsafe owner/mode, symlink component and malformed input rejection cases. Verify the preflight does not allocate resources.
- Add an exact mktemp name/direct-parent test and original dev/ino mismatch before VM launch. Replace the path between creation and pinning and verify the guest launch is skipped.
- Exercise missing, malformed and escaped mountinfo, a mount at the workspace root, a nested same-device bind mount, and a similarly named sibling that must remain outside the scope check. Test with synthetic inventory first. Real mounts need separate authorization.
- Check rename, substitution, missing path with retained inode, stat errors, FD lifetime, confirmed rm and no cleanup on unconfirmed QEMU stop. Repeat the Linux zero-link check on the actual target filesystem without mocking it.
- Verify unchanged QEMU argv, ISO/SHA-256/EROFS, bounded serial output, 1200-second supervisor success-decision deadline, 30-minute job timeout and no A–D invocation.

## Residual risks and acceptance

The sequence is not atomic against a host process that can mutate names, mounts or process state after checks. The trusted-host assumption is required for the path-based unprivileged rm. The host must use a known-safe filesystem and keep competing tasks out of the workspace. A guest or hypervisor failure can leave cleanup unconfirmed. Guest isolation checks cannot attest the absence of hypervisor vulnerabilities. Compatibility with actual RUNNER_TEMP ownership/mode, GNU rm and mount reporting remains unverified. Keep BLOCK for any preflight mismatch, new threat-model requirement, or missing evidence.

Only Python syntax and patch applicability were checked. No runtime tests, publication, Actions, QEMU, VM or A–D were performed. Separate authorization is required to apply the patch and to approve any future execution.
