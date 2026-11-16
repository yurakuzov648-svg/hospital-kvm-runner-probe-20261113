# Protected Workspace Boundary

**Historical BLOCK under the previous same-UID threat model.** The trusted-host decision superseded that requirement for the local readiness package. The separate-UID design below was not implemented. The standard GitHub-hosted Linux runner gives the job account passwordless sudo. A competing process with the same job UID has the same sudo authorization. Root ownership and DAC/ACL can deny a direct rename by a process operating unprivileged, but cannot enforce the requested boundary against that process exercising its existing authorization. A narrower new sudo rule would leave the existing grant in place. Read-only review supplies no evidence of an independently enforced UID boundary. That version retained its unconditional preflight block. No privileged helper or removal was added.

[GitHub-hosted runner administrative privileges](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges)

## Minimal design for an environment with separated privileges

1. A trusted bootstrap, whose code and input are outside the worker's write access, provisions a dedicated worker UID with no sudo or equivalent authority, including privileged groups, capabilities, administrative sockets and inherited administrative FDs. All QEMU and workspace consumers run as that UID. The bootstrap UID is a separate, trusted principal. Host root and the bootstrap remain in the trusted set. This changes the worker identity from the standard job UID and requires a separate approved design and Linux validation.
2. The bootstrap opens a fixed root-owned base component by component from a trusted anchor. Each component must be a directory, checked without following symlinks, with root ownership and no worker write ACL or write permission for non-root. Validate the POSIX ACL as well as the mode, including defaults on the base. A base mode of 0711 permits traversal without granting mutation. The bootstrap creates one unique, exclusive directory entry by a generated single-component name, pins its directory FD and records the name, device, inode and mount identity. Only the child directory is accessible for worker writes, with worker ownership and mode 0700. The grant never includes parent write permission. QEMU is given access only to the intended disk and ISO through that workspace under the existing device policy.
3. The worker empties its own synthetic workspace without privileges, only after QEMU is confirmed reaped. Do not schedule any privileged recursive walk. Before final removal, the trusted process checks that the recorded entry is a non-symlink directory, still the pinned inode on the expected mount, with no nested mounts and no remaining entries. It exposes no path-taking deletion interface. Its only privileged deletion is a single nonrecursive directory removal relative to the retained parent FD, using the single-component name generated during creation. A nonempty directory, mountpoint or identity mismatch is a failure. No retry after ambiguity.
4. Observe the actual worker removal process and the final directory-removal process directly. Preserve the existing monotonic deadlines and TERM/KILL/reap behavior. Confirm both successful exit statuses, absence of the recorded name and zero link count for the pinned inode, then decide. Any missing evidence blocks success.

The privileged operation has no recursive traversal or caller-selected path. The worker cannot rename an entry in the protected parent, and racing creation of an entry inside the workspace can at most make the final nonrecursive removal fail. Root code, its recorded name and the parent FD are part of the trusted boundary. This scope argument describes the proposed design. The current implementation adds zero privileged removal operations.

## Linux acceptance matrix for the future boundary

| Check | Required observation | Status |
|---|---|---|
| Same-worker-UID rename and replacement from a separate process | Both direct operations fail; initial dev/ino stays unchanged. Worker cannot exercise bootstrap authority. | NOT_RUN |
| Path structure | Symlink component, unsafe owner/mode/ACL, unexpected mount ID or nested mount blocks before removal. | NOT_RUN |
| Disk access | Same UID and groups as QEMU can read and write only its synthetic disk without parent write access. | NOT_RUN |
| Normal removal | Worker and final removal are confirmed reaped, statuses are zero, entry absent, pinned inode has zero links before deadline. | NOT_RUN |
| Error and replacement | Bad identity, nonempty directory, removal error or timeout cannot pass. | NOT_RUN |
| Scope | Invalid run identity, extra paths and external sentinels are rejected or left intact, including a sentinel targeted by a symlink inside the workspace. | NOT_RUN |

Existing local tests cover fail-closed entry, identity, time limits, serial and cleanup on fixtures. They cannot attest Linux DAC, ACL, the runner's effective grants or this unimplemented bootstrap. No Ubuntu VM, sudo, QEMU or Actions execution was used.
