# KVM runner diagnostic
Manual, read-only capability probe of a standard Ubuntu GitHub-hosted runner.
The probe reads KVM API version only and does not create or boot a virtual machine.
If needed, a per-user ACL is applied to the ephemeral KVM device.
