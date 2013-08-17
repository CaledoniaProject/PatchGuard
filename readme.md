What's Patchguard?
---
Patchguard is a kernel module designed to protect critical system calls from being tampered, e.g sys_open, socket_seq_show.

Specifically, it's capable of restoring:
- SSDT Hooks
- Inline Hooks

Important notice
---
Patchguard must be loaded ahead of any rootkits. Currently there's no way to regain tampered bytes anywhere.

Supported and fully tested on:
---
- Linux 3.2 +
- FreeBSD 9 + (Ongoing)
