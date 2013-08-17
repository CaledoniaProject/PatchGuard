What's Patchguard?
---
Patchguard protect important system calls from being tampered.

Specifically, it's capable of restoring:
- SSDT Hooks
- Inline Hooks

Important notice
---
Patchguard must be loaded ahead of any rootkits. Currently there's no way to regain tampered bytes from kernel itself.

Supported and fully tested on:
---
- Linux 3.2 +
- FreeBSD 9 + (Ongoing)
