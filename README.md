# The Sea Watcher

Implementation of *The Watcher*, a SMM rootkit:

- https://www.mitre.org/sites/default/files/publications/14-2221-extreme-escalation-presentation.pdf
  (slides 57 to 63)
- https://scumjr.github.io/2016/01/10/from-smm-to-userland-in-a-few-bytes/

This is a (dirty) proof-of-concept.

## Files

- `hijack_vdso.c`: SMM payload hijacking VDSO
- `payload.s`: shellcode written to VDSO by `hijack_vdso.c`
- `seabios/`: SMM backdoor, applied against SeaBIOS
- `shellcode.rb`: metasm script to compile `hijack_vdso.c`
- `smm-trigger-local.c`: trigger the execution of the SMM payload from a local
  account
- `smm-trigger-remote.py`: trigger the execution of the SMM payload from the
  network
- `trigger_smi.c`
- `vdso-test/`: stuff to test VDSO shellcodes
