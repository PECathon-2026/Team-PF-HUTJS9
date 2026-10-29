# Requests from LNX to the user

Things only you can do. Newest first. Owner of this file: LNX.

## U-LNX-003: allow TSan on this laptop (optional, Phase 0)
ThreadSanitizer needs `vm.mmap_rnd_bits <= 28` (this kernel's default is higher, and TSan's own workaround is blocked by Docker's seccomp profile, which we keep on). CI already sets it on its runner. To run `make test-tsan-lnx` locally:
```bash
sudo sysctl -w vm.mmap_rnd_bits=28        # until reboot
# permanent: echo 'vm.mmap_rnd_bits=28' | sudo tee /etc/sysctl.d/60-pl-tsan.conf
```
This slightly lowers address-space randomisation for all processes; skip it if you prefer and rely on CI.

## U-LNX-002: git author e-mail is a placeholder
`git config user.email` is literally `<the email on your GitHub account>` (from docs/SETUP.md). Commits get that address, so GitHub can't link them to you. Fix with `git config --global user.email <your address>`.

## U-LNX-001: docker group not active in the login session
You're in the `docker` group, but the current login session predates it, so plain `docker` gets "permission denied" (Claude works around it with `sg docker`). Log out and back in (or reboot) once.
