# tools/hooks

**Owner: LNX.** The repo guard. `pre-commit` runs `pl_hook.py`, which rejects staged files this machine doesn't own (`tools/ownership.tsv`, schemas through `contracts/OWNERS.tsv`), USER paths without `PL_USER_COMMIT=1`, files over 5 MB, CRLF, model/data/key file types and likely secrets (built-in patterns always; gitleaks too when available). `ownership.yml` runs the same checker on PRs by branch prefix.

Install with `make hooks`. Never bypass it.
