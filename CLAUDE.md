# PrivacyLens: Claude Code instructions

This repo is built by **two Claude Code sessions on two laptops** at the same time.

1. Run `cat .pl-machine`. It says `WIN` or `LNX`. If it's missing or says anything else, stop and ask the user.
2. Read `docs/prompts/SHARED.md` (rules for both machines), then your own prompt file: `docs/prompts/WIN.md` or `docs/prompts/LNX.md`.
3. The spec is `docs/PrivacyLens_Features.md`.

The user will say one of:
- **"Run Phase N"**: follow SHARED.md §8 "Starting a phase".
- **"Resume"**: follow SHARED.md §8 "Resuming".
- **"Run Gate N"**: follow SHARED.md §8 "Gate N".

Golden rules (details in SHARED.md):
- Only edit paths your machine owns (SHARED.md §3). The pre-commit hook enforces this.
- Never commit to `main` directly; branch, PR, CI green, squash-merge.
- Never claim something works without running the tests and reading the output.
- Never weaken or skip a test to make it pass.
- Never put real PII, real keys, models or datasets in the repo.
- Never edit this file, `docs/prompts/**`, `docs/PrivacyLens_Features.md` or `docs/SETUP.md`.
