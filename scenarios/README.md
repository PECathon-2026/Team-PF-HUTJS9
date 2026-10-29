# scenarios/

Owner: **WIN**. The five required scenario pages (spec §15): login, checkout, customer support chat, video call, developer settings. Plain HTML/CSS/JS; no network access from the pages.

- `pages/<name>/`: templates. `{{slot}}` markers are filled with synthetic values from `ml/gen/values.py`.
- `plscen/`: the builder. `python -m plscen.build [--seed N] [--out DIR]` writes
  - `build/site/<name>/`: the served pages (what the `sites` container will serve),
  - `build/truth/<name>.json`: ground truth (type, canonical value, shown form, selector, channel). **Never served**: it holds the answers.
- Rendered output is gitignored. It contains key-shaped strings and canaries, and it can be rebuilt from the seed (AD-08).
- Channels covered: input values, hidden inputs, text, split spans, `aria-label`, `alt`, `title`, `data-*`, URL query, images, canvas (drawn avatars + screen share), plus zero-width and full-width obfuscation. Decoys (a non-Luhn order number) must *not* be redacted.
- Video-call faces are cartoon avatars drawn on a canvas. No photos of people.

Tests (until the dev image exists):

```bash
tools/win/pyrun.sh scenarios uv run pytest                 # structure, validity, completeness, determinism
# real-browser render test (headless Chromium):
docker run --rm --ipc=host -v "$PWD":/src -w /src/scenarios mcr.microsoft.com/playwright/python:v1.52.0-noble \
  sh -c 'pip -q install --break-system-packages uv==0.7.3 && uv sync -q --frozen --group browser --python /usr/bin/python3 && uv run pytest -m browser'
```
