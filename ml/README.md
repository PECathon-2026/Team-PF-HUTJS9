# ml/

Owner: **WIN**. Synthetic data generators, model training, and ML tools for PrivacyLens.

- `gen/values.py`: seeded generators and validators for synthetic sensitive values (cards, Aadhaar, PAN, IFSC, UPI, phone, email, DOB, keys, canaries). Nothing here is real PII (AD-09).
- `tests/`: pytest + Hypothesis.

Until the dev image exists, run tests in a throwaway container:

```bash
docker run --rm -v "$PWD":/src -w /src/ml python:3.12 \
  sh -c 'pip -q install uv==0.7.3 && uv sync -q --frozen && uv run pytest'
```
