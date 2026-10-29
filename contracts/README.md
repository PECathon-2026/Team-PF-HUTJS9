# contracts

**Owner of this README, `OWNERS.tsv` and `lib/`: LNX.** Each schema and its fixtures are owned by the message's **producer** (listed in `OWNERS.tsv`; the pre-commit hook and `ownership.yml` resolve it).

Every message that crosses a process boundary (IPC frame payloads, ledger events, gate records, dashboard streams) is JSON validated against a schema here. Producers validate what they emit in debug/test builds; consumers validate everything they receive, always (SHARED.md §5).

## Layout

```
contracts/
  OWNERS.tsv                         schema name glob -> producer (LNX | WIN)
  schemas/<name>.v<N>.json           JSON Schema 2020-12, one message type per file
  fixtures/<name>.v<N>/valid/*.json  must validate
  fixtures/<name>.v<N>/invalid/*.json must NOT validate (one reason per file; say which in the file name)
  lib/python/pl_contracts/           Python validator, fixture checker, contract linter (`python -m pl_contracts.cli`)
  lib/cpp/                           C++ validator (`pl_contracts` CMake target) + fixture test
```

## Conventions (enforced by the linter, `make lint`)

1. **File and identity.** `schemas/<name>.v<N>.json`, `name` is `snake_case`. `$schema` is `https://json-schema.org/draft/2020-12/schema`; `$id` is `https://privacylens.invalid/contracts/<name>.v<N>.json`. `title` and `description` are required.
2. **Self-describing messages.** The top level is an object with a required `"schema"` property whose `const` is `"<name>.v<N>"`. Consumers dispatch on it.
3. **Closed shapes.** Every object schema with `properties` sets `additionalProperties: false`. Unknown shapes are rejected (spec §8 "format checks").
4. **Portable keyword subset.** Schemas must validate identically in Python (`jsonschema`, 2020-12) and C++ (`json-schema-validator`, draft-7 engine). Allowed keywords: `$schema $id $ref $defs $comment title description type properties required additionalProperties items enum const minimum maximum exclusiveMinimum exclusiveMaximum minLength maxLength pattern minItems maxItems uniqueItems minProperties maxProperties oneOf anyOf allOf not format default examples` plus the `x-pl-*` annotations below. `$ref` is local only (`#/$defs/...`); there are no cross-file references. Patterns use the ECMA-262 subset both engines share (no lookbehind, no named groups).
5. **Zone annotation.** Each schema declares `"x-pl-zone"`:
   - `raw`: core-internal, may describe captured page content; never published on the bus, never logged, never leaves `core`.
   - `vault`: the vault API and the core→vault channel. The only zone where sensitive field names are allowed.
   - `sanitized`: data the agent may see (placeholders, never values).
   - `metadata`: events, logs, ledger records, dashboard streams, gate records. Strictest zone.
6. **Banned field names.** `value`, `raw`, `text_raw`, `secret`, `plaintext` may not appear as property names anywhere outside the `vault` zone.
7. **Metadata strings are constrained.** In the `metadata` zone every string must carry `enum`, `const`, `pattern` or `format`, so no free-text field can smuggle a value. Exception: a string explicitly marked `"x-pl-scrubbed": true`, which the producer must pass through the log scrubber (plcommon/plpy) before emitting.
8. **Taint labels agree.** Any property named `taint` must use exactly the level enum of `taint_label.v1`.
9. **Fixtures exist.** At least one `valid/` and one `invalid/` fixture per schema; all valid ones pass and all invalid ones fail in **both** validators (`make test-contracts`).
10. **Synthetic data only** in fixtures (AD-09). Never real PII, cards or keys; test values use the documented canary formats.

## Versioning

- **Additive** changes (a new optional field) may stay in the same version.
- **Breaking** changes (new required field, removed field, narrowed type or enum) create `<name>.v<N+1>.json` with its own fixtures. The old version stays until the consumer acknowledges the migration request in its `done-by-<machine>.md`.

## Placeholders and field types

Placeholders look like `[REDACTED:CARD#3]`: `^\[REDACTED:[A-Z][A-Z0-9_]{1,23}#[0-9]{1,6}\]$`, numbers drawn fresh per session (spec §5). The field-type vocabulary used in placeholders, vault bindings and taint categories is the `category` enum in `taint_label.v1`; WIN's `detection` schema should use the same names (request L-001).

## Validating

```bash
make test-contracts      # every fixture, Python and C++
make lint                # includes the contract linter
python -m pl_contracts.cli validate contracts/schemas/event.v1.json some.json   # inside `make shell`
```
