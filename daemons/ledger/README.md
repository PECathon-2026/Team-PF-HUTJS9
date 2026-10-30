# ledger

**Owner: WIN-B (moved from LNX for Sprint 1).** Metadata-only event bus over Unix sockets, reject rules, decision records, append-only hash-chained segments, stream endpoint. No network. Merkle tree and Ed25519-signed roots are Sprint 2.

Run: `ledgerd --ingest /run/pl/ledger.sock --stream /run/pl/ledger-stream.sock --dir /var/lib/pl/ledger --schemas /contracts/schemas`; `ledgerd --verify <dir>` checks the hash chain. Make: `ledger-test`, `ledger-asan` (daemons/ledger/ledger.mk).

## Ingest socket
plcommon framing (4-byte BE length + JSON). One contract message per frame; one ack frame back: `{"ok":true,"seq":N}` or `{"ok":false,"rule_id":"LG-001","code":"banned_field"}`.
Accepted schemas (metadata and sanitized zones only): event, decision_record, egress_record, liveness, isolation_counters, capability_report, attestation, merkle_proof, pipeline_timing, approval_token, browsing_policy. Everything else (page_snapshot, vault_api, ...) is rejected.

## Reject rules (fail-closed; a rejected message is never stored)
| Rule | Code | Trigger |
|---|---|---|
| LG-001 | banned_field | any object key (any depth, case-insensitive) in `value raw text_raw secret plaintext` |
| LG-002 | canary, canary_prefix | any string or key containing `PLCANARY-<16 Crockford base32>-<2 digits>` (check = base-32 value mod 97), or the bare prefix |
| LG-003 | unknown_schema, schema_invalid | not on the allow-list, or fails contract validation |
| LG-004 | too_deep, oversize | nesting > 32, frame > 4 MiB |
Every rejection is itself recorded as a `decision_record.v1` (component `ledger`, verdict `block`, rule ID, detail code); it never contains the offending content.

## Segments
`seg-NNNNNNNN.jsonl`, one entry per line `{"kind","prev","record","seq","ts_ns"}` with `prev` = SHA-256 of the previous line (first: 64 zeros). Rotated at 4 MiB, sealed read-only, fdatasync per append, torn tail truncated on restart.

## Stream socket
Subscribers receive framed JSON, never send: `{"type":"hello","stream":"ledger.stream.v0","next_seq"}`, then the retained backlog (last 1000 entries), then live `{"type":"entry","seq","ts_ns","kind","record"}` and `{"type":"stats",accepted,rejected,by_rule,by_schema,head,next_seq}` (every second). Slow subscribers are dropped.
