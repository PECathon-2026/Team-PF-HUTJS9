# ledger

**Owner: WIN-B (moved from LNX for Sprint 1).** Metadata-only event bus over Unix sockets, reject rules, decision records, append-only hash-chained segments, stream endpoint. No network.

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

## Merkle audit log (Sprint 2)
- Leaf i is entry seq i+1: `leaf = SHA-256(0x00 || line)`, node = `SHA-256(0x01 || l || r)` (RFC 6962 / 9162). Known-answer test uses the Certificate Transparency vectors; every inclusion and consistency proof for trees up to 37 leaves is checked, plus tampering.
- Signed tree head (STH, `merkle_proof.v1` `sth`): Ed25519 over `"pl-sth-v1\n<tree_size>\n<root hex>\n<ts_ns>"`, `key_id = ledger:<8 bytes of pubkey hex>`. A new STH is appended to `<dir>/sth.jsonl` and sent on the stream (`{"type":"sth",...}`) at most once a second when the log grew. `stats` carries `tree_size`, `root`, `key_id`.
- Key: 32-byte seed generated on first start in `<dir>/ledger.key` (0600); public key in `<dir>/ledger.pub`. LIMITATION: the key sits next to the log, so a host that can rewrite the log can re-sign it. Production needs the key in a separate trust domain (vault/TPM); not done.
- `ledgerd --attestation <file>` records the attestation value as entry #0 (only on an empty log).
- `pl-audit verify <dir> [--pub f]` checks chain, every STH signature and root, and consistency between consecutive heads. `pl-audit inclusion <dir> <seq>`, `pl-audit consistency <dir> <m> <n>` print proofs (consistency adds `first_root`, not part of the contract); `pl-audit check <file> --pub f` verifies a proof file.
