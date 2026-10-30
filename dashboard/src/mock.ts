// Mock relay (MOCK MODE ONLY). Produces messages in the same shape as the real
// stream, from synthetic placeholders; the UI labels everything as mock.
import type { StreamMsg } from './types.ts';

let n = 0;
const hex = (prefix: string) => `${prefix}-${(++n).toString(16).padStart(16, '0')}`;
const nowNs = () => Date.now() * 1e6;

const CASES = [
  { field: 'CARD', ph: '[REDACTED:CARD#3]', el: 'n42', text: 'Checkout form. Card number field n42 holds [REDACTED:CARD#3]; expiry n43; button n51 "Pay now".' },
  { field: 'PASSWORD', ph: '[REDACTED:PASSWORD#7]', el: 'n9', text: 'Login form. Field n9 holds [REDACTED:PASSWORD#7]. Email field n8 holds [REDACTED:EMAIL#2]. Button n12 "Sign in".' },
  { field: 'UPI_ID', ph: '[REDACTED:UPI_ID#1]', el: 'n21', text: 'Payment options. UPI field n21 holds [REDACTED:UPI_ID#1]; phone n22 holds [REDACTED:PHONE#4].' },
];

function svgScreen(redacted: boolean): string {
  const field = (y: number, label: string, shown: string) =>
    `<text x="40" y="${y}" fill="#667" font-size="13" font-family="sans-serif">${label}</text>` +
    (redacted
      ? `<rect x="40" y="${y + 8}" width="300" height="30" fill="#05070a"/>`
      : `<rect x="40" y="${y + 8}" width="300" height="30" fill="#fff" stroke="#bbc"/><text x="50" y="${y + 29}" fill="#223" font-size="14" font-family="monospace">${shown}</text>`);
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="560" height="340" viewBox="0 0 560 340">` +
    `<rect width="560" height="340" fill="#f4f5f8"/><rect width="560" height="38" fill="#2d3550"/>` +
    `<text x="20" y="25" fill="#fff" font-size="15" font-family="sans-serif">shop.example.test / checkout</text>` +
    field(80, 'Card number', '0000 0000 0000 0000') + field(150, 'Email', 'demo@example.test') +
    `<rect x="40" y="240" width="140" height="36" rx="4" fill="#3b6cf0"/><text x="70" y="263" fill="#fff" font-size="14" font-family="sans-serif">Pay now</text>` +
    `<text x="280" y="320" fill="#a33" font-size="12" font-family="sans-serif">MOCK FIXTURE IMAGE (synthetic)</text></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}
export const MOCK_SCREEN_USER = svgScreen(false);
export const MOCK_SCREEN_AI = svgScreen(true);

/** Starts the mock; returns a stop function and a trigger for a mock approval request. */
export function startMock(emit: (m: StreamMsg) => void, isKilled: () => boolean) {
  let seq = 0;
  let step = 0;
  const entry = (kind: string, record: unknown) => emit({ type: 'entry', seq: ++seq, ts_ns: nowNs(), kind, record });
  emit({ type: 'hello', stream: 'mock', next_seq: 1 });

  const tick = () => {
    if (isKilled()) return;
    const c = CASES[step % CASES.length];
    const blocked = step % 4 === 3;
    step++;
    const sid = 'ses-0000000000001a2b';
    entry('event', { schema: 'event.v1', event_id: hex('evt'), ts_ns: nowNs(), component: 'core', session_id: sid, type: 'detection.found', field_type: c.field, placeholder: c.ph, element_id: c.el, score: 0.97 });
    const dec = hex('dec');
    entry('decision_record', {
      schema: 'decision_record.v1', decision_id: dec, ts_ns: nowNs(), component: 'gate', session_id: sid, subject: 'egress',
      verdict: blocked ? 'block' : 'allow', rule_id: blocked ? 'GT-002' : 'GT-010', score: 0.99,
      evidence: [{ kind: blocked ? 'canary' : 'taint', detail_code: blocked ? 'canary_match' : 'only_public' }],
    });
    const messages = [{ role: 'user', content: c.text }];
    entry('egress_record', {
      schema: 'egress_record.v1', record_id: hex('egr'), request_id: hex('req'), ts_ns: nowNs(), session_id: sid, lane: 'ai',
      verdict: blocked ? 'blocked' : 'sent', decision_id: dec,
      destination: { provider: 'replay', host: 'replay.local', port: 443 },
      payload_sha256: 'ab'.repeat(32),
      ...(blocked ? {} : { payload: { messages, image_count: 1 } }),
      bytes_out: 900 + step * 37, bytes_in: blocked ? 0 : 310,
      checks: [
        { check: 'taint', result: 'pass', rule_id: 'GT-010' },
        { check: 'canary', result: blocked ? 'fail' : 'pass', ...(blocked ? { rule_id: 'GT-002' } : {}) },
        { check: 'recheck_text', result: blocked ? 'skipped' : 'pass' },
      ],
    });
    if (step % 3 === 0) {
      entry('egress_record', {
        schema: 'egress_record.v1', record_id: hex('egr'), ts_ns: nowNs(), lane: 'browsing', verdict: 'sent', decision_id: hex('dec'),
        destination: { host: 'shop.example.test', port: 443 }, bytes_out: 4200, checks: [{ check: 'domain', result: 'pass', rule_id: 'GT-020' }],
      });
    }
    emit({ type: 'stats', accepted: seq, rejected: 0, by_rule: {}, by_schema: {} });
  };

  emit({ type: 'screen', view: 'user', ts_ns: nowNs(), width: 560, height: 340, png_b64: '' });
  tick();
  const timer = setInterval(tick, 2500);
  return {
    stop: () => clearInterval(timer),
    approval: () =>
      emit({ type: 'approval_request', approval_id: hex('apr'), ts_ns: nowNs(), expires_ns: nowNs() + 15e9, action_kind: 'click: Pay now (irreversible)', risk: 0.82 }),
  };
}
