// Shapes of the relay stream (see docs/requests/to-lnx.md WB-001 and
// contracts/schemas/{egress_record,decision_record,event}.v1.json).

export interface EgressCheck { check: string; result: 'pass' | 'fail' | 'skipped'; rule_id?: string }
export interface EgressRecord {
  schema: 'egress_record.v1';
  record_id: string; request_id?: string; ts_ns: number; session_id?: string;
  lane: 'ai' | 'browsing'; verdict: 'sent' | 'blocked'; decision_id: string;
  destination: { provider?: string; host: string; port: number };
  payload_sha256?: string;
  payload?: { messages: { role: string; content: string }[]; image_count: number };
  bytes_out: number; bytes_in?: number; checks: EgressCheck[];
}
export interface Evidence { kind: string; field_type?: string; placeholder?: string; element_id?: string; detail_code?: string; score?: number }
export interface DecisionRecord {
  schema: 'decision_record.v1';
  decision_id: string; ts_ns: number; component: string; session_id?: string;
  subject: string; subject_id?: string;
  verdict: 'allow' | 'block' | 'redact' | 'require_approval' | 'error';
  rule_id: string; evidence: Evidence[]; score?: number;
}
export interface BusEvent {
  schema: 'event.v1'; event_id: string; ts_ns: number; component: string; type: string;
  field_type?: string; placeholder?: string; element_id?: string; rule_id?: string; score?: number; count?: number;
}
export type Kind = 'event' | 'decision_record' | 'egress_record' | string;

export interface EntryMsg { type: 'entry'; seq: number; ts_ns: number; kind: Kind; record: unknown }
export interface StatsMsg {
  type: 'stats'; accepted: number; rejected: number;
  by_rule: Record<string, number>; by_schema: Record<string, number>; head?: string; next_seq?: number;
}
export interface HelloMsg { type: 'hello'; stream: string; next_seq: number }
export interface ScreenMsg { type: 'screen'; view: 'user' | 'ai'; ts_ns: number; width: number; height: number; png_b64: string }
export interface ApprovalRequestMsg {
  type: 'approval_request'; approval_id: string; ts_ns: number; expires_ns: number; action_kind: string; risk?: number;
}
export interface KillStateMsg { type: 'kill_state'; engaged: boolean }
export type StreamMsg = EntryMsg | StatsMsg | HelloMsg | ScreenMsg | ApprovalRequestMsg | KillStateMsg;

export type Mode = 'connecting' | 'live' | 'mock' | 'disconnected';
