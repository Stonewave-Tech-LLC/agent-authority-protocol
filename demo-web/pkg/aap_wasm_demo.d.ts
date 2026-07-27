/* tslint:disable */
/* eslint-disable */

export class DemoSession {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * JSON: { delegation_id, principal_id, agent_id, scope_summary }
     */
    delegation_summary(): string;
    constructor();
    /**
     * Re-presents the exact same signed message from the last `request()`
     * call — demonstrates replay protection via the nonce store.
     */
    replay_last(): string;
    /**
     * Issues and verifies a fresh signed request for `amount` EUR.
     * JSON: { accepted, reason, receipt_id, receipt_outcome, digest }
     */
    request(amount: number): string;
    /**
     * Revokes the one delegation this session issued.
     */
    revoke(): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_demosession_free: (a: number, b: number) => void;
    readonly demosession_delegation_summary: (a: number) => [number, number];
    readonly demosession_new: () => number;
    readonly demosession_replay_last: (a: number) => [number, number];
    readonly demosession_request: (a: number, b: number) => [number, number];
    readonly demosession_revoke: (a: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
