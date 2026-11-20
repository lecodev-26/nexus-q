/* tslint:disable */
/* eslint-disable */

/**
 * An ML-DSA-65 key pair whose private signing material remains in WASM memory.
 */
export class WasmMlDsa65KeyPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Generate a fresh ML-DSA-65 key pair using the platform CSPRNG.
     */
    static generate(): WasmMlDsa65KeyPair;
    /**
     * Return the encoded public key. The private key is never exported.
     */
    public_key(): Uint8Array;
    /**
     * Sign a message and return its detached ML-DSA-65 signature.
     */
    sign(message: Uint8Array): Uint8Array;
}

/**
 * Encapsulation result. The shared secret is exposed for educational
 * interoperability demonstrations and must not be logged or persisted.
 */
export class WasmMlKem768Encapsulation {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Return the ML-KEM-768 ciphertext.
     */
    ciphertext(): Uint8Array;
    /**
     * Return the shared secret for local demonstration only.
     */
    shared_secret(): Uint8Array;
}

/**
 * An ML-KEM-768 key pair whose decapsulation key remains in WASM memory.
 */
export class WasmMlKem768KeyPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decapsulate a ciphertext and return the shared secret.
     */
    decapsulate(ciphertext: Uint8Array): Uint8Array;
    /**
     * Generate a fresh ML-KEM-768 key pair using the platform CSPRNG.
     */
    static generate(): WasmMlKem768KeyPair;
    /**
     * Return the encoded ML-KEM-768 public key.
     */
    public_key(): Uint8Array;
}

/**
 * Verify an ML-DSA-65 detached signature.
 */
export function ml_dsa_65_verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

/**
 * Encapsulate a fresh shared secret to an encoded ML-KEM-768 public key.
 */
export function ml_kem_768_encapsulate(public_key: Uint8Array): WasmMlKem768Encapsulation;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmmldsa65keypair_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlkem768encapsulation_free: (a: number, b: number) => void;
    readonly __wbg_wasmmlkem768keypair_free: (a: number, b: number) => void;
    readonly ml_dsa_65_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly ml_kem_768_encapsulate: (a: number, b: number, c: number) => void;
    readonly wasmmldsa65keypair_generate: (a: number) => void;
    readonly wasmmldsa65keypair_public_key: (a: number) => number;
    readonly wasmmldsa65keypair_sign: (a: number, b: number, c: number, d: number) => void;
    readonly wasmmlkem768encapsulation_ciphertext: (a: number) => number;
    readonly wasmmlkem768encapsulation_shared_secret: (a: number) => number;
    readonly wasmmlkem768keypair_decapsulate: (a: number, b: number, c: number, d: number) => void;
    readonly wasmmlkem768keypair_generate: (a: number) => void;
    readonly wasmmlkem768keypair_public_key: (a: number) => number;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
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
