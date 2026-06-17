/**
 * Polyfills required for the Cloudflare Workers test environment.
 *
 * MSW imports BroadcastChannel in its core module (ws.mjs) to support
 * WebSocket handler messaging, even when WebSocket features are not used.
 * The Workers runtime does not expose BroadcastChannel as a global when
 * nodejs_compat is enabled, so we provide a stub here.
 */
if (typeof BroadcastChannel === 'undefined') {
  globalThis.BroadcastChannel = class BroadcastChannel {
    readonly name: string;
    onmessage: null = null;
    onmessageerror: null = null;

    constructor(name: string) {
      this.name = name;
    }

    postMessage(): void {
      /* Empty */
    }
    close(): void {
      /* Empty */
    }
    addEventListener(): void {
      /* Empty */
    }
    removeEventListener(): void {
      /* Empty */
    }
    dispatchEvent(): boolean {
      return false;
    }
  };
}
