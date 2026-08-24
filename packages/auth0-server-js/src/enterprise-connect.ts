import { EnterpriseConnectNotSupportedError } from '@auth0/auth0-auth-js';
import type { StateStore } from './types.js';

export const EC_ALLOWED_METHODS = new Set([
  'startInteractiveLogin',
  'startEnterpriseLogin',
  'completeInteractiveLogin',
  'logout',
  'customTokenExchange',
]);

export const EC_ALLOWED_GETTERS = new Set(['authClient']);

export class NullStateStore<TStoreOptions> implements StateStore<TStoreOptions> {
  async get() { return undefined; }
  async set() {}
  async delete() {}
  async deleteByLogoutToken() {}
}

export function applyEnterpriseConnectRestrictions(instance: object): void {
  const proto = Object.getPrototypeOf(instance);
  for (const [name, desc] of Object.entries(Object.getOwnPropertyDescriptors(proto))) {
    if (name === 'constructor') continue;
    if (desc.get && !EC_ALLOWED_GETTERS.has(name)) {
      Object.defineProperty(instance, name, {
        get: () => { throw new EnterpriseConnectNotSupportedError(name); },
        configurable: true,
      });
    } else if (typeof desc.value === 'function' && !EC_ALLOWED_METHODS.has(name)) {
      (instance as Record<string, unknown>)[name] = () => {
        throw new EnterpriseConnectNotSupportedError(name);
      };
    }
  }
}
