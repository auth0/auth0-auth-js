import { expect, test } from 'vitest';
import { EnterpriseConnectNotSupportedError } from '@auth0/auth0-auth-js';
import {
  EC_ALLOWED_METHODS,
  EC_ALLOWED_GETTERS,
  NullStateStore,
  applyEnterpriseConnectRestrictions,
} from './enterprise-connect.js';

// ─── NullStateStore ────────────────────────────────────────────────────────────

test('NullStateStore - get should return undefined', async () => {
  const store = new NullStateStore();
  expect(await store.get('key')).toBeUndefined();
});

test('NullStateStore - set should resolve without error', async () => {
  const store = new NullStateStore();
  await expect(store.set('key', {} as unknown as never, true)).resolves.toBeUndefined();
});

test('NullStateStore - delete should resolve without error', async () => {
  const store = new NullStateStore();
  await expect(store.delete('key')).resolves.toBeUndefined();
});

test('NullStateStore - deleteByLogoutToken should resolve without error', async () => {
  const store = new NullStateStore();
  await expect(store.deleteByLogoutToken('token')).resolves.toBeUndefined();
});

// ─── applyEnterpriseConnectRestrictions ────────────────────────────────────────

test('applyEnterpriseConnectRestrictions - should block methods not in EC_ALLOWED_METHODS', () => {
  class FakeClient {
    allowed() { return 'ok'; }
    blocked() { return 'should not reach'; }
  }

  const allowedMethodsBackup = new Set(EC_ALLOWED_METHODS);
  EC_ALLOWED_METHODS.clear();
  EC_ALLOWED_METHODS.add('allowed');

  const instance = new FakeClient();
  applyEnterpriseConnectRestrictions(instance);

  expect(instance.allowed()).toBe('ok');
  expect(() => instance.blocked()).toThrowError(EnterpriseConnectNotSupportedError);

  EC_ALLOWED_METHODS.clear();
  allowedMethodsBackup.forEach((m) => EC_ALLOWED_METHODS.add(m));
});

test('applyEnterpriseConnectRestrictions - should block getters not in EC_ALLOWED_GETTERS', () => {
  class FakeClient {
    get allowedGetter() { return 'ok'; }
    get blockedGetter() { return 'should not reach'; }
  }

  const allowedGettersBackup = new Set(EC_ALLOWED_GETTERS);
  EC_ALLOWED_GETTERS.clear();
  EC_ALLOWED_GETTERS.add('allowedGetter');

  const instance = new FakeClient();
  applyEnterpriseConnectRestrictions(instance);

  expect(instance.allowedGetter).toBe('ok');
  expect(() => instance.blockedGetter).toThrowError(EnterpriseConnectNotSupportedError);

  EC_ALLOWED_GETTERS.clear();
  allowedGettersBackup.forEach((g) => EC_ALLOWED_GETTERS.add(g));
});

test('applyEnterpriseConnectRestrictions - should not override the constructor', () => {
  class FakeClient {
    value = 42;
  }

  const instance = new FakeClient();
  applyEnterpriseConnectRestrictions(instance);

  expect(instance.value).toBe(42);
});

test('applyEnterpriseConnectRestrictions - blocked method error includes method name', () => {
  class FakeClient {
    doSomething() { return 'x'; }
  }

  EC_ALLOWED_METHODS.delete('doSomething');
  const instance = new FakeClient();
  applyEnterpriseConnectRestrictions(instance);

  try {
    instance.doSomething();
    expect.fail('should have thrown');
  } catch (e: unknown) {
    expect(e).toBeInstanceOf(EnterpriseConnectNotSupportedError);
    expect((e as Error).message).toContain('doSomething');
  }
});

test('applyEnterpriseConnectRestrictions - blocked getter error includes getter name', () => {
  class FakeClient {
    get someProperty() { return 'x'; }
  }

  EC_ALLOWED_GETTERS.delete('someProperty');
  const instance = new FakeClient();
  applyEnterpriseConnectRestrictions(instance);

  try {
    void instance.someProperty;
    expect.fail('should have thrown');
  } catch (e: unknown) {
    expect(e).toBeInstanceOf(EnterpriseConnectNotSupportedError);
    expect((e as Error).message).toContain('someProperty');
  }
});

// ─── Constants ─────────────────────────────────────────────────────────────────

test('EC_ALLOWED_METHODS contains the expected set', () => {
  expect(EC_ALLOWED_METHODS).toEqual(
    new Set([
      'startInteractiveLogin',
      'startEnterpriseLogin',
      'completeInteractiveLogin',
      'logout',
      'customTokenExchange',
    ])
  );
});

test('EC_ALLOWED_GETTERS contains the expected set', () => {
  expect(EC_ALLOWED_GETTERS).toEqual(new Set(['authClient']));
});
