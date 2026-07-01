import { expect, test } from 'vitest';
import {
  requireFields, transformSignUpRequest, transformChangePasswordRequest,
  normalizeSignUpResult, parseErrorBody,
} from './utils.js';
import { SignUpError } from './errors.js';
import type { SignUpOptions } from './types.js';

test('transformSignUpRequest maps camelCase to snake_case, omits clientId', () => {
  const wire = transformSignUpRequest({
    email: 'a@b.com', password: 'pw', connection: 'db', clientId: 'override',
    givenName: 'Jo', familyName: 'Bloggs', userMetadata: { plan: 'free' },
  });
  expect(wire).toEqual({
    email: 'a@b.com', password: 'pw', connection: 'db',
    given_name: 'Jo', family_name: 'Bloggs', user_metadata: { plan: 'free' },
  });
  expect(wire.clientId).toBeUndefined();
  expect(wire.client_id).toBeUndefined(); // client_id added by the client, not here
});

test('transformChangePasswordRequest includes organization only when set', () => {
  expect(transformChangePasswordRequest({ email: 'a@b.com', connection: 'db' }))
    .toEqual({ email: 'a@b.com', connection: 'db' });
  expect(transformChangePasswordRequest({ email: 'a@b.com', connection: 'db', organization: 'org_1' }))
    .toEqual({ email: 'a@b.com', connection: 'db', organization: 'org_1' });
});

test('normalizeSignUpResult resolves identifier from _id, user_id, id', () => {
  expect(normalizeSignUpResult({ _id: 'x', email: 'a@b.com', email_verified: false }).id).toBe('x');
  expect(normalizeSignUpResult({ user_id: 'y', email: 'a@b.com', email_verified: true }).id).toBe('y');
  expect(normalizeSignUpResult({ id: 'z', email: 'a@b.com', email_verified: true }).id).toBe('z');
});

test('normalizeSignUpResult prefers _id over user_id over id (node-auth0 precedence)', () => {
  expect(normalizeSignUpResult({ _id: 'a', user_id: 'b', id: 'c', email: 'a@b.com', email_verified: false }).id).toBe('a');
  expect(normalizeSignUpResult({ user_id: 'b', id: 'c', email: 'a@b.com', email_verified: false }).id).toBe('b');
});

test('normalizeSignUpResult defaults email to empty string when server omits it', () => {
  expect(normalizeSignUpResult({ id: 'z', email_verified: false }).email).toBe('');
});

test('normalizeSignUpResult leaves id undefined when no identifier present', () => {
  const r = normalizeSignUpResult({ email: 'a@b.com', email_verified: false, given_name: 'Jo' });
  expect(r.id).toBeUndefined();
  expect(r.email).toBe('a@b.com');
  expect(r.emailVerified).toBe(false);
  expect(r.givenName).toBe('Jo');
});

test('normalizeSignUpResult maps all optional profile fields to camelCase (T1.4)', () => {
  const r = normalizeSignUpResult({
    id: 'z', email: 'a@b.com', email_verified: true,
    username: 'jo', given_name: 'Jo', family_name: 'Bloggs', name: 'Jo Bloggs',
    nickname: 'jojo', picture: 'https://img', user_metadata: { plan: 'pro' },
  });
  expect(r).toEqual({
    id: 'z', email: 'a@b.com', emailVerified: true,
    username: 'jo', givenName: 'Jo', familyName: 'Bloggs', name: 'Jo Bloggs',
    nickname: 'jojo', picture: 'https://img', userMetadata: { plan: 'pro' },
  });
});

test('requireFields throws the given error class before any work', () => {
  expect(() => requireFields(
    { email: 'a@b.com' } as unknown as SignUpOptions, ['email', 'password'], SignUpError
  )).toThrowError(SignUpError);
});

test('requireFields rejects empty-string values', () => {
  expect(() => requireFields(
    { email: '', password: 'pw' } as unknown as SignUpOptions, ['email', 'password'], SignUpError
  )).toThrowError(SignUpError);
});

test('parseErrorBody accepts {code,description} and {error,error_description}', async () => {
  const a = await parseErrorBody(new Response(JSON.stringify({ code: 'invalid_signup', description: 'Invalid sign up' }), { status: 400 }));
  expect(a).toEqual({ error: 'invalid_signup', error_description: 'Invalid sign up' });
  const b = await parseErrorBody(new Response(JSON.stringify({ error: 'bad', error_description: 'nope' }), { status: 400 }));
  expect(b).toEqual({ error: 'bad', error_description: 'nope' });
  const c = await parseErrorBody(new Response('not json', { status: 500 }));
  expect(c).toBeUndefined();
  const d = await parseErrorBody(new Response(JSON.stringify({ code: 'x' }), { status: 400 }));
  expect(d).toEqual({ error: 'x', error_description: '' });
});
