import { describe, it, expect } from 'vitest';
import { buildPrincipal } from './principal.js';
import { VerifyAccessTokenError } from './errors.js';
import type { VerifiedAccessTokenClaims } from './types.js';

function claims(overrides: Record<string, unknown>): VerifiedAccessTokenClaims {
  return overrides as unknown as VerifiedAccessTokenClaims;
}

const BASE = {
  sub: 'user|123',
  exp: 9999999999,
};

describe('buildPrincipal', () => {
  // 1. sub missing
  it('throws VerifyAccessTokenError when sub is missing', () => {
    expect(() => buildPrincipal(claims({ exp: BASE.exp }))).toThrowError(VerifyAccessTokenError);
    expect(() => buildPrincipal(claims({ exp: BASE.exp }))).toThrowError(/Missing or blank "sub"/);
  });

  // 2. sub blank / whitespace-only
  it('throws VerifyAccessTokenError when sub is blank string', () => {
    expect(() => buildPrincipal(claims({ ...BASE, sub: '   ' }))).toThrowError(VerifyAccessTokenError);
  });

  it('throws VerifyAccessTokenError when sub is empty string', () => {
    expect(() => buildPrincipal(claims({ ...BASE, sub: '' }))).toThrowError(VerifyAccessTokenError);
  });

  // 3. valid sub → set on Principal
  it('sets sub from claims', () => {
    const p = buildPrincipal(claims({ ...BASE }));
    expect(p.sub).toBe('user|123');
  });

  // 4. client_id only → clientId = client_id
  it('uses client_id for clientId when only client_id is present', () => {
    const p = buildPrincipal(claims({ ...BASE, client_id: 'cid_abc' }));
    expect(p.clientId).toBe('cid_abc');
  });

  // 5. azp only (no client_id) → clientId = azp
  it('falls back to azp for clientId when client_id is absent', () => {
    const p = buildPrincipal(claims({ ...BASE, azp: 'azp_xyz' }));
    expect(p.clientId).toBe('azp_xyz');
  });

  // 6. both client_id and azp → client_id wins
  it('prefers client_id over azp', () => {
    const p = buildPrincipal(claims({ ...BASE, client_id: 'cid_win', azp: 'azp_lose' }));
    expect(p.clientId).toBe('cid_win');
  });

  // 7. neither client_id nor azp → null, no throw
  it('sets clientId to null when neither client_id nor azp present', () => {
    const p = buildPrincipal(claims({ ...BASE }));
    expect(p.clientId).toBeNull();
  });

  // 8. permissions absent → null
  it('sets permissions to null when permissions claim is absent', () => {
    const p = buildPrincipal(claims({ ...BASE }));
    expect(p.permissions).toBeNull();
  });

  // 9. permissions [] → [] (not null)
  it('sets permissions to empty array when permissions claim is []', () => {
    const p = buildPrincipal(claims({ ...BASE, permissions: [] }));
    expect(p.permissions).toEqual([]);
  });

  // 10. permissions populated → array
  it('sets permissions to the provided array', () => {
    const p = buildPrincipal(claims({ ...BASE, permissions: ['read:data', 'write:data'] }));
    expect(p.permissions).toEqual(['read:data', 'write:data']);
  });

  // 11. scope absent → []
  it('sets scopes to [] when scope claim is absent', () => {
    const p = buildPrincipal(claims({ ...BASE }));
    expect(p.scopes).toEqual([]);
  });

  // 12. scope present → split array (multi-scope)
  it('splits scope into scopes array', () => {
    const p = buildPrincipal(claims({ ...BASE, scope: 'openid profile email' }));
    expect(p.scopes).toEqual(['openid', 'profile', 'email']);
  });

  it('handles single scope value', () => {
    const p = buildPrincipal(claims({ ...BASE, scope: 'openid' }));
    expect(p.scopes).toEqual(['openid']);
  });

  it('filters empty strings from scope split', () => {
    const p = buildPrincipal(claims({ ...BASE, scope: '  openid  profile  ' }));
    expect(p.scopes).toEqual(['openid', 'profile']);
  });

  // 13. org_id present → string; absent → null
  it('sets orgId from org_id claim', () => {
    const p = buildPrincipal(claims({ ...BASE, org_id: 'org_abc' }));
    expect(p.orgId).toBe('org_abc');
  });

  it('sets orgId to null when org_id is absent', () => {
    const p = buildPrincipal(claims({ ...BASE }));
    expect(p.orgId).toBeNull();
  });

  // 14. expiresAt = exp value
  it('maps exp to expiresAt', () => {
    const p = buildPrincipal(claims({ ...BASE, exp: 1234567890 }));
    expect(p.expiresAt).toBe(1234567890);
  });
});
