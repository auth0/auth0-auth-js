import { base64url } from 'jose';
import type { CookieHandler, CookieSerializeOptions } from '../store/cookie-handler.js';
import type { PoppyConfig } from '../poppy/types.js';
import { generateToken } from './tokens.js';

// Fixtures for the Poppy tests. The values are fixed, so a test can name them.

export const POPPY_DOMAIN = 'auth.zepto.example';
export const POPPY_ISSUER = 'https://auth.zepto.example/';
export const POPPY_CLIENT_ID = 'web_app_client';
export const CIMD_URL = 'https://agent.example/agent.json';
export const SESSION_ID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
export const OTHER_SESSION_ID = 'Pq9xR2tV5wY8zB1cD4fG7h';
// base64url(SHA-256(`${CIMD_URL}\n${SESSION_ID}`)), the same value the API SDK computes for this pair.
export const SESSION_KEY = 'TCKalJy8Oz7hl1YTKAJt86LQcaiaLsYmFX-cLwiaJ4c';
export const USER_ID = 'usr_Q7c1vK';
export const AGENT_ID = 'travel_agent';
export const GUEST_SUB = 'anon_poppy@z4eHq6gTjlgaMSjrplb3j5j3kb3hEDz9hZx8mgdxQLg';

/**
 * A valid config, a new object on each call. It has the fields the API SDK reads too (`identifier`,
 * `public_origin` and `agents`), as the real file does.
 */
export function createPoppyConfig(): PoppyConfig {
  // Not typed as `PoppyConfig` here, so the fields that this SDK does not read do not fail the excess property check.
  const config = {
    protocol_version: '0.3',
    organization: { name: 'Zepto', domain: 'zepto.example' },
    issuer: POPPY_ISSUER,
    scopes: {
      'orders:read': { description: 'See your orders.', hints: { changes: 'none', personal_data: true } },
      checkout: { description: 'Place orders and pay.', hints: { changes: 'irreversible', personal_data: true } },
    },
    apis: [
      {
        type: 'openapi',
        identifier: 'https://zepto.example/api',
        url: 'https://zepto.example/api/openapi.json',
        public_origin: 'https://zepto.example',
        description: 'Orders and checkout',
      },
    ],
    web: {
      client_id: POPPY_CLIENT_ID,
      browser_session_endpoint: 'https://auth.zepto.example/poppy/web_app_client/browser-session',
    },
    agents: [CIMD_URL],
  };

  return config;
}

/**
 * The `act` claim that Auth0 puts in the ID token of an agent's browser join. The Session ends one hour from the
 * time of the call. `overrides` replace or add members, so a test can make the claim malformed.
 */
export function agentAct(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: CIMD_URL,
    poppy_sid: SESSION_ID,
    poppy_user_id: USER_ID,
    poppy_agent_id: AGENT_ID,
    poppy_session_exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  };
}

export interface AgentIdTokenOptions {
  /** The `sub` of the token. Default: `auth0|ana`. */
  sub?: string;
  /** The `act` claim. Default: `agentAct()`. `null` leaves the claim out. */
  act?: Record<string, unknown> | null;
  /** The `sub_profile` claim. Left out when not given. */
  subProfile?: unknown;
  /** The `exp` claim, in Unix seconds. Default: two hours from now. */
  exp?: number;
  /** More claims, which win over the ones above. */
  claims?: Record<string, unknown>;
}

/** A signed ID token for the web app, as Auth0 issues it after a browser join. */
export async function agentIdToken(options: AgentIdTokenOptions = {}): Promise<string> {
  const act = options.act === undefined ? agentAct() : options.act;

  return generateToken(
    POPPY_DOMAIN,
    options.sub ?? 'auth0|ana',
    POPPY_CLIENT_ID,
    undefined,
    {
      sid: 'auth0_sid_1',
      ...(act !== null && { act }),
      ...(options.subProfile !== undefined && { sub_profile: options.subProfile }),
      ...options.claims,
    },
    options.exp ?? '2h'
  );
}

/** What a browser holds: its cookies, with the options of the last `setCookie` for each name. */
export type Browser = Map<string, { value: string; options?: CookieSerializeOptions }>;

/** A cookie handler that keeps the cookies in a `Browser` map, passed as the store options. */
export class BrowserCookieHandler implements CookieHandler<Browser> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, browser?: Browser): void {
    browser!.set(name, { value, options });
  }

  getCookie(name: string, browser?: Browser): string | undefined {
    return browser!.get(name)?.value;
  }

  getCookies(browser?: Browser): Record<string, string> {
    return Object.fromEntries([...browser!].map(([name, cookie]) => [name, cookie.value]));
  }

  deleteCookie(name: string, browser?: Browser): void {
    browser!.delete(name);
  }
}

// A compact JWE with the header that is given and made-up bytes for the rest. jose reads and checks the header before
// it opens anything, so the header decides what a store does with the cookie. The made-up bytes are never reached.
function forgedJwe(header: string | Record<string, unknown>): string {
  return [
    base64url.encode(typeof header === 'string' ? header : JSON.stringify(header)),
    '',
    base64url.encode(new Uint8Array(16).fill(1)),
    base64url.encode(new Uint8Array(32).fill(2)),
    base64url.encode(new Uint8Array(32).fill(3)),
  ].join('.');
}

const FORGED_KID = 'a8c6f4de-0000-4000-8000-000000000000';

/**
 * Values of the guest cookie that a visitor can make by hand, and so can another site on the same domain. Each is a JWE
 * that jose refuses in its own way, so each fails at a different step on the way to the plaintext. None of them opens
 * with any secret, and a guest store must read every one as no guest.
 */
export const FORGED_GUEST_COOKIES: ReadonlyArray<{ name: string; value: string }> = [
  { name: 'a header with no kid', value: forgedJwe({ alg: 'dir', enc: 'A256CBC-HS512' }) },
  {
    name: 'an enc that jose does not support',
    value: forgedJwe({ alg: 'dir', enc: 'A256CBC-HS999', kid: FORGED_KID }),
  },
  {
    name: 'an alg that needs a key pair',
    value: forgedJwe({ alg: 'RSA-OAEP', enc: 'A256CBC-HS512', kid: FORGED_KID }),
  },
  {
    name: 'an alg that jose does not allow by default',
    value: forgedJwe({ alg: 'PBES2-HS256+A128KW', enc: 'A256CBC-HS512', kid: FORGED_KID }),
  },
  { name: 'a header that is not JSON', value: forgedJwe('not json') },
];
