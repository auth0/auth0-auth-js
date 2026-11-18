import { base64url } from 'jose';
import type { CookieHandler, CookieSerializeOptions } from '../store/cookie-handler.js';
import { ANONYMOUS_USER_PROFILE } from '../poppy/constants.js';
import type {
  PoppyActClaim,
  PoppyAgentContext,
  PoppyConfig,
  PoppyGuestData,
  PoppySessionState,
} from '../poppy/types.js';
import poppyFile from './poppy-config.json' with { type: 'json' };
import { generateToken } from './tokens.js';

// Fixtures for the Poppy tests. The values are fixed, so a test can name them.

export const POPPY_DOMAIN = 'auth.zepto.example';
export const POPPY_ISSUER = 'https://auth.zepto.example/';
export const POPPY_CLIENT_ID = 'web_app_client';
export const CIMD_URL = 'https://agent.example/agent.json';
export const SESSION_ID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
export const OTHER_SESSION_ID = 'Pq9xR2tV5wY8zB1cD4fG7h';
// base64url(SHA-256(`${CIMD_URL}\n${SESSION_ID}\n${USER_ID}`)), the same value the API SDK computes for this combination.
export const SESSION_KEY = '3X_qiM4THChkGSbMHW5cwViMXCkP6myL_fqSvIz33h0';
export const USER_ID = 'usr_Q7c1vK';
export const AGENT_ID = 'travel_agent';
export const GUEST_SUB = 'anon_poppy@z4eHq6gTjlgaMSjrplb3j5j3kb3hEDz9hZx8mgdxQLg';
// The `sub` of the person that a signed-in agent acts for, in the tokens of `agentIdToken()`.
export const PERSON_SUB = 'auth0|ana';
// The scope of the access token of a join, in the fake token endpoints of the Poppy specs.
export const JOIN_SCOPE = 'openid profile';

/**
 * The file that `auth0 poppy config` writes, for the Zepto website: the same members in the same order as the file of
 * the CLI. TypeScript types the import from the JSON, so it is what an app gets when it imports its own `poppy.json`.
 */
export type PoppyFile = typeof poppyFile;

/**
 * A new copy of the Zepto file on each call, typed as the JSON is, so a test can read and change its members. Use
 * `createPoppyConfig()` where a `PoppyConfig` is needed.
 */
export function createPoppyFile(): PoppyFile {
  return structuredClone(poppyFile);
}

/**
 * A valid config, a new object on each call: the Zepto file as it is. There is no cast here, which checks that the
 * parsed JSON of the CLI is a `PoppyConfig` by itself.
 */
export function createPoppyConfig(): PoppyConfig {
  return createPoppyFile();
}

/**
 * The `act` claim that Auth0 puts in the ID token of an agent's browser join. `overrides` replace or add members, so
 * a test can make the claim malformed.
 */
export function agentAct(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: CIMD_URL,
    poppy_sid: SESSION_ID,
    poppy_user_id: USER_ID,
    poppy_agent_id: AGENT_ID,
    ...overrides,
  };
}

/**
 * The same `act` claim as `agentAct()`, typed as the claim that the SDK gives to an app, for a test that builds a record
 * or a session from it. It is meant for claims that are well formed, so `overrides` must keep `sub`.
 */
export function agentActClaim(
  overrides: Record<string, unknown> = {}
): PoppyActClaim & { poppy_sid: string; poppy_user_id: string } {
  return agentAct(overrides) as PoppyActClaim & { poppy_sid: string; poppy_user_id: string };
}

export interface AgentIdTokenOptions {
  /** The `sub` of the token. Default: `auth0|ana`. */
  sub?: string;
  /** The `act` claim. Default: `agentAct()`. `null` leaves the claim out. */
  act?: Record<string, unknown> | null;
  /** The `sub_profile` claim. Left out when not given. */
  subProfile?: unknown;
  /** The `exp` claim, in Unix seconds. Default: one hour from now. It is the end of an agent's session in the tests. */
  exp?: number;
  /** More claims, which win over the ones above. */
  claims?: Record<string, unknown>;
}

/** A signed ID token for the web app, as Auth0 issues it after a browser join. */
export async function agentIdToken(options: AgentIdTokenOptions = {}): Promise<string> {
  const act = options.act === undefined ? agentAct() : options.act;

  return generateToken(
    POPPY_DOMAIN,
    options.sub ?? PERSON_SUB,
    POPPY_CLIENT_ID,
    undefined,
    {
      sid: 'auth0_sid_1',
      ...(act !== null && { act }),
      ...(options.subProfile !== undefined && { sub_profile: options.subProfile }),
      ...options.claims,
    },
    options.exp ?? '1h'
  );
}

/**
 * The context of an agent's browser after a join with the default `agentAct()`, as the Poppy specs make it: a guest has
 * `GUEST_SUB`, the guest profile and no scopes, and a signed-in agent has `PERSON_SUB`, no profile and the scopes of
 * `JOIN_SCOPE`. `overrides` replace or add members, and a member that is set to `undefined` is left out.
 */
export function agentContext(
  state: PoppySessionState,
  overrides: { [Member in keyof PoppyAgentContext]?: PoppyAgentContext[Member] | undefined } = {}
): PoppyAgentContext {
  const context: Record<string, unknown> = {
    kind: 'agent',
    state,
    sub: state === 'guest' ? GUEST_SUB : PERSON_SUB,
    ...(state === 'guest' && { sub_profile: ANONYMOUS_USER_PROFILE }),
    act: agentAct(),
    scopes: state === 'guest' ? [] : JOIN_SCOPE.split(' '),
    key: SESSION_KEY,
  };

  for (const [member, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete context[member];
    } else {
      context[member] = value;
    }
  }

  return context as unknown as PoppyAgentContext;
}

/** A guest as the SDK writes it, with a deadline an hour away and a token that ends in ten minutes. */
export function guestRecord(overrides: Partial<PoppyGuestData> = {}): PoppyGuestData {
  const at = Math.floor(Date.now() / 1000);

  return {
    sub: GUEST_SUB,
    sub_profile: ANONYMOUS_USER_PROFILE,
    act: agentActClaim(),
    tokenSets: [{ audience: 'default', accessToken: 'at_custom', scope: JOIN_SCOPE, expiresAt: at + 600 }],
    createdAt: at,
    expiresAt: at + 3600,
    ...overrides,
  };
}

/** What a browser holds: its cookies, with the options of the last `setCookie` for each name. */
export type Browser = Map<string, { value: string; options?: CookieSerializeOptions }>;

/**
 * Whether a browser accepts a `Set-Cookie` header for this name with these attributes (RFC 6265bis, section 4.1.3). The
 * rule is the same for a header that sets a cookie and for one that clears it, because a clear is a `Set-Cookie` header
 * too: a `__Secure-` name needs `Secure`, and a `__Host-` name needs `Secure`, `Path=/` and no `Domain`. A header that
 * breaks it is dropped, and the cookie stays as it was.
 */
export function browserAccepts(name: string, options?: CookieSerializeOptions): boolean {
  const lower = name.toLowerCase();

  if (lower.startsWith('__secure-')) {
    return options?.secure === true;
  }

  if (lower.startsWith('__host-')) {
    return options?.secure === true && options.path === '/' && options.domain === undefined;
  }

  return true;
}

/**
 * A cookie handler that keeps the cookies in a `Browser` map, passed as the store options. It behaves like a browser
 * where that matters for the stores: it drops a header that breaks the rule of a cookie name prefix (see
 * {@link browserAccepts}), and it removes a cookie that is set with a `Max-Age` of 0 or less.
 */
export class BrowserCookieHandler implements CookieHandler<Browser> {
  setCookie(name: string, value: string, options?: CookieSerializeOptions, browser?: Browser): void {
    if (!browserAccepts(name, options)) {
      return;
    }

    if (options?.maxAge !== undefined && options.maxAge <= 0) {
      browser!.delete(name);
      return;
    }

    browser!.set(name, { value, options });
  }

  getCookie(name: string, browser?: Browser): string | undefined {
    return browser!.get(name)?.value;
  }

  getCookies(browser?: Browser): Record<string, string> {
    return Object.fromEntries([...browser!].map(([name, cookie]) => [name, cookie.value]));
  }

  deleteCookie(name: string, browser?: Browser, options?: CookieSerializeOptions): void {
    if (!browserAccepts(name, options)) {
      return;
    }

    browser!.delete(name);
  }
}

/**
 * A cookie handler like the Fastify one in the README, which clears a cookie with `reply.clearCookie(name)`: its
 * `deleteCookie` drops the options, so a browser ignores it for a `__Host-` name (no `Secure`, no `Path=/`). `setCookie`
 * keeps every option. A store that clears a `__Host-` cookie with `deleteCookie` leaves the cookie in the browser here.
 */
export class LossyBrowserCookieHandler extends BrowserCookieHandler {
  override deleteCookie(name: string, browser?: Browser): void {
    super.deleteCookie(name, browser, undefined);
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
