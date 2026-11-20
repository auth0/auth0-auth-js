import type { PoppySessionAct } from './claims.js';
import { computePoppySessionKey } from './session-key.js';
import type { PoppyAgentContext, PoppySessionState } from './types.js';

/**
 * @internal
 * What the context of an agent's browser is made from: the `sub`, the `sub_profile` and the `act` of an ID token. They
 * come from a login, from a user session or from a guest record, and they keep the names of the claims.
 */
export interface AgentContextSource {
  sub: string;
  sub_profile?: unknown;
  act: PoppySessionAct;
}

/**
 * @internal
 * The scopes in a `scope` string: the parts that a space separates. It gives `[]` when there is no scope.
 */
export function splitScopes(scope: string | undefined): string[] {
  return typeof scope === 'string' ? scope.split(' ').filter(Boolean) : [];
}

/**
 * @internal
 * Builds the context of an agent's browser. Every context is made here, so each one has the key that the API SDK gives
 * for the same Session.
 *
 * The `act` is copied whole, so a change by the app never reaches a store, and a record from a custom store cannot add
 * members to what the app sees. The `sub_profile` is left out when it is not a string, and it is never `undefined`.
 *
 * @param state - `'guest'` for a browser that joined without signing in, `'signed_in'` for a user whose session has the
 * agent in `act`.
 * @param source - The claims of the join.
 * @param scopes - The scopes of the access token of the join. A guest has none.
 */
export async function buildAgentContext(
  state: PoppySessionState,
  source: AgentContextSource,
  scopes: string[]
): Promise<PoppyAgentContext> {
  const { sub, sub_profile: subProfile, act } = source;

  return {
    kind: 'agent',
    state,
    sub,
    ...(typeof subProfile === 'string' && { sub_profile: subProfile }),
    act: structuredClone(act),
    scopes: [...scopes],
    key: await computePoppySessionKey(act.poppy_sid, act.poppy_user_id),
  };
}
