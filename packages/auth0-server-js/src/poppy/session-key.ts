import { base64url } from 'jose';

/**
 * @internal
 * The key of a Poppy Session: an opaque, stable name for the combination of an agent, a Session id and a User ID, for the
 * application to key its state by. Two agents can pick the same Session id, and so can two Users of one agent, so the id
 * alone is not a key. Poppy finds a Session by these three (spec section 5.3).
 *
 * ```
 * key = base64url(SHA-256(UTF-8(agentId + "\n" + sessionId + "\n" + userId)))    (no padding, 43 characters)
 * ```
 *
 * The agent id is a URL in canonical form, or the id of an Auth0 agent, and a Session id has the characters of the
 * base64url alphabet only, so neither holds a newline. The User ID comes last, so two different combinations never make
 * the same text.
 *
 * **The formula is a contract between SDKs.** `@auth0/auth0-api-js` is to build the key of a Session with the same
 * formula (its Poppy support is not released yet), so that an application that uses both SDKs sees one Session as one.
 * Never change it in one SDK alone.
 *
 * @param agentId - The agent. It is the `sub` of the `act` claim: the URL of the client metadata document of the agent,
 * or the id of its Auth0 agent when it is linked to one.
 * @param sessionId - The id of the Poppy Session. It is the `poppy_sid` member of the `act` claim.
 * @param userId - The pairwise User ID. It is the `poppy_user_id` member of the `act` claim.
 * @returns The key: 43 characters of the base64url alphabet.
 */
export async function computePoppySessionKey(agentId: string, sessionId: string, userId: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${agentId}\n${sessionId}\n${userId}`));

  return base64url.encode(new Uint8Array(digest));
}
