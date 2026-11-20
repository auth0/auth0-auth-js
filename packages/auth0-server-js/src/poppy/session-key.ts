import { base64url } from 'jose';

/**
 * @internal
 * The key of a Poppy Session: an opaque, stable name for the combination of a Session id and a User ID, for the
 * application to key its state by. Poppy finds a Session by `client_id`, `sid` and User ID together (spec section 5.3),
 * so the Session id alone is not a key.
 *
 * ```
 * key = base64url(SHA-256(UTF-8(sessionId + "\n" + userId)))    (no padding, 43 characters)
 * ```
 *
 * **The agent is not part of the key.** The `act` claim of the ID token cannot give the `client_id` in the form that the
 * `Poppy-Session` header gives it to an API: `act.sub` is the id of the Auth0 agent when the agent is linked to one, so
 * one Session would get two keys. So two agents that send the same Session id and the same User ID get the same key. What
 * keeps them apart is that an agent MUST choose its Session id at random and MUST NOT use it for another Session (section
 * 5.2), and that the Session id and the User ID stay private. The SDK cannot check how a Session id is made. The Agent ID
 * is not in the key either: it is optional, and an agent MUST send the same one in every Session JWT of a Session
 * (section 5.2), so for an agent that follows the specification it adds nothing. This is the key of the Beta: a later
 * release may add the agent to it, and then every key changes.
 *
 * The SDK makes a key only from a Session id that `findSessionActIssue` has checked, and that has the characters of the
 * base64url alphabet only, so it holds no newline. The first newline ends it and the User ID comes last, so two
 * different combinations never make the same text.
 *
 * **The formula is a contract between SDKs.** `@auth0/auth0-api-js` is to build the key of a Session with the same
 * formula (its Poppy support is not released yet), so that an application that uses both SDKs sees one Session as one.
 * Never change it in one SDK alone.
 *
 * @param sessionId - The id of the Poppy Session. It is the `poppy_sid` member of the `act` claim.
 * @param userId - The pairwise User ID. It is the `poppy_user_id` member of the `act` claim.
 * @returns The key: 43 characters of the base64url alphabet.
 */
export async function computePoppySessionKey(sessionId: string, userId: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${sessionId}\n${userId}`));

  return base64url.encode(new Uint8Array(digest));
}
