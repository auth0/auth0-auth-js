import { base64url } from 'jose';

/**
 * @internal
 * The key of a Poppy Session: an opaque, stable name for the pair of an agent and a Session, for the application to
 * key its state by. Two agents can pick the same Session id, so the id alone is not a key.
 *
 * ```
 * key = base64url(SHA-256(UTF-8(cimdUrl + "\n" + sessionId)))    (no padding, 43 characters)
 * ```
 *
 * A Session id has the characters of the base64url alphabet only, so it holds no newline. The text then splits at its
 * last newline in one way only, and two different pairs never make the same text.
 *
 * **The formula is a contract between SDKs.** `@auth0/auth0-api-js` builds the key of a Session with the same formula,
 * so that an application that uses both SDKs sees one Session as one. Never change it in one SDK alone.
 *
 * @param cimdUrl - The URL of the client metadata document of the agent. It is the `sub` of the `act` claim.
 * @param sessionId - The id of the Poppy Session. It is the `poppy_sid` member of the `act` claim.
 * @returns The key: 43 characters of the base64url alphabet.
 */
export async function computePoppySessionKey(cimdUrl: string, sessionId: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${cimdUrl}\n${sessionId}`));

  return base64url.encode(new Uint8Array(digest));
}
