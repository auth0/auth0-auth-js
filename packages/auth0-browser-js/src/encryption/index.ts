import { EncryptJWT, jwtDecrypt } from 'jose';
import type { JWTPayload } from 'jose';

const ENC = 'A256CBC-HS512';
const ALG = 'dir';
const DIGEST = 'SHA-256';
const BIT_LENGTH = 512;
const HKDF_INFO = 'derived storage encryption secret';

let encoder: TextEncoder | undefined;

async function deriveEncryptionSecret(secret: string, salt: string, kid: string) {
  encoder ||= new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits']);

  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: DIGEST,
        info: encoder.encode(HKDF_INFO),
        salt: encoder.encode(`${salt}${kid}`),
      } as HkdfParams,
      key,
      BIT_LENGTH
    )
  );
}

export async function encrypt(payload: JWTPayload, secret: string, salt: string, expiration: number) {
  const kid = crypto.randomUUID();
  const encryptionSecret = await deriveEncryptionSecret(secret, salt, kid);

  return await new EncryptJWT(payload)
    .setProtectedHeader({ enc: ENC, alg: ALG, kid: kid })
    .setExpirationTime(expiration)
    .encrypt(encryptionSecret);
}

export async function decrypt<T>(value: string, secret: string, salt: string) {
  const res = await jwtDecrypt<T>(
    value,
    async (protectedHeader) => {

      // This error shouldn't happen, as we always set a kid.
      // However, leaving this here as a safety net.
      if (!protectedHeader.kid) {
        throw new Error('Missing "kid" in JWE header');
      }

      return await deriveEncryptionSecret(secret, salt, protectedHeader.kid);
    },
    { clockTolerance: 15 }
  );
  return res.payload;
}
