import { EncryptJWT, jwtDecrypt } from 'jose';
import type { JWTPayload } from 'jose';

const ENC = 'A256CBC-HS512';
const ALG = 'dir';
const DIGEST = 'SHA-256';
const BIT_LENGTH = 512;
const HKDF_INFO = 'derived cookie encryption secret';

let encoder: TextEncoder | undefined;

async function deriveEncryptionSecret(secret: string, salt: string) {
  encoder ||= new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits']);

  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: DIGEST,
        info: encoder.encode(HKDF_INFO),
        salt: encoder.encode(salt),
      } as HkdfParams,
      key,
      BIT_LENGTH
    )
  );
}

export async function encrypt(payload: JWTPayload, secret: string, salt: string, expiration: number) {
  const encryptionSecret = await deriveEncryptionSecret(secret, salt);

  return await new EncryptJWT(payload)
    .setProtectedHeader({ enc: ENC, alg: ALG })
    .setExpirationTime(expiration)
    .encrypt(encryptionSecret);
}

export async function decrypt<T>(value: string, secret: string, salt: string) {
  const encryptionSecret = await deriveEncryptionSecret(secret, salt);

  const res = await jwtDecrypt<T>(value, encryptionSecret, { clockTolerance: 15 });
  return res.payload;
}
