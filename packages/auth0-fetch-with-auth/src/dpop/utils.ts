import * as dpopLib from 'dpop';

export const DPOP_NONCE_HEADER = 'dpop-nonce';

export type KeyPair = Readonly<dpopLib.KeyPair>;

type GenerateProofParams = {
  keyPair: KeyPair;
  url: string;
  method: string;
  nonce?: string;
  accessToken?: string;
};

function normalizeUrl(url: string): string {
  const parsedUrl = new URL(url);

  /**
   * "The HTTP target URI (...) without query and fragment parts"
   * @see {@link https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2-4.6}
   */
  parsedUrl.search = '';
  parsedUrl.hash = '';

  return parsedUrl.href;
}

export function generateProof({
  keyPair,
  url,
  method,
  nonce,
  accessToken
}: GenerateProofParams): Promise<string> {
  const normalizedUrl = normalizeUrl(url);

  return dpopLib.generateProof(
    keyPair,
    normalizedUrl,
    method,
    nonce,
    accessToken
  );
}
