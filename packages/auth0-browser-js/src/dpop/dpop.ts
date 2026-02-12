/**
 * DPoP (Demonstrating Proof-of-Possession) implementation
 * RFC 9449: https://datatracker.ietf.org/doc/html/rfc9449
 */

export interface DpopOptions {
  domain: string;
}

export interface DpopProofParams {
  /**
   * The HTTP URL of the request
   */
  url: string;
  /**
   * The HTTP method of the request (e.g., 'GET', 'POST')
   */
  method: string;
  /**
   * Optional nonce from server to prevent replay attacks
   */
  nonce?: string;
  /**
   * Optional access token to bind the proof to
   */
  accessToken?: string;
}

/**
 * DPoP implementation for demonstrating proof-of-possession of keys
 */
export class Dpop {
  #domain: string;
  #keyPair: CryptoKeyPair | null = null;
  #nonces: Map<string, string> = new Map();

  constructor(options: DpopOptions) {
    this.#domain = options.domain;
  }

  /**
   * Generate a DPoP proof JWT
   *
   * @param params - Parameters for generating the proof
   * @returns The DPoP proof JWT
   */
  async generateProof(params: DpopProofParams): Promise<string> {
    // Ensure we have a key pair
    if (!this.#keyPair) {
      await this.#generateKeyPair();
    }

    const { url, method, nonce, accessToken } = params;

    // Create JWT header
    const header = {
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: await this.#getPublicJwk(),
    };

    // Create JWT payload
    const payload: Record<string, unknown> = {
      jti: this.#generateJti(),
      htm: method.toUpperCase(),
      htu: url,
      iat: Math.floor(Date.now() / 1000),
    };

    // Add optional nonce if provided
    if (nonce) {
      payload.nonce = nonce;
    }

    // Add access token hash if provided
    if (accessToken) {
      payload.ath = await this.#hashAccessToken(accessToken);
    }

    // Create and sign JWT
    const jwt = await this.#createSignedJwt(header, payload);
    return jwt;
  }

  /**
   * Get a stored nonce for a specific identifier
   *
   * @param id - Optional identifier for the nonce (defaults to 'default')
   * @returns The nonce string or undefined if not found
   */
  getNonce(id: string = 'default'): string | undefined {
    return this.#nonces.get(id);
  }

  /**
   * Store a nonce for a specific identifier
   *
   * @param nonce - The nonce string to store
   * @param id - Optional identifier for the nonce (defaults to 'default')
   */
  setNonce(nonce: string, id: string = 'default'): void {
    this.#nonces.set(id, nonce);
  }

  /**
   * Generate a new key pair for DPoP
   */
  async #generateKeyPair(): Promise<void> {
    this.#keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    );
  }

  /**
   * Get the public key in JWK format
   */
  async #getPublicJwk(): Promise<JsonWebKey> {
    if (!this.#keyPair) {
      throw new Error('Key pair not initialized');
    }

    const jwk = await crypto.subtle.exportKey('jwk', this.#keyPair.publicKey);

    // Remove private key material
    delete jwk.d;
    delete jwk.key_ops;

    return jwk;
  }

  /**
   * Generate a unique JTI (JWT ID) for the proof
   */
  #generateJti(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Hash the access token for the 'ath' claim
   */
  async #hashAccessToken(accessToken: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(accessToken);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert to base64url
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashBase64 = btoa(String.fromCharCode(...hashArray));
    return hashBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Create and sign a JWT
   */
  async #createSignedJwt(header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string> {
    if (!this.#keyPair) {
      throw new Error('Key pair not initialized');
    }

    // Encode header and payload
    const encodedHeader = this.#base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.#base64UrlEncode(JSON.stringify(payload));

    // Create signing input
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(signingInput);

    // Sign the data
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      this.#keyPair.privateKey,
      data
    );

    // Encode signature
    const encodedSignature = this.#base64UrlEncode(signature);

    return `${signingInput}.${encodedSignature}`;
  }

  /**
   * Base64url encode data
   */
  #base64UrlEncode(data: string | ArrayBuffer): string {
    let base64: string;

    if (typeof data === 'string') {
      base64 = btoa(data);
    } else {
      const bytes = new Uint8Array(data);
      const binary = String.fromCharCode(...bytes);
      base64 = btoa(binary);
    }

    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}
