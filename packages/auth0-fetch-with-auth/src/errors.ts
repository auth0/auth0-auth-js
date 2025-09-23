/**
 * Error thrown when the wrong DPoP nonce is used and a potential subsequent retry wasn't able to fix it.
 */
export class UseDpopNonceError extends Error {
  public code: string = 'use_dpop_nonce_error';
  public newDpopNonce: string | undefined;

  constructor(newDpopNonce: string | undefined) {
    super('Server rejected DPoP proof: wrong nonce');
    this.name = 'UseDpopNonceError';
    this.newDpopNonce = newDpopNonce;
  }
}

/**
 * Error thrown when DPoP is enabled but no DPoP provider was configured.
 */
export class DpopProviderError extends Error {
  public code: string = 'dpop_provider_error';

  constructor(message: string) {
    super(message);
    this.name = 'DpopProviderError';
  }
}