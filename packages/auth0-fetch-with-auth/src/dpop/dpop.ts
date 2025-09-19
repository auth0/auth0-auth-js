import { DpopStorage } from './storage.js';
import { calculateThumbprint, generateKeyPair, generateProof } from './utils.js';
import type { KeyPair } from './utils.js';

export class Dpop {
  protected readonly storage: DpopStorage;

  public constructor(clientId: string) {
    this.storage = new DpopStorage(clientId);
  }

  public getNonce(id?: string): Promise<string | undefined> {
    return this.storage.findNonce(id);
  }

  public setNonce(nonce: string, id?: string): Promise<void> {
    return this.storage.setNonce(nonce, id);
  }

  protected async getOrGenerateKeyPair(): Promise<KeyPair> {
    let keyPair = await this.storage.findKeyPair();

    if (!keyPair) {
      keyPair = await generateKeyPair();
      await this.storage.setKeyPair(keyPair);
    }

    return keyPair;
  }

  public async generateProof(params: {
    url: string;
    method: string;
    nonce?: string;
    accessToken?: string;
  }): Promise<string> {
    const keyPair = await this.getOrGenerateKeyPair();

    return generateProof({
      keyPair,
      ...params
    });
  }

  public async calculateThumbprint(): Promise<string> {
    const keyPair = await this.getOrGenerateKeyPair();

    return calculateThumbprint(keyPair);
  }

  public async clear(): Promise<void> {
    await Promise.all([
      this.storage.clearNonces(),
      this.storage.clearKeyPairs()
    ]);
  }
}
