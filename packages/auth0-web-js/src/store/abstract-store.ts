import type { AbstractDataStore } from '../types.js';
import { JWTPayload } from 'jose';

/**
 * Abstract class that can be used to implement an Encrypted JWT State Store
 */
export abstract class AbstractStore<TData extends JWTPayload, TStoreOptions = unknown> implements AbstractDataStore<TData, TStoreOptions>
{ 
  abstract set(identifier: string, state: TData, removeIfExists?: boolean, options?: TStoreOptions | undefined): Promise<void>;
  abstract get(identifier: string, options?: TStoreOptions | undefined): Promise<TData | undefined>;
  abstract delete(identifier: string, options?: TStoreOptions | undefined): Promise<void>;
}
