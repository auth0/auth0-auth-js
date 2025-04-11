import { H3Event } from 'h3';

export interface StoreOptions {
  event: H3Event
}

export interface SessionConfiguration {
  rolling?: boolean;
  absoluteDuration?: number;
  inactivityDuration?: number;
}

export interface User {
  sub: string;
}