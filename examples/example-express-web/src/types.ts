import type { Request, Response } from 'express';

export interface StoreOptions {
  request: Request;
  response: Response;
}

export interface SessionConfiguration {
  rolling?: boolean;
  absoluteDuration?: number;
  inactivityDuration?: number;
}