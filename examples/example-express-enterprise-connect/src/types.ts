import type { Request, Response } from 'express';

export interface StoreOptions {
  request: Request;
  response: Response;
}
