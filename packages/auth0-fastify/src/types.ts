import type { FastifyReply, FastifyRequest } from "fastify";
import { LogoutTokenClaims, StateData } from "@auth0/auth0-server-js";

export interface StoreOptions {
  request: FastifyRequest;
  reply: FastifyReply;
}

export interface SessionStore {
  delete(identifier: string): Promise<void>;
  set(identifier: string, stateData: StateData): Promise<void>;
  get(identifier: string): Promise<StateData | undefined>;
  deleteByLogoutToken(claims: LogoutTokenClaims, options?: StoreOptions | undefined): Promise<void>;
}