import { SetMetadata } from '@nestjs/common';

export const PROTECTED_KEY = 'AUTH0_PROTECTED';
export const Protected = ({ scopes }: { scopes?: string[] } = {}) =>
  SetMetadata(PROTECTED_KEY, { scopes });
