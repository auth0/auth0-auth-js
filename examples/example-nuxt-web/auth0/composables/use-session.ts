import type { SessionData } from '@auth0/auth0-server-js';

export const useSession = () => useState<SessionData | undefined>('auth0_session', () => undefined);
