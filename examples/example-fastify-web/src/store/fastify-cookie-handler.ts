import { CookieHandler, CookieSerializeOptions } from '@auth0/auth0-server-js';
import { StoreOptions } from '../types.js';

export class FastifyCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(
    storeOptions: StoreOptions,
    name: string,
    value: string,
    options?: CookieSerializeOptions
  ): void {
    storeOptions.reply.setCookie(name, value, options || {});
  }

  getCookie(storeOptions: StoreOptions, name: string): string | undefined {
    return storeOptions.request.cookies?.[name];
  }

  getCookies(storeOptions: StoreOptions): Record<string, string> {
    return storeOptions.request.cookies as Record<string, string>;
  }

  deleteCookie(storeOptions: StoreOptions, name: string): void {
    storeOptions.reply.clearCookie(name);
  }
}
