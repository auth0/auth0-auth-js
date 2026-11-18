/**
 * Options for serializing cookies.
 * These options are used when setting cookies in the store.
 *
 * @category Session Stores & Cookies
 */
export interface CookieSerializeOptions {
  domain?: string;
  expires?: Date;
  httpOnly?: boolean;
  /**
   * MaxAge value of the cookie in seconds.
   *
   * Note for implementors of {@link CookieHandler}: this value is always in seconds.
   * Some frameworks (e.g. Express) expect `maxAge` in milliseconds, so you may need to convert
   * before passing it to the underlying framework (e.g. `maxAge * 1000`).
   */
  maxAge?: number;
  path?: string;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none";
  partitioned?: boolean;
  priority?: "low" | "medium" | "high";
}

/**
 * Interface for handling cookies in a store.
 * Implementations of this interface should handle the specifics of cookie management in a framework-specific way.
 *
 * @category Session Stores & Cookies
 */
export interface CookieHandler<TStoreOptions> {
  /**
   * Set a cookie using the framework specific integration.
   * @param name The name of the cookie to set.
   * @param value The value of the cookie to set.
   * @param options The options for serializing the cookie. Pass every one of them on (`secure`, `path`, `httpOnly`,
   * `sameSite`, `maxAge`, and the others), and honour `maxAge: 0` as a request to clear the cookie. A store may clear a
   * cookie by setting it again with `maxAge: 0`: a browser ignores a header that clears a `__Host-` or `__Secure-`
   * cookie unless the header has `Secure`, so an adapter that drops attributes would leave the cookie behind.
   * @param storeOptions The options for the store, which may include framework-specific configurations.
   */
  setCookie: (
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    storeOptions?: TStoreOptions,
  ) => void;

  /**
   * Get a cookie using the framework specific integration.
   * @param name The name of the cookie to retrieve.
   * @param storeOptions The options for the store, which may include framework-specific configurations.
   * @returns The value of the cookie if it exists, or undefined if it does not.
   */
  getCookie: (name: string, storeOptions?: TStoreOptions) => string | undefined;

  /**
   * Get all cookies using the framework specific integration.
   * @param storeOptions The options for the store, which may include framework-specific configurations.
   * @returns An object containing all cookies as key-value pairs.
   */
  getCookies: (storeOptions?: TStoreOptions) => Record<string, string>;

  /**
   * Delete a cookie using the framework specific integration.
   * @param name The name of the cookie to delete.
   * @param storeOptions The options for the store, which may include framework-specific configurations.
   * @param options The options for serializing the cookie. A browser ignores the header that clears a cookie whose name
   * has the `__Host-` or `__Secure-` prefix unless that header has `Secure` (and, for `__Host-`, `Path=/` and no
   * `Domain`), so pass `secure`, `path` and `domain` on to the clearing header, as well as `httpOnly` and `sameSite`.
   * The `StatelessPoppyGuestStore` has a cookie with the `__Host-` prefix, and it does not depend on this: it clears that
   * cookie with `setCookie`, which every handler passes the options on for. Your own cookies with such a prefix do.
   */
  deleteCookie: (name: string, storeOptions?: TStoreOptions, options?: CookieSerializeOptions) => void;
}