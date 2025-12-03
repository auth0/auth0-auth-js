/**
 * Options for serializing cookies.
 * These options are used when setting cookies in the store.
 */
export interface CookieSerializeOptions {
  domain?: string;
  expires?: Date;
  httpOnly?: boolean;
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
 */
export interface CookieHandler<TStoreOptions> {
  /**
   * Set a cookie using the framework specific integration.
   * @param name The name of the cookie to set.
   * @param value The value of the cookie to set.
   * @param options The options for serializing the cookie.
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
   * @param options The options for serializing the cookie.
   */
  deleteCookie: (name: string, storeOptions?: TStoreOptions, options?: CookieSerializeOptions) => void;
}