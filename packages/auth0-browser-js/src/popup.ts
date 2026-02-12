import { PopupAuthResult, PopupConfigOptions } from './types.js';
import { PopupCancelledError, PopupOpenError, PopupTimeoutError } from './errors.js';

/**
 * Default popup timeout in seconds
 */
const DEFAULT_POPUP_TIMEOUT = 60;

/**
 * Default popup window features
 */
const DEFAULT_POPUP_FEATURES = 'toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes,resizable=yes,width=500,height=600';

/**
 * Handler for popup-based authentication flows
 */
export class PopupHandler {
  /**
   * Opens a popup window for authentication and waits for the result
   *
   * @param url - The authorization URL to open in the popup
   * @param config - Configuration options for popup behavior
   * @returns A promise that resolves with the authorization code and state
   * @throws {PopupOpenError} If the popup fails to open
   * @throws {PopupTimeoutError} If the popup times out
   * @throws {PopupCancelledError} If the user closes the popup
   */
  static async openPopup(url: string, config: PopupConfigOptions = {}): Promise<PopupAuthResult> {
    const timeoutInSeconds = config.timeoutInSeconds ?? DEFAULT_POPUP_TIMEOUT;
    const closePopup = config.closePopup ?? true;

    // Open or use existing popup
    let popup: Window | null = config.popup ?? null;

    if (!popup || popup.closed) {
      popup = window.open(url, 'auth0:authorize:popup', DEFAULT_POPUP_FEATURES);
    } else {
      popup.location.href = url;
    }

    if (!popup) {
      throw new PopupOpenError('Failed to open popup window. It may have been blocked by the browser.');
    }

    // Set up timeout
    const abortController = new AbortController();
    const timeoutId = setTimeout(() => {
      abortController.abort();
    }, timeoutInSeconds * 1000);

    try {
      const result = await this.waitForPopupResult(popup, abortController.signal);

      if (closePopup) {
        popup.close();
      }

      clearTimeout(timeoutId);
      return result;
    } catch (error) {
      clearTimeout(timeoutId);

      if (popup && !popup.closed && closePopup) {
        popup.close();
      }

      throw error;
    }
  }

  /**
   * Waits for the popup to complete authentication
   *
   * @param popup - The popup window
   * @param signal - AbortSignal for timeout handling
   * @returns A promise that resolves with the authorization code and state
   */
  private static async waitForPopupResult(popup: Window, signal: AbortSignal): Promise<PopupAuthResult> {
    return new Promise<PopupAuthResult>((resolve, reject) => {
      // Handle abort (timeout)
      signal.addEventListener('abort', () => {
        reject(new PopupTimeoutError());
      });

      // Poll for popup closure
      const checkClosedInterval = setInterval(() => {
        if (popup.closed) {
          clearInterval(checkClosedInterval);
          reject(new PopupCancelledError());
        }
      }, 100);

      // Listen for postMessage from popup
      const messageHandler = (event: MessageEvent) => {
        // Verify origin matches the popup's origin
        if (event.source !== popup) {
          return;
        }

        // Check for authorization response
        if (event.data && event.data.type === 'authorization_response') {
          clearInterval(checkClosedInterval);
          window.removeEventListener('message', messageHandler);

          const { code, state, error, error_description } = event.data;

          if (error) {
            reject(new Error(error_description || error));
            return;
          }

          if (!code || !state) {
            reject(new Error('Invalid authorization response from popup'));
            return;
          }

          resolve({ code, state });
        }
      };

      window.addEventListener('message', messageHandler);

      // Cleanup on signal abort
      signal.addEventListener('abort', () => {
        clearInterval(checkClosedInterval);
        window.removeEventListener('message', messageHandler);
      });
    });
  }
}

/**
 * Sends authorization response from popup to parent window
 * Call this from your redirect callback page when it's loaded in a popup
 *
 * @param url - The callback URL containing authorization parameters
 */
export function sendPopupResponse(url: URL = new URL(window.location.href)): void {
  if (window.opener) {
    const params = new URLSearchParams(url.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');

    window.opener.postMessage(
      {
        type: 'authorization_response',
        code,
        state,
        error,
        error_description: errorDescription,
      },
      window.location.origin
    );
  }
}
