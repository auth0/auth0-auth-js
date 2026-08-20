# Plan — dx-parity hardening: fix sentinel sweep, live validation, combineSignals test

## Context

Post-implementation hardening of the dx-parity PR stack (auth0-auth-js #248 `option-c-fullresponse` + auth0-server-js #249). Prior commits landed the Finding #1 fix + the #6 `MissingCapturedResponseError` sentinel sweep. Re-audit surfaced three gaps, ranked by impact/cost:

1. **[HIGH impact / LOW cost] #6 sweep is incomplete — a real correctness regression shipped in commit `b377e8d`.** The sweep only converted single-line `throw new Error(...)`; four MULTI-line raw throws survived. Two of them sit in try blocks whose catch now guards on `e instanceof MissingCapturedResponseError` — so the guard NEVER matches and the internal-bug error is silently wrapped into a domain error. This is wrong behavior introduced by our own commit.
2. **[HIGH impact / LOW-MED cost] No LIVE (real-tenant) validation of dx-parity.** `fullResponse` + `requestOptions` are exercised only under MSW mocks. User flagged live as important. Creds + harness already exist.
3. **[LOW impact / LOW cost] `combineSignals` manual fallback + `cleanup()` untested** (original Finding #5). Dead on all supported Node (≥20.3 has `AbortSignal.any`); coverage-only.

**Outcome:** sentinel actually reaches consumers uniformly; dx-parity proven against a real Auth0 tenant; fallback code covered. All three land on branch `option-c-fullresponse` (#248) — all touch auth-js only. No opus subagents; sonnet where delegated.

**Branch:** everything here is `option-c-fullresponse` (#248). Server-js side of #6 already correct (5 bare `if(!response) throw sentinel`, no catch, verified). After committing, rebase #249 on updated #248 (as before).

---

## Objective 1 — [HIGH/BLOCKING] Complete the #6 sentinel sweep

**File:** `packages/auth0-auth-js/src/auth-client.ts`. Four surviving raw multi-line throws (grep-confirmed): lines **382, 427, 1485, 1790**. All read `throw new Error('fullResponse: true requested but no HTTP Response was captured. This is a bug in CapturingFetch.')`.

**Two confirmed BUGS (guard can never match → error mis-wrapped):**
- **1485** (getTokenByRefreshToken fullResponse branch): try throws raw Error; catch at 1490 `if (e instanceof MissingCapturedResponseError) throw e;` → never matches → wrapped in `TokenByRefreshTokenError`.
- **1790** (getTokenByPasswordlessOtp / passwordless verify): try throws raw Error; catch at 1795 → wrapped in `PasswordlessVerifyError`.

**Two sentinel-intent-defeated sites (raw throw escapes to a wrapping caller):**
- **382** (passkey `grantRequest` capture callback) and **427** (passwordless `grantRequest` capture callback): these async-arrow callbacks have no local try/catch. The raw Error propagates to the sub-client caller, which wraps ANY error via `toOAuth2Error` into `PasskeyGetTokenError` (passkey-client.ts:257) / `PasswordlessStartError`. A sentinel thrown here would also be wrapped unless the caller re-throws it first.

**Fix:**
- Replace all four raw `throw new Error('...no HTTP Response...')` with `throw new MissingCapturedResponseError();`. (1485, 1790 immediately fix the mis-wrap since their catches already guard the sentinel.)
- For 382/427: the callbacks return through `PasskeyClient.getToken` (passkey-client.ts:255-262) and the passwordless OTP caller. Add a sentinel re-throw at the TOP of those sub-client catch blocks so the internal-bug error surfaces as-is instead of `PasskeyGetTokenError`/`PasswordlessStartError`:
  ```ts
  } catch (e) {
    if (e instanceof MissingCapturedResponseError) throw e;   // add
    // ...existing domain-error wrap
  }
  ```
  Import `MissingCapturedResponseError` from `../errors.js` in `passkey/passkey-client.ts` and `passwordless/passwordless-client.ts` (only if a capture path there can throw it — verify each sub-client's fullResponse caller has a catch; add the guard to each that wraps).
- Verify final state: `grep -n "no HTTP Response was captured" packages/auth0-auth-js/src/**/*.ts | grep -v spec` returns ONLY errors.ts:328 (the class default message).

**Test (lock the regression):** in `auth-client.spec.ts`, for getTokenByRefreshToken(fullResponse) and passwordless verify(fullResponse), stub the capture path so `getCapturedResponse()` returns undefined, assert the rejection is `instanceof MissingCapturedResponseError` (NOT `TokenByRefreshTokenError`/`PasswordlessVerifyError`). This test fails against current `b377e8d` and passes after the fix. Check existing fullResponse tests (T-AUTH-08..18 region) for the stubbing pattern to mirror.

---

## Objective 2 — [HIGH] Live-tenant validation of dx-parity

**File:** `packages/auth0-auth-js/src/auth-client.live.integration.spec.ts` (existing; `describe.skipIf(!process.env.AUTH0_M2M_CLIENT_ID)`, hits real tenant via `.env.validation`). Run: `cd packages/auth0-auth-js && npm run test:integration` (config `vitest.config.integration.ts`, include `*.live.integration.spec.ts`, setupFile loads `.env.validation`, timeout 20s, retry 2).

Add to the live suite, reusing the M2M client-credentials flow already proven by C-live-01 (safe to retry; NOT the password grants which are `retry:0` brute-force-sensitive):

- **C-live-05: fullResponse envelope.** Correct API shape (verified auth-client.ts:1824-1835):
  ```ts
  const { data, response } = await client.getTokenByClientCredentials(
    { audience: process.env.AUTH0_AUDIENCE!, fullResponse: true }
  );
  expect(data.accessToken).toBeTruthy();
  expect(response).toBeInstanceOf(Response);
  expect(response.status).toBe(200);
  // rate-limit / request-id headers actually present on a real Auth0 response
  expect(response.headers.get('x-ratelimit-limit') ?? response.headers.get('date')).toBeTruthy();
  ```
- **C-live-06: requestOptions per-call header + customFetch reach the wire.** Pass `requestOptions` with a spy `customFetch` wrapping global fetch + a custom header; assert the spy was invoked and the token still returns (proves per-request fetch composes over telemetry against a real endpoint). Also pass an already-aborted `signal` to a second call and assert it rejects (real cancellation).

**Decision (locked):** live specs only, and RUN them against the real tenant. Hono end-to-end smoke DEFERRED (not this pass). server-js `fullResponse` covered transitively via delegation over the same auth-js path.

_(hono note for later: `~/src/auth0-hono` is the SDK repo, already `file:`-linked to local `../auth0-auth-js/packages/auth0-server-js`; `examples/demo` runs a full login/getAccessToken flow; rebuild server-js → demo picks it up. Manual browser smoke only.)_

---

## Objective 3 — [LOW] combineSignals fallback + cleanup test

**File:** `packages/auth0-auth-js/src/request-fetch.spec.ts` (add `describe('combineSignals')`; `combineSignals` is exported at request-fetch.ts:18). Import it alongside existing `createCapturingFetch, composeRequestFetch`.

**Stubbing the fallback (critical detail):** the code checks `typeof AbortSignal.any === 'function'` (line 29). `vi.spyOn(AbortSignal,'any')` leaves it a function → fallback NOT taken. Must override the property directly and restore:
```ts
let originalAny: typeof AbortSignal.any;
beforeEach(() => { originalAny = AbortSignal.any; });
afterEach(() => { (AbortSignal as any).any = originalAny; });
// inside test: (AbortSignal as any).any = undefined;
```

**Cases:**
1. Both signals present, `AbortSignal.any` forced undefined → returns a combined `signal` (≠ either source) + a `cleanup` fn; aborting caller aborts combined with caller's reason; separately aborting init aborts combined with init's reason.
2. On first abort, `cleanup()` detaches BOTH listeners — spy `removeEventListener` on the NON-firing source (fired one auto-removed by `{once:true}`), assert it was called.
3. Already-aborted short-circuit (lines 37-42): pass `AbortSignal.abort(reason)` as a source → combined immediately aborted, reason propagated, `cleanup` undefined, `addEventListener` never called (spy).
4. `cleanup()` after normal completion: no abort, call cleanup → `removeEventListener` on both, no throw. Optionally drive through `composeRequestFetch` (finally at line 164) asserting cleanup runs after a successful fetch.
5. (native sanity, no stub) both present with real `AbortSignal.any` → returns signal, `cleanup` undefined.

---

## Execution order (all on `option-c-fullresponse` #248)

1. **Obj 1** — fix 4 raw throws → sentinel + sub-client re-throw guards; add regression test; grep-verify zero raw throws remain (except errors.ts default). This is a correctness bug in a shipped commit → first.
2. **Obj 3** — combineSignals test (cheap, mechanical).
3. **Run mocked suite** `npm run test --workspace=@auth0/auth0-auth-js` + build + lint → all green.
4. **Obj 2** — add C-live-05/06; run `npm run test:integration` against the real tenant → green.
5. Commit as NEW follow-up commits on top of `b377e8d` (do NOT amend — already pushed): one `fix(auth0-auth-js): complete MissingCapturedResponseError sweep` (Obj1 + Obj3 tests), one `test(auth0-auth-js): live fullResponse + requestOptions coverage` (Obj2). Then `git checkout feat/dx-per-request-options-a1-serverjs-rebased && git rebase option-c-fullresponse`.

Delegation: sonnet subagent may implement Obj1+Obj3 (edit+run mocked tests, report RED/GREEN); I verify diff + run the live suite (Obj2) myself since it hits a real tenant with real creds.

---

## Verification

- **Obj1:** `grep -rn "no HTTP Response was captured" packages/auth0-auth-js/src --include=*.ts | grep -v spec` → only `errors.ts:328`. New unit test: refresh/passwordless fullResponse with uncaptured Response rejects `instanceof MissingCapturedResponseError` (fails pre-fix, passes post-fix). Full auth-js suite green.
- **Obj3:** combineSignals tests pass with `AbortSignal.any` stubbed undefined AND with it native.
- **Obj2:** `cd packages/auth0-auth-js && npm run test:integration` → C-live-01..06 pass against the real tenant; C-live-05 shows a real `Response` with status 200 + real headers; C-live-06 shows per-request customFetch/header/abort work end-to-end.
- Build + lint clean both before and after. server-js untouched (rebase only).
