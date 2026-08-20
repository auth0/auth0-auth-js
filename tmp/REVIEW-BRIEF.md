# REVIEW BRIEF — dx-parity PR stack (#248 + #249)

## The question you must answer
Do PRs **#248** (auth-js) + **#249** (server-js) **COMPLETELY and CORRECTLY** bridge the dx-parity gap?
"Complete" = every requirement below satisfied on every applicable method, both packages. "Correct" = no bug, no regression, no security hole, no concurrency leak.

## The two PRs (already pushed, MERGEABLE, stacked)
- **#248** `option-c-fullresponse` → `main`. auth-js: per-request options (was PR #230) + `fullResponse` envelope (Option C). 448 tests green.
- **#249** `feat/dx-per-request-options-a1-serverjs-rebased` → base `option-c-fullresponse`. server-js: per-request options (was #244) composed with fullResponse. 494 tests green. Stacked: its diff shows ONLY server-js delta.

Merge intent: #248 → main, then #249 retargets to main. Together they must deliver the WHOLE gap. #234/#236/#231/#230/#244 all to be CLOSED (superseded/carried).

## Local artifacts (READ THESE — do not re-derive)
- PR diffs saved: `tmp/pr248.diff` (5090 lines), `tmp/pr249.diff` (2999 lines).
- Live source is checked out on branch `feat/dx-per-request-options-a1-serverjs-rebased` (superset — contains BOTH PRs). Read any file directly under `packages/`.
- Parity spec: `.forge/features/dx-parity/SPEC-DX-PARITY.md` (Workstream A + B).
- Requirements: `.forge/features/dx-parity/REQUIREMENTS.md`.
- Metadata-ownership decision: `.forge/features/pr-surgery-metadata-strip/ANALYSIS.md`.
- Parity source-of-truth (node-auth0): `~/src/node-auth0/.forge/features/auth-separation/AUTH-JS-REQUIRED-CHANGES.md` (§5 = the two DX asks).

## THE GAP DEFINITION (authoritative)
node-auth0 → auth-js/server-js migration. dx-parity = the DX layer. Two workstreams:

### Workstream A — per-request options (MUST be complete)
Add optional trailing `requestOptions?: RequestOptions` to EVERY network public method, uniform, both packages.
```ts
interface RequestOptions { signal?: AbortSignal; headers?: Record<string,string>; customFetch?: typeof fetch; }
```
Hard constraints (from SPEC §"Threading mechanism", §"Consistency requirements"):
- **C1 openid-client v6 gives NO per-call signal/customFetch/headers** (only DPoPOptions). So signal/headers/customFetch MUST be delivered by composing a **request-scoped fetch** installed per-call.
- **C2 NO shared-config mutation** — `this.#configuration[client.customFetch]` is shared/cached; mutating it leaks across concurrent calls. Must use per-call clone / per-call fetch closure. **Concurrency-safety is critical.**
- **C3 requestOptions.customFetch must compose OVER telemetry + mTLS wrappers**, never replace them. If a per-request fetch drops the `Auth0-Client` telemetry header or breaks mTLS → BUG.
- **C4 headers merge precedence:** caller headers must NOT override `Authorization` or telemetry `Auth0-Client`. Reserved keys win.
- **C5 signal** applied into `init.signal`; abort mid-flight → request rejects.
- **C6 URL builders / non-network methods** (buildAuthorizationUrl, buildLogoutUrl, buildLinkUserUrl, buildUnlinkUserUrl, verifyLogoutToken) — requestOptions is a no-op; acceptably omitted.
- **C7 server-js mirrors** by threading requestOptions through delegating methods down to auth-js.
- **DoD:** RequestOptions exported; on every network method both packages; customFetch composes over telemetry/mTLS (test proves telemetry header present with per-request fetch); signal-cancellation test; header-merge test; existing call sites unaffected (optional arg); EXAMPLES + TSDoc.

### Workstream B (now Option C `fullResponse`) — response/metadata access
Original B = expose HTTP response metadata (headers/status/body) all-or-nothing. RESOLVED via Option C:
- **`ApiResponse<T> = { data: T; response: Response }`**, opt in with `fullResponse: true`.
- `createCapturingFetch(baseFetch)` clones the underlying Response per-invocation; `getCapturedResponse()` returns it.
- Overloads on networked methods return `ApiResponse<T>` when `fullResponse: true`, bare `T` otherwise.
- **Option C is the SINGLE owner of metadata.** There must be NO leftover Option-A metadata: no `HttpResponseMetadata` type, no `httpResponse?` field on domain objects, no `statusCode/headers/body` added to error classes, no `composeRequestFetch`/`extractHttpMetadata`/`enrich*` helpers. (Pre-existing `PasswordlessChallengeError.statusCode` is legit — keep.)
- **fullResponse concurrency:** capturing fetch is per-invocation only — NEVER a shared class field (concurrent calls would clobber capturedResponse). Verify.
- **fullResponse + cache:** a cache hit produces no live Response — `getAccessToken` with fullResponse must bypass cache or handle the no-Response case (server-js throws a clear error). Verify no silent wrong-Response.

## METHOD COVERAGE INVENTORY (verified via AST-ish scan of current branch; RO=requestOptions, FR=fullResponse overload)
### auth-js
- auth-client.ts network token methods — RO=Y + FR=Y: backchannelAuthentication, getTokenForConnection, exchangeToken, getTokenByCode, getTokenByMagicLinkCode, getTokenByRefreshToken, getTokenByPassword, getTokenByPasswordlessEmail, getTokenByPasswordlessSms, getTokenByClientCredentials.
- revokeToken RO=Y FR=- (void method — FR N/A, correct).
- initiateBackchannelAuthentication / backchannelAuthenticationGrant RO=Y.
- URL builders / verifyLogoutToken / getServerMetadata / buildLogoutUrl — RO=- FR=- (non-network; per C6 acceptable — CONFIRM each is truly non-network).
- mfa: listAuthenticators/enrollAuthenticator/deleteAuthenticator/challengeAuthenticator RO=Y; verify RO=Y FR=Y.
- passkey: register/challenge RO=Y; getTokenByPasskey RO=Y FR=Y.
- passwordless: sendEmail/sendSms/challengeWithEmail/challengeWithPhoneNumber RO=Y; getTokenByPasswordlessDbConnection RO=Y FR=Y.
- database: signUp/changePassword RO=Y.
- **CONFIRMED FLAG — anonymous-session-client.ts: createSession (L131), getTokenSilently (L197), logout (L259) — RO=- FR=-.** VERIFIED these do raw `fetch` to `/anonymous/*` (network methods). anon-sessions (#240) merged AFTER #230's method sweep, so these never received requestOptions. This is a REAL per-request-options parity HOLE unless intentionally excluded. Assess severity: does completeness of Workstream A ("EVERY network public method, uniform") require these? Note anon-session may use its own fetch path (not the AuthClient config) — check whether requestOptions even threads there and whether it's in the migration-critical surface.
### server-js
- server-client.ts: loginBackchannel RO=Y FR=Y; completePasswordless RO=Y FR=Y; getAccessToken RO=Y FR=Y; getAccessTokenForConnection RO=Y FR=Y; loginWithCustomTokenExchange RO=Y FR=Y; customTokenExchange RO=Y FR=Y; startPasswordless/completePasswordlessMagicLink/logout/requestSessionTransferToken RO=Y.
- revokeRefreshToken: RESOLVED — RO=Y (scan missed the multiline signature; sig is `(options, storeOptions?, requestOptions?)` and logout threads it through). NOT a gap.
- getUser/getSession/startInteractiveLogin/startLinkUser/startUnlinkUser/buildSessionTransferRedirect/handleBackchannelLogout RO=-. Determine which are network-delegating (should have RO) vs pure session/local (correctly omitted).
- mfa/passkey/database server sub-clients: RO=Y across the board.

## KNOWN HISTORY / RISK AREAS to probe
1. request-fetch.ts: `combineSignals` returns `{ signal, cleanup? }` (perf fix — detaches abort listeners on completion). Verify cleanup actually runs (finally block) and no listener leak; verify AbortSignal.any path vs manual fallback both correct.
2. The #249 compose: every server-js method must thread requestOptions in BOTH the `if (options.fullResponse)` branch AND the `else` branch. A missing thread in one branch = silent drop of caller's signal/headers when the other mode is used.
3. Header override safety (C4): confirm the `Authorization`-skip loop is correct and case-insensitive; confirm telemetry header applied last.
4. customFetch mTLS caveat: per-request customFetch must itself be mTLS-capable if mTLS configured — is this documented and not silently broken?
5. Backward compat: all new params optional; no existing call-site breaks.
6. Tests: are there ACTUAL tests for — telemetry-preserved-with-per-request-customFetch, signal-abort-rejects, header-merge-precedence, concurrency (Promise.all no cross-leak) on BOTH the requestOptions capture and the fullResponse capture? Or are these DoD items untested?

## YOUR OUTPUT
Rank findings by severity. For each: file:line, what's wrong, concrete failure scenario, fix. Explicitly answer: (1) Is Workstream A complete on ALL network methods both packages? (2) Is fullResponse/Option C correct + sole metadata owner? (3) Any concurrency/security/mTLS/telemetry defect? (4) Are the anonymous-session + revokeRefreshToken flags real gaps? (5) GO / NO-GO to merge, with blocking issues listed.
