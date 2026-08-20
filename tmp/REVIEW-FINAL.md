# dx-parity PR stack (#248 + #249) — 2-Pass Review Verdict

**Date:** 2026-08-20
**Branches:** #248 `option-c-fullresponse` → main; #249 `feat/dx-per-request-options-a1-serverjs-rebased` → #248 (stacked).
**Question:** Do #248 + #249 completely + correctly bridge the dx-parity gap?

---

## RESUME CONTEXT (cold-start — read first)

**Repo:** `/Users/tushar.pandey/src/auth0-auth-js` (npm workspaces + turbo monorepo; packages `@auth0/auth0-auth-js` + `@auth0/auth0-server-js`). NOT pnpm — build/test/lint via `npm run <script> --workspace=<pkg>`.

**What this feature is.** node-auth0 is being split; auth code moves to the auth-js/server-js stack. "dx-parity" = the DX layer that must exist before customers migrate. Two asks (node-auth0 `~/src/node-auth0/.forge/features/auth-separation/AUTH-JS-REQUIRED-CHANGES.md` §5):
1. **Per-request options** — optional trailing `requestOptions?: RequestOptions {signal, headers, customFetch}` on every network method, both packages. (was PR #230 auth-js / #244 server-js)
2. **Response/metadata access** — originally "Workstream B" (metadata fields on returns/errors); that approach ("Option A") was ABANDONED. Replaced by **Option C**: opt-in `fullResponse: true` → returns `ApiResponse<T> = { data, response }` envelope. Option C is the SINGLE owner of all HTTP-response-metadata.

**How we got here (PR surgery).** 4 stale PRs (#230/#234/#236/#244) were built on the dead Option-A assumption. A surgery (plan: `~/.claude/plans/2fd84ff-check-pr-surgery-metadata-strip-silly-possum.md`; analysis: `.forge/features/pr-surgery-metadata-strip/ANALYSIS.md`) consolidated them:
- Option C was found as UNCOMMITTED working-tree changes → committed to branch `option-c-fullresponse`, rebased onto #230's newest plumbing.
- #244 server-js rebased on top, its `requestOptions` COMPOSED with Option C's `fullResponse` in every method.
- Result = 2 clean stacked branches, pushed, PRs opened.

**Current PR state (as of review):**
- **#248** `option-c-fullresponse` → `main`. auth-js: per-request options + fullResponse. 448 tests green, MERGEABLE.
- **#249** `feat/dx-per-request-options-a1-serverjs-rebased` → base `option-c-fullresponse` (STACKED — diff shows server-js only). 494 tests green, MERGEABLE.
- Merge plan: merge #248 → main, then #249 auto-retargets to main.
- **To be CLOSED by human (superseded/carried, none closed yet):** #230, #234, #236, #244, #231.
- Backup branch: `option-c-snapshot-backup` (@ e2cebf5, pre-rebase Option C snapshot).

**Verification harness (all green on branch `feat/dx-per-request-options-a1-serverjs-rebased`, the superset containing BOTH PRs):**
```
npm run build --workspace=@auth0/auth0-auth-js && npm run test --workspace=@auth0/auth0-auth-js && npm run lint --workspace=@auth0/auth0-auth-js
npm run build --workspace=@auth0/auth0-server-js && npm run test --workspace=@auth0/auth0-server-js && npm run lint --workspace=@auth0/auth0-server-js
```

**This review (2 passes, both opus, inline):** Pass 1 = deep code+test+security (report `tmp/PASS1-REPORT.md`). Pass 2 = adversarial quorum (transcript in agent output). Supporting artifacts: `tmp/REVIEW-BRIEF.md` (gap definition + method-coverage inventory), `tmp/pr248.diff`, `tmp/pr249.diff`.

**STATUS OF FIX:** Finding #1 (the blocker) is **DOCUMENTED, NOT YET FIXED** (per owner instruction). Nothing in the working tree changed for the fix. All other findings also open. Next action when resumed: apply Finding #1 fix + regression test #3, then decide on #2/#4-#7, then merge.

---

## VERDICT: GO-WITH-CONDITIONS (collective confidence 0.86)

Pass 1 (deep code+test+security, opus) returned GO / no blockers.
Pass 2 (adversarial quorum, opus) **OVERTURNED to GO-WITH-CONDITIONS** — found one HIGH concurrency-correctness defect Pass 1 missed. Parent independently git-verified the defect (see §Verification).

Merge blocked ONLY on Finding #1 (+ its regression test). Everything else is recommended or fast-follow.

---

## Finding #1 — [HIGH / BLOCKING] mfa.verify(fullResponse:true) mutates the shared cached Configuration

**File:** `packages/auth0-auth-js/src/mfa/mfa-client.ts:373`

**Defect.** In the `fullResponse` branch, `verify` does:
```ts
const baseFetch = (configuration[client.customFetch] as typeof fetch);   // 371
const capturingFetch = createCapturingFetch(baseFetch ?? fetch);          // 372
configuration[client.customFetch] = capturingFetch;                        // 373  <-- mutates shared object
```
`configuration` comes from `this.#getConfiguration(requestOptions)` (mfa-client.ts:349), wired in auth-client.ts:335-336 to `(await this.#discoverForRequest(requestOptions)).configuration`. When `requestOptions` is **undefined**, `#discoverForRequest` returns the **shared memoized `this.#configuration`** (auth-client.ts:496-498 → #discover 515-519, no clone). So line 373 writes a per-call capturingFetch onto the SDK-wide shared Configuration.

**This is the exact C2 hazard the SPEC named as the core design risk** (SPEC-DX-PARITY.md:46 "mutating [shared config customFetch] leaks across concurrent calls").

**Failure scenario (concrete).** Two concurrent `authClient.mfa.verify({...,fullResponse:true})` calls, no requestOptions (the most natural call shape), discovery already warm:
1. Call A: `config[customFetch] = capturingFetchA`.
2. Call B overwrites: `config[customFetch] = capturingFetchB` before A's `genericGrantRequest` reads it.
3. Both requests now fetch through `capturingFetchB`.
4. `capturingFetchA.getCapturedResponse()` → `undefined` → **Call A throws the spurious "no HTTP Response was captured. This is a bug in CapturingFetch" error** (mfa-client.ts:388), OR A returns B's Response (cross-caller Response leak).

**Secondary defect.** The mutation is **never reverted**. After any fullResponse verify, the shared config's `customFetch` stays a stale capturingFetch closure holding a cloned Response → memory retention, and subsequent *non*-fullResponse verifies silently run through a capturing wrapper.

**Why the whole codebase is safe EXCEPT here.** Every other capture site builds a FRESH config and never touches the shared one:
- backchannelAuthentication (auth-client.ts:732-739): `captureConfig = await #createConfiguration(serverMetadata, capturingFetch)`.
- passkey grantRequest capture (auth-client.ts:369-371): `configuration = await #createConfiguration(serverMetadata, capturingFetch)` then mutates THAT fresh object.
- getTokenByRefreshToken / getTokenByCode / etc: all via `#discoverForRequest` fresh-config path or `#createConfiguration`.
mfa.verify is the LONE site that mutates the object returned by `getConfiguration` instead of building its own.

**Fix (NOT YET APPLIED — per instruction).** Mirror the backchannel pattern: build a dedicated capture config, never mutate the injected one. Complication: `MfaClient` only receives `getConfiguration` (which can return the shared config); it has NO access to `#createConfiguration`. So the fix requires one of:
- (a) Inject a config-factory into MfaClient (e.g. `createCaptureConfiguration: (capturingFetch) => Promise<Configuration>`) analogous to how auth-client builds fresh configs, and use it in the fullResponse branch. Cleanest; matches existing architecture.
- (b) Change the `getConfiguration` provider so that when capture is needed it always returns a fresh (non-shared) Configuration — e.g. add a `capture` flag to the provider signature mirroring `GrantRequestFn`'s `capture?: boolean` (passkey/types.ts).
- (c) Clone the Configuration inside verify before mutating. Requires Configuration to be cheaply cloneable (SPEC OQ-A3 flagged this as unverified) — riskier.
Recommend (a) or (b) — they reuse the proven fresh-config mechanism. ~5-10 line change + regression test.

**Regression test required (Action #3 below).** `Promise.all([verify(fullResponse), verify(fullResponse)])` with no requestOptions → each gets its own Response, neither throws the spurious capture-bug error.

---

## Findings #2-#7 (recommended pre-merge, non-blocking)

**#2 — [MED / material] Authorization-drop test is tautological.**
`per-request-options.integration.spec.ts:238-245` (C-230-06) exercises via getTokenByClientCredentials (auth in body). Assertion guarded by `if(authHeader){...}` (line 242); guard body never runs. Deleting the case-insensitive `authorization` skip at request-fetch.ts:150 would NOT fail this test. The reserved-key protection is unproven. **Fix:** direct unit test on `composeRequestFetch` with `{Authorization:'attacker'}` and `{authorization:'attacker'}` caller headers, assert dropped. Security-adjacent (C4). Material because it guards the class of Finding #1.

**#3 — [MED / material] No concurrency test on any fullResponse capture path.**
`C-230-11` (spec:421-462) covers the requestOptions/header path only, not fullResponse capture, not mfa.verify. This is the exact test that would have caught Finding #1. **Fix:** Promise.all concurrency test over a fullResponse capture path incl. mfa.verify.

**#4 — [MED] `if(!capturedResponse) throw` branches untested.**
7 auth-js + 4 server-js sites (auth-client.ts:375,420,747,1000,1101,1313,1478; server-client.ts:699,908,1184,1303,1486). No test forces `getCapturedResponse()===undefined`. **Fix:** stub CapturingFetch returning undefined, assert throw.

**#5 — [LOW→MED, disputed] combineSignals manual fallback + cleanup untested.**
request-fetch.ts:34-61 (manual AbortController fallback + removeEventListener cleanup) never executes on Node ≥20.3 (AbortSignal.any always present). `combined.cleanup?.()` at line 164 unproven. Expert A: LOW (dead on supported runtimes, logic correct on inspection). Expert C: material (test-hygiene that would catch this bug class). **Fix:** unit-test combineSignals with `AbortSignal.any` stubbed undefined; assert both listeners detached after cleanup() and after normal completion.

**#6 — [LOW] Fragile substring error-sniffing for the capture-bug error.**
Catch blocks distinguish the internal bug-error by substring: backchannel checks `e.message.includes('no HTTP Response')` (auth-client.ts:752); others check `includes('CapturingFetch')` (mfa-client.ts:392; auth-client.ts:1005,1106,1323). Inconsistent + brittle: a server error containing "CapturingFetch" would be misrouted; a future string edit breaks one check style. **Fix:** dedicated `MissingCapturedResponseError` sentinel class, branch on `instanceof`.

**#7 — [LOW] Auth0-Client reserved-key protection is implicit.**
`composeRequestFetch` (request-fetch.ts:145-155) explicitly skips only `authorization`; caller-supplied `Auth0-Client` protection relies solely on the telemetry wrapper running last (telemetry.ts:49). Docstrings (request-fetch.ts:118-120, types.ts:104) claim it "cannot be overridden" as if enforced here. If telemetry wrapper is ever reordered/made conditional → silent caller override. **Fix:** skip `auth0-client` in the same reserved-key loop, or comment binding the guarantee to wrapper ordering.

---

## Finding #8 — [FOLLOW-UP, non-blocking] anonymous-session per-request-options parity gap

**Files:** `packages/auth0-auth-js/src/anonymous-session/anonymous-session-client.ts:131 (createSession), 197 (getTokenSilently), 259 (logout)`

These 3 public NETWORK methods (raw fetch to `/anonymous/token`, `/anonymous/logout`) accept NO `requestOptions` — cannot cancel, add per-call headers, or one-off customFetch. Violates Workstream A "EVERY network public method, uniform."

**BUT out of the dx-parity/migration parity surface.** node-auth0 `AUTH-JS-REQUIRED-CHANGES.md` §5 lists only per-request-options + response-headers as the DX asks; the G-table (G1-G8) has no anonymous sessions. Anon-sessions arrived via #240 (merged to main AFTER the #230 method sweep) and is filed as a deferred nit. Telemetry is intact (constructor passes telemetry-wrapped customFetch, auth-client.ts:444); no security defect. **Fast-follow, do not block the stack.**

Also non-blocking cleanup: 5 `it.skip` C-244 integration stubs (`per-request-options.integration.spec.ts:72-129`) are redundant (delegation covered by server-client.spec.ts A1-A10, 8920-9700) — delete or un-skip to stop signalling false coverage.

---

## What both passes CONFIRM (no action needed)

1. **fullResponse / Option C is the SOLE metadata owner.** Grep-verified: no HttpResponseMetadata, no extractHttpMetadata/enrich*, no httpResponse? field on domain objects, no statusCode/headers/body added to error classes. Only statusCode residents = pre-existing PasswordlessChallengeError (legit) + separate auth0-api-js package (out of stack).
2. **fullResponse overload resolution works** (literal-true overload more specific; verified getTokenByCode/RefreshToken/exchangeToken/mfa.verify).
3. **fullResponse + cache correct + tested** (server-js getAccessToken: plain cache-hit returns early no-forward at server-client.ts:1131-1133; fullResponse cache-hit falls through to live refresh so envelope always has real Response; tested server-client.spec.ts:8532-8575, A8 9477/9522).
4. **Concurrency safe EVERYWHERE EXCEPT Finding #1.** All auth-client token methods + passkey + passwordless build fresh configs per call, never mutate shared this.#configuration.
5. **Header injection safe** (case-insensitive Authorization skip; telemetry applied last) — modulo the tautological test (#2) and implicit Auth0-Client protection (#7).
6. **mTLS correctly caveated** (per-request customFetch re-wrapped telemetry-only NOT mTLS; documented types.ts:107-115, request-fetch.ts:136-138, EXAMPLES.md).
7. **Telemetry preserved** with per-request customFetch (createTelemetryFetch(perRequestFetch); tested spec:256-286).
8. **revokeRefreshToken threads requestOptions correctly** (server-client.ts:1327/1367/1380/1402) — NOT a gap.
9. **server-js delegation forwarding well tested** (A1-A10, server-client.spec.ts:8920-9700).
10. **server-js getUser/getSession/startInteractiveLogin correctly omit requestOptions** (pure store reads / URL build, no network).
11. **G8 getUserInfo does not exist** in this stack — not a regression, separate gap.

---

## Ranked Action Items

| # | Sev | Action | Blocking | Conf |
|---|-----|--------|----------|------|
| 1 | HIGH | Fix mfa-client.ts:373 shared-config mutation (fresh capture config, options a/b) | **YES** | 0.9 |
| 3 | MED | Concurrency test on fullResponse capture incl. mfa.verify (catches #1 class) | with #1 | 0.85 |
| 2 | MED | Real composeRequestFetch Authorization-drop unit test (replace tautological C-230-06) | rec | 0.85 |
| 4 | MED | Test the no-captured-Response throw branches | rec | 0.7 |
| 5 | LOW/MED | Unit-test combineSignals fallback + cleanup | disputed | 0.6 |
| 6 | LOW | MissingCapturedResponseError sentinel, drop substring sniffing | rec | 0.75 |
| 7 | LOW | Explicitly skip Auth0-Client in reserved-header loop | rec | 0.6 |
| 8 | — | anon-session requestOptions parity + delete it.skip C-244 stubs | fast-follow | 0.8 |

## Verification (parent, independent git-read)
- mfa-client.ts:349 → auth-client.ts:335-336 → #discoverForRequest:496-498 → #discover:515-519 returns shared this.#configuration when requestOptions undefined. CONFIRMED.
- mfa-client.ts:373 mutates that shared object. CONFIRMED.
- Correct fresh-config pattern at auth-client.ts:732-739 (backchannel), 369-371 (passkey capture). CONFIRMED.
- grep of all `[client.customFetch] =` sites: only mfa-client.ts:373 mutates a shared config; passkey 371/384 mutate fresh configs; 467/574/1593 are init/scoped. CONFIRMED.
