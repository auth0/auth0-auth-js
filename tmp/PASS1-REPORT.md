# PASS 1 — Deep Review report (input to Pass 2 quorum)

## FINDINGS (ranked)

### [HIGH] anonymous-session-client.ts:131,197,259 — Workstream A incomplete on anon-session network methods
createSession, getTokenSilently, logout are public network methods (authClient.anonymous.*) POSTing to /anonymous/token and /anonymous/logout via this.#customFetch (lines 270,299), accept NO requestOptions. Caller cannot cancel/add headers/one-off fetch. Violates "EVERY network public method, uniform". Telemetry IS preserved (constructor passes telemetry-wrapped customFetch, auth-client.ts:444) → completeness gap, not security. Fix: thread requestOptions on all three, route through composeRequestFetch. Blocking only if anon-sessions in node-auth0 parity surface.

### [MED] request-fetch.ts:34-61 — combineSignals manual fallback + listener-cleanup ZERO test coverage
Node ≥20.3 always has AbortSignal.any → lines 34-61 (manual AbortController fallback + removeEventListener cleanup) never execute in tests. combineSignals has no unit test; request-fetch.spec.ts covers only createCapturingFetch. Listener-detach perf fix (combined.cleanup?.() at line 164) unproven. Risk: regression leaking listeners on long-lived caller signal, uncaught. Fix: unit-test combineSignals, stub AbortSignal.any=undefined, assert both source listeners removed after cleanup() and after normal completion.

### [MED] per-request-options.integration.spec.ts:238-245 — Authorization-override test tautological
C-230-06 exercises via getTokenByClientCredentials (auth in body, not Authorization header). Assertion guarded by if(authHeader){...} (line 242) — guard body never runs → case-insensitive skip at request-fetch.ts:150 never proven. Deleting the check would still pass this test. Fix: prove on a header-auth flow, or unit-test composeRequestFetch directly with {Authorization:'attacker'} caller header, assert dropped (both Authorization and authorization).

### [MED] auth-client.ts:375,420,747,1000,1101,1313,1478 (+server-client.ts:699,908,1184,1303,1486) — "no HTTP Response captured" throw branches untested
if(!capturedResponse) throw guards implement DoD cache-hit-no-Response/bug-detection, no test triggers any. Fix: stub CapturingFetch whose getCapturedResponse() returns undefined, assert throw.

### [LOW] auth-client.ts:752,1005,1106,1323,1485,1790 — fragile string-matching for capture-bug error
Catch blocks re-throw internal bug-error by substring sniff: some check e.message.includes('CapturingFetch'), one checks includes('no HTTP Response') (line 752). Server error containing "CapturingFetch" misrouted as internal bug; future string edit breaks one check style. Fix: dedicated sentinel error class (MissingCapturedResponseError), branch on instanceof.

### [LOW] request-fetch.ts:145-155 — Auth0-Client reserved-key protection implicit, only Authorization explicit
composeRequestFetch explicitly skips authorization but sets caller Auth0-Client into mergedHeaders; protection relies solely on telemetry wrapper running last (telemetry.ts:49). Correct today; docstring (request-fetch.ts:118-120, types.ts:104) claims Auth0-Client "cannot be overridden" as if enforced here. If telemetry wrapper reordered/conditional → silent caller override. Fix: skip auth0-client in same reserved loop, or comment binding guarantee to ordering.

### [OBSERVATION] server-js per-request-options.integration.spec.ts C-244-01..05 are it.skip (lines 72,89,98,110,122)
BUT server-client.spec.ts:8920-9700 (A1-A10) asserts via vi.spyOn every server method forwards requestOptions to correct auth-js method (getAccessToken cache-miss forwards 9514-9517; cache-hit does NOT forward 9522). Delegation covered. Skipped tests redundant, not a hole — but dead weight signalling false coverage. Delete or un-skip.

## EXPLICIT ANSWERS
1. Workstream A complete ALL network methods both packages? NO — sole gap = 3 authClient.anonymous.* methods lack requestOptions. Everything else complete + verified.
2. fullResponse/Option C correct + sole metadata owner? YES. No HttpResponseMetadata/extractHttpMetadata/enrich*/httpResponse? field. Only statusCode = pre-existing PasswordlessChallengeError (legit) + separate auth0-api-js package (out of stack). createCapturingFetch per-invocation everywhere, clones Response (non-consumed proven), overloads resolve, cache-bypass proven, both branches thread requestOptions.
3. Concurrency/security/mTLS/telemetry: Concurrency SAFE (new Configuration per call, never mutates shared this.#configuration; only shared write assigns constant this.#customFetch, idempotent; capturing fetch closes over local var). Header injection SAFE (case-insensitive Authorization skip; telemetry last). mTLS correctly caveated (per-request customFetch re-wrapped telemetry-only NOT mTLS, documented types.ts:107-115, request-fetch.ts:136-138, EXAMPLES). Telemetry PRESERVED (createTelemetryFetch(perRequestFetch), proven). Signal/abort no leak (cleanup in finally). Response clone no double-consume. auth0ForwardedFor spread safe (oauth4webapi passes plain obj not Headers).
4. revokeRefreshToken NOT a gap (threads requestOptions correctly, server-client.ts:1327/1367/1380/1402). anon-session REAL gap, non-blocking (it's #240 feature, not node-auth0 §5 DX asks; telemetry intact, no security defect); fast-follow recommended.
5. GO — no true blockers. Recommended pre-merge (none code-blocking): decide anon-session scope; close 3 test gaps (combineSignals fallback+cleanup, real Authorization-drop, no-captured-Response throw); delete/un-skip redundant C-244 it.skip; nice-to-have sentinel error class.
