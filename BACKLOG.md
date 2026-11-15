# Backlog

Handoff file. Refreshed 2026-11-02 for a cold restart (state below is as of that
day; re-check with `git ls-remote origin` and `gh pr list`). Detailed history (defects,
verdicts, incidents, residual risks) is in the PRIVATE repo
`pii_buddy_private`: `docs/reviews/2026-10-14-team-review.md`, and the
local API/MCP build spec (original + "As built" amendments + the PR 3 MUST
list) is `docs/design/local-api-mcp-build-spec.md` there (private PR #5, MERGED as 972f03b).

## Next

**Launch path: the invited-tester hosted beta.** Owner decision: it goes live before
PRs 3b-5. Do these in order, one at a time:

1. Public PR #31 (`feat/killable-worker`, `pii_buddy/server/worker.py`): wait for CI to
   go green on all three jobs (`gh pr checks 31`; macOS py3.12, macOS py3.10 and
   ubuntu py3.12), then the owner re-reviews and merges. Do not merge it yourself.
2. Private PR #8 (`hosted/`, red-team approved at cb0f050): set `PII_BUDDY_REF` to the
   FULL SHA of public `main` after #31 merges (`git ls-remote origin main`), then the
   owner merges.
3. Deploy from the "Hostinger VPS (on box)" session; the owner types yes there. The
   pieces: the `pb-edge` network, a Coolify compose app, a deploy key, and env
   `PII_BUDDY_REF` + `PII_BUDDY_KEY_HASHES`.
4. Run the smoke tests from outside the box.
5. On deploy day, merge the privacy-page PR #30.
6. Issue the tester keys.

Owner action, blocks step 5: create the `privacy@piibuddy.com` alias.

**Off the launch path: PR #28 (local HTTP).** It fails on Linux CI:
`TestDrain::test_whole_body_uploader_reads_its_401[524288]` raises BrokenPipeError,
likely an RST on close with unread request data. Fix the root cause in `http.py`
(graceful `shutdown(SHUT_WR)` plus a bounded drain before close), then re-review.

### Half-applied / live state (read before touching anything)

- **#23 MERGED 2026-10-19 (`ba50e22`, pinned to 679d4f9).** Independent red team:
  APPROVE WITH CHANGES (0 false positives in 2,600 results). Follow-up PR to open
  (`fix/timing-test-gaps`, test-only, own red team): (1) `test_redact_text_scales_linearly_in_distinct_emails`
  catches nothing (spaCy dominates at 500/1,000 emails): raise N or drop it; (2) ratio
  checks need the quadratic part >75% of the 25k runtime, so a 7x slowdown above 300k
  chars passes at 5.7 s of an 8 s backstop; (3) the 0.4 s CPU limit and the 24x
  restorer limit are machine-dependent (24x is tuned to 5,000 keys x 1 occurrence;
  correct code reaches 23.3x at 3 occurrences each): use a multiple of an in-process
  reference; (4) add an `@override ` unit to `test_detector_perf._UNITS` (handle
  lookback); (5) add a PERSON-scaling ratio test for `redact` (`_group_names` is
  O(names^2), only an absolute 2 s limit today); (6) py3.10 CI shows 3,664 passed vs
  3,679 locally: find out why (unexplained). Verify the Test workflow on `ba50e22`.
- **Found by that fixer, NOT fixed (product code):** `core._restore_unchecked` is one
  alternation regex and is O(keys x occurrences): `t(2N)/t(N)` ~3.4 on CORRECT code, so
  a plain ratio cannot tell it from a per-key `str.replace` loop. #23 therefore tests it
  as linear-in-text for a fixed mapping and <24x the time of `restore_text`.
- **`~/code/pii_buddy/.claude/worktrees/`:** 58 agent worktrees, 820 MB, untracked
  (`?? .claude/`). Safe to delete only with the owner's OK: `git worktree list`,
  `git worktree prune`, then remove the `worktree-agent-*` local branches.
- **Remote branches:** 27 heads besides `main` on 2026-11-02, most merged (e.g.
  `origin/feat/local-api-core`, `origin/fix/*`, `origin/chore/*`): leftover, not
  deleted; ask first. `docs/backlog-bridge-2026-10-26` is this PR's own branch.
- **Your login item** `~/Library/LaunchAgents/dev.piibuddy.menubar.plist` was
  restored to its original content after a test run rewrote it (2026-10-14); it runs
  `~/code/pii_buddy/.venv/bin/python -m pii_buddy.menubar` FROM THE CLONE, so keep the
  clone on `main`.
- **`~/PII_Buddy/originals/` is EMPTY** (emptied by a test run 2026-10-14 06:27; about
  11 old test files). Local snapshots rolled off. The Time Machine backup disk is
  configured but not mounted ("Failed to mount destination"): connect it, then
  `tmutil listbackups` (read-only) to see if a pre-2026-10-14 06:27 backup exists.
- **Private repo:** main 972f03b; one open PR, #6 (`docs/backlog-bridge-post-merge`, a
  private BACKLOG bridge); leftover remote branches, ask before deleting:
  `add-cost-analysis-draft`, `docs/log-final-state`, `docs/team-review-log`,
  `revert/unrelated-files-from-log-commit` (1 UNMERGED commit; its PR #4 was closed, so
  check before deleting). `sync/readme-and-check-script` is merged but probably the
  peer session's: do not touch it. A peer Claude session
  `pii-buddy-private-4f` owns the private `client/` and `scripts/check_sync.py`
  (its check fails if a public PR renames Settings `verify_*`/`openrouter_*`/`venice_*`
  fields or removes `detector.get_nlp` or `redactor._make_initials`); it works in
  `/Users/robertmerrill/code/pii_buddy_private_sync`: never touch that directory.
- Memory: `~/.claude/projects/-Users-robertmerrill-code-pii-buddy/memory/` has
  `feedback_redteam_before_merge.md` and `project_local_api_mcp.md`.

## Open decisions

- **Ship the stale `v1.0.0` fix first? (GitHub release vs App Store.)** The public
  release `v1.0.0` (2026-02-07, `PII_Buddy.dmg`, 20 downloads) predates all review-wave
  fixes. Recommended: cut a new GitHub release before any App Store work. Needs: one
  version number (setup_py2app.py says 0.6.0; build_dmg.sh says 1.0.0), a real-Mac
  `./extras/build_dmg.sh` run (never run), Developer ID + notarization ($99/yr) to drop
  the Gatekeeper workaround, clean-Mac test (the DMG builds a venv at first launch and
  needs Python 3.10+). Publishing is public: ask first. Would change my mind: owner
  prefers App Store only.
- **Mac App Store path (checked 2026-10-19):** blocked by (1) the never-run sandbox smoke
  test below, (2) Apple Developer membership, two 3rd Party Mac Developer certs and a
  provisioning profile, (3) a listing that does not exist: no privacy-policy or support
  URL (docs/ is index.html plus CNAME, style, script and images), no screenshots/icon, `LSApplicationCategoryType`
  missing in setup_py2app.py, export-compliance answers, network-client entitlement
  needs a disclosed reason. The local API server must never ship in the MAS build.
- **Watchdog timeout value and policy.** Recommended >= 30 s. Slowest LEGITIMATE input
  4.4 s quiet / ~10 s loaded (50,000-character CSV of 5,000 SSNs); pathological
  `"a"+"."*49998+"b"` 6-8 s, `"a\n"*25000` 7.7 s, `"!"*50000` > 90 s (~250 s). A 30 s
  timeout bounds the stall, it does not remove it (a flood can pin workers); needs the
  concurrency cap. What would change it: measuring on the owner's real documents.
- **Accepted residual detector leaks** (identical to or better than `main`):
  4-5-6 / 5-5-5 card groupings; tab/newline/dot/slash/underscore card separators;
  ~46% of unseparated 16-19 digit cards with 1-8 glued digits; bare path-less
  `.dev/.app/.ai/.io/.me/.ly/.page` domains stay visible (`jane.me`); card false
  positives rose (130 labels / 755 ordinary lines). Follow-up: issuer-prefix gate,
  wider separators. Reverse any if the owner wants stricter.
- **`--update-app`** runs `git stash` with no pop (documented, code unchanged).
- **Blocklist provenance:** the +25 growth cap bounds blast radius, it is not
  provenance; signed/pinned releases are the real fix.
- **Reverse-order test leak:** `main.py --dir` mutates `cfg` globals so
  `test_watch_defaults_to_config_input_dir` fails when run after CLI tests.
- **Mappings and prefs** still bypass the private-write helper and ignore
  `PII_BUDDY_DIR` (`main.py` paste path ~line 551, `menubar.py` clipboard mapping and
  `_PREFS_DIR`).
- **Small #25 follow-ups:** propagation tests at `parse_json_body` / `_class_name` /
  `_usage_ok`, a test that `ping`/`initialize`/`tools/list` never touch core, optional
  prebuilt-500 for a stack-edge RecursionError.
- **Does a sandboxed app get background folder access via
  `startAccessingSecurityScopedResource`?** (PARKED, App Store track.) The smoke test
  answers it; if it fails, "watch a folder" becomes drag-and-drop. Will App Review
  accept background folder watching? Budget for one rejection cycle.
- **Bookmark staleness** across OS upgrades, volume renames or iCloud Drive folders is
  only observable through long-term use; code logs a warning and proceeds on `is_stale`.

- **Hosted service at `mcp.piibuddy.com` (owner direction 2026-11-02; `pii.sh` is
  unavailable, so it is not an option).** Agents should be able to pay per use by
  token, with free starter tokens for new users. Design is in the PRIVATE repo:
  `docs/strategy/08-mcp-hosted-service-design.md` and `09-mcp-service-gtm-debate.md`
  (Stripe-keyed rail first; doc 08 blocks x402/pay.sh on its undisclosed fee, doc 09
  schedules a 2-day x402 spike after Stripe is live). New here, not in doc 08: the
  `mcp.piibuddy.com` host (doc 08 mounts `/mcp` on the existing API app) and the
  caller-held mapping key. Open: what a
  "token" is (prepaid credit balance tied to a `pb_live_` key, or per-call payment such
  as x402); how many free tokens per new user and the abuse limit (doc 08: Groq free
  tier costs about $0.09-0.14 per user per month at 3-5 redactions/day); caller-held
  encryption key for the returned mapping, so the server cannot read it. Not started;
  the local API/MCP build (PR 3-5) comes first. Would change my mind: a hosted-first
  demand signal from real users.
- **Private-inference provider for the hosted service: NEAR AI Cloud vs Venice
  (researched 2026-11-02 from vendor pages only; nothing tested).** NEAR: per-token,
  no minimums, no extra charge for attestation, attestation report needs no account;
  own-hardware "Private TEE" models (e.g. GLM 5.3 Flash $0.08 in / $0.50 out per 1M
  tokens) plus "3P TEE" models on a third party's enclave; direct API only (the
  OpenRouter gateway in front is NOT attested); retention terms not on the pricing
  page, read the DPA. Venice: TEE mode still sends plaintext to Venice's API (the
  enclave protects it after that); E2EE mode needs client-side crypto (secp256k1 +
  HKDF + AES-256-GCM, attestation check, three headers) and works on text models only;
  one third-party review says TEE/E2EE need a Pro plan and prices are in credits
  (unverified). Doc 03 costs only Groq/OpenRouter-class providers and self-hosting.
  Doc 08 costs Venice E2EE (~$0.0045/doc, $0.68/user/mo at 5/day) and already decides
  Groq for free, Venice for paid; that Venice number has no source in doc 03. No NEAR
  costing exists anywhere. Recommended next step for the HOSTED track only (after PR
  3-5, or as a one-day side spike; it does not replace `## Next`): a one-day spike calling NEAR's direct API with
  already-redacted shards and checking the attestation. Would change my mind: NEAR
  retention terms are unacceptable, or shard accuracy on its models is below Groq's.

### App Store track: free sandbox smoke test

Independent of PR 3. Do it before any Apple spend. Needs a real Mac and
Console.app. Run the tests first:
`pip install pytest && pytest -q` (pytest is not in `requirements.txt`;
CI runs Python 3.10 and 3.12).

It answers the single biggest open risk for free, using **ad-hoc code
signing** (no Apple Developer Program membership required — `codesign
--sign -` applies real entitlements and gets real App Sandbox enforcement
on your own Mac, it just can't be distributed to anyone else).

Status as of this writing: **not yet run.** Nobody has executed this on
real macOS yet — everything below is the plan, not a result.

```bash
cd ~/code/pii_buddy   # or wherever the clone lives
./setup.sh            # skip if already set up

./extras/build_py2app_mas.sh
# produces dist/mas/PII Buddy.app, UNSIGNED — expected, sign it next

codesign --deep --force --options runtime \
  --entitlements extras/entitlements_mas.plist \
  --sign - \
  "dist/mas/PII Buddy.app"

codesign --verify --deep --strict --verbose=2 "dist/mas/PII Buddy.app"
# should report no errors
```

Then:
1. Open **Console.app** (Spotlight → "Console"), filter/search for
   `sandboxd`, leave it running and visible.
2. `open "dist/mas/PII Buddy.app"` — Gatekeeper will likely block first
   launch since it's ad-hoc signed; right-click the app in Finder → Open
   → confirm.
3. Click the menu bar icon → **"Choose Watch Folder…"** (this menu item
   auto-appears — the MAS build sets its own `PII_BUDDY_MAS_BUILD` flag
   via `LSEnvironment`, no manual env var needed). Pick any folder in the
   real NSOpenPanel that appears.
4. Drop a test `.txt` file with an obviously fake name/email into that
   folder.
5. **Read the result:**
   - **Success:** a redacted output file appears within a few seconds,
     no `sandboxd` denials in Console.
   - **Failure:** nothing happens, or Console shows something like
     `sandboxd: deny(1) file-read/file-write...` — this means
     `startAccessingSecurityScopedResource` isn't actually granting
     `watchdog` access inside the sandbox, and the "watch a folder in the
     background" UX would need to become drag-and-drop instead. This
     would be a real, structural finding — not a bug to just patch.

Whatever happens, capture the Console.app output (verbatim, especially
any `deny` lines) before moving on to certs/provisioning below.

**Then, after the smoke test passes:**

- [ ] Get an Apple Developer Program membership (if not already enrolled).
- [ ] Create the "3rd Party Mac Developer Application" and "3rd Party Mac
      Developer Installer" certificates + a provisioning profile for the
      chosen Bundle ID, in the Apple Developer portal / Xcode.
- [ ] Re-run the build, this time with `MAS_APP_SIGNING_ID` /
      `MAS_INSTALLER_SIGNING_ID` set to the real certs (see
      `extras/build_py2app_mas.sh` header comment for the exact env var
      names/format), plus the provisioning profile copied into
      `dist/mas/embedded.provisionprofile` before signing.
- [ ] Build and verify the signed `.pkg` installs and runs sandboxed on a
      clean Mac, not just the dev machine.
- [ ] Create the App Store Connect listing: metadata, screenshots, privacy
      questionnaire, review notes. Listing copy already drafted from an
      earlier session — needs to be pasted in.
- [ ] Submit for App Review (TestFlight beta first). Budget for at least
      one rejection cycle — Apple may reject the "watch a folder in the
      background" pattern outright regardless of correct entitlements.

## Ruled out

Never retry these blind.

- **Worker pool: slot thread waiting only on `w.gone`.** A worker that dies while idle
  never sets it, so the death surfaced as a 503 on the next request. The slot thread now
  waits on the process sentinel and claims the idle worker under the pool lock.
- **Worker pool: saving/restoring `OMP_NUM_THREADS` around each spawn.** Raced every
  other thread's getenv and clobbered concurrent writers. Spawn has no per-child env;
  it is set once in `WorkerPool.start` before any slot thread exists.
- **Worker pool: no `atexit` close.** multiprocessing's exit hook terminates daemon
  workers; once slot threads watch the sentinel they respawn into the dying interpreter,
  which then hung about 1 run in 5 in the resource tracker.

- **Calibrated tokenizer-cost proxy + 16,000-token cap in `core`.** Rejected on three
  independent reviews: a mid-chunk dot run slipped through (6-8 s), `://` chains were
  under-estimated 1.3x, ~9% of ordinary documents and 50,000-character PII lists
  (3,100 phones, 4,000 SSNs, ...) were falsely rejected, and the constants drift with
  spaCy upgrades. Replaced by: 50,000-character cap + watchdog in the server layer.
- **Word-boundary / CamelCase name sweep in the redactor.** Two rejections (crashed on
  `ſam`/`İlker`, leaked glued names like `annlee`, `DrLee`, `jsmith`, slower). Back to
  `main`'s case-insensitive substring sweep (over-redacts `Annual`; fail closed).
- **`except BaseException` in `protocol.handle()`.** Swallowed
  `BaseExceptionGroup([KeyboardInterrupt()])`, `CancelledError`, GreenletExit-like
  exceptions. Use `except Exception`; interrupts propagate by design.
- **Public `trusted=True` kwarg on `restore_text`.** A validation bypass. Use the
  private `core._restore_unchecked` (restorer.py only).
- **Automatic LaunchAgent plist rewrite at startup.** It rewrote the owner's real login
  item during a test run. Warn only; write only on the explicit toggle.
- **Own-output filename regexes in the watcher** (`PII_FREE_*`, stamped names): silently
  skipped real user files. Use a stat-keyed registry `(path, mtime_ns, size, ino)`.
- **Absolute-seconds and wall-clock timing asserts** in tests: flaky on slower CI and
  under load. Use CPU-time ratio t(2N)/t(N) with a generous backstop.
- **Python 3.9 support.** Current spaCy needs `thinc>=8.3.12` which needs Python 3.10;
  the floor is 3.10 (CI runs 3.10 and 3.12).
- **Tests that touch the real environment.** Twice a test run damaged
  `~/PII_Buddy/originals` and the login-item plist. Always set `PII_BUDDY_DIR`; the
  autouse guard in `tests/conftest.py` blocks real `~/Library`/`~/PII_Buddy` writes and
  real `pbcopy`/`launchctl`/`osascript`/`open`/`gh`.
- **Merging a "docs-only" PR on a substring file check.** It swept another session's
  four edited files into private `main`. Compare the file set by exact equality.
- **Restoring `originals/` from a local Time Machine snapshot.** They roll off in ~24 h.
- **The cost-analysis branch** (`claude/pii-redaction-cost-analysis-SjAw1`): moved to the
  private repo (`docs/strategy/10-pii-redaction-cost-analysis-draft.md`, marked
  UNVERIFIED) and the public branch deleted.
