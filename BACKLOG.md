# Backlog — App Store submission

Tracked follow-up work after the sandbox-compliance build
(`pii_buddy/mac_sandbox/`). See `app_store_sandbox.md` for the full
writeup of what's implemented/tested vs. unverified.

Fixed, kept for history: `main.py --once` threw `FileNotFoundError` in
`--dir` mode because `ensure_dirs()` used a stale `ALL_DIRS` /
`USER_BLOCKLISTS_DIR` binding captured at import time, and the `--dir`
override block never created `USER_BLOCKLISTS_DIR` / `FEEDBACK_DIR`.
Regression tests: `tests/test_dir_override.py`.

## Next

**The team-mode review wave is done (2026-10-15).** All of #1-#17 are merged.
Running log (defects, verdicts, incidents, residual risks) is in the PRIVATE
repo: `pii_buddy_private/docs/reviews/2026-10-14-team-review.md`.

**Now building: local API + local MCP server** (build spec, security model and
test plan: `pii_buddy_private` log + the PR bodies). Five PRs, tests first,
each independently red-teamed:
1. `feat/local-api-core` (#18): merged.
2. guard (`server/guard.py`) merged; `feat/local-api-protocol` (#25): pure
   `server/protocol.py` dispatcher (REST + MCP JSON-RPC), in review. It is
   `handle(route, body, *, request_id, usage) -> Response(status, body,
   headers, diag, entity_count)`; `route` is exactly `guard.Decision.route`
   ("GET /v1/health", "POST /v1/check", ..., "POST /mcp"): protocol builds its
   dispatch table from `guard._ROUTES` (`protocol.ROUTES`), so a route added
   to the guard without a handler fails at import; any other string is 404.
   `tests/test_server_guard_protocol_integration.py` pins that seam. `handle()`
   catches `Exception` only: KeyboardInterrupt, SystemExit, GeneratorExit,
   CancelledError and BaseExceptionGroups of them propagate by design (the
   watchdog's `future.result(timeout)` raises ordinary Exception types); a bad
   `usage` (no callable `increment`) or a non-`str` route never raises (500 /
   404). #24 is merged; open neighbours: #23 (de-flake detector timing tests)
   and this PR (#25).
   Next command: `gh pr list`, then read
   `tests/test_server_guard_protocol_integration.py` before creating
   `pii_buddy/server/http.py`.
   PR 3 contract: log only `Response.diag` (code, class name, where) and
   `entity_count`, NEVER `__cause__` (through ProcessPoolExecutor it is a
   stdlib `_RemoteTraceback` holding formatted worker traceback text); give it
   `request_id` as `r_<hex>`; empty body + 202 for MCP notifications (write
   nothing on stdio); run core in a worker process with >= 30 s timeout.
3. HTTP server + runtime (token file, server.json, flock, logging).
4. MCP: `/mcp` Streamable HTTP and stdio, hand-written JSON-RPC subset.
5. `main.py --serve` / `--mcp-stdio`, MAS refusal, `docs/local_api.md`.
Later: menubar toggle; subprocess watchdog; hosted-parity checks.
Settled: zero new dependencies; MCP `return_mapping` defaults false (HTTP
true); explicit `--serve` only; never in the Mac App Store build.

Known follow-ups (not blockers): card issuer-prefix gate (false positives),
4-5-6 / 5-5-5 groupings, wider card separators; mappings and prefs through the
private-write helper and `PII_BUDDY_DIR` (`main.py` paste path, `menubar.py`);
`main.py --dir` mutates config globals (reverse-order test leak);
`--update-app` stash without pop.

Rules: never run the suite without `PII_BUDDY_DIR` set to a temp dir; use
explicit-path `git add` (never `-a`) in shared checkouts; do not delete any
remote branch without asking the owner.

**Free sandbox smoke test — do this first.** Needs a real Mac and
Console.app. Run the tests first:
`pip install pytest && pytest -q` (pytest is not in `requirements.txt`;
CI uses Python 3.12).

Do this before spending money or time on Apple Developer enrollment/certs.
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

### Then, after the smoke test passes

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

## Open decisions

- **Does a sandboxed app get background folder access via
  `startAccessingSecurityScopedResource`?** The smoke test answers this.
  If it fails, "watch a folder" becomes drag-and-drop. That is a
  structural change, not a patch.
- **Will App Review accept the "watch a folder in the background"
  pattern?** Budget for one rejection cycle regardless of entitlements.
- **Where does `claude/pii-redaction-cost-analysis-SjAw1` go?** It holds a
  business-plan doc (pricing tiers, revenue, margins) that should not
  ship in this public repo. Options: move to `pii_buddy_private`, or
  delete. Owner decides; unmerged for now.
- **Bookmark staleness** across OS upgrades, volume renames or iCloud
  Drive folders is only observable through long-term use. Code logs a
  warning and proceeds on `is_stale`; UX not validated.

## Ruled out

None yet.
