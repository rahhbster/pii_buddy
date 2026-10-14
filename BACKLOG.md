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

**Team-mode review wave, in flight (2026-10-14).** Detailed running log
(defects, verdicts, incidents) is in the PRIVATE repo:
`pii_buddy_private/docs/reviews/2026-10-14-team-review.md`. It lists
unfixed defects, so it is not kept here.

1. Open fix PRs, all red-teamed, fixers pushing to the same branches:
   #1, #12 (detector), #3 (updater), #4 (redactor), #7 (watcher),
   #6 (menubar), #2, #5 (LICENSE, site), #8-#11 (CI, tests, DMG).
   `gh pr list` is the live set. Merge nothing until each branch's
   latest commit has been re-reviewed by someone who did not write it.
2. Merge order: 4, 3, 1 then 12, 7, 6, 2/5, 8-11.
3. Then build the local API + MCP server from the Architect design
   (private log has the full design): core.py first, tests first.
4. Never run the test suite without `PII_BUDDY_DIR` pointed at a temp
   dir. A prior run emptied `~/PII_Buddy/originals`.
5. Do not delete any remote branch without asking the owner.

Also pending: the free sandbox smoke test below (not yet run).

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
