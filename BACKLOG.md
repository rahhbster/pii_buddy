# Backlog — App Store submission

Tracked follow-up work after the sandbox-compliance build
(`pii_buddy/mac_sandbox/`). See `app_store_sandbox.md` for the full
writeup of what's implemented/tested vs. unverified, and the
"if you're picking this up to actually ship it" section for the
detailed order of operations.

## Blocking submission

- [ ] Get an Apple Developer Program membership (if not already enrolled).
- [ ] Create the "3rd Party Mac Developer Application" and "3rd Party Mac
      Developer Installer" certificates + a provisioning profile for the
      chosen Bundle ID, in the Apple Developer portal / Xcode.
- [ ] Run the MAS build on real macOS + Xcode — **this is the single
      biggest open risk**: the `PyObjCSandboxBridge` has never actually
      run against a real sandbox. All existing tests use
      `FakeSandboxBridge`. Specifically verify:
      - Bookmark creation/resolution actually works via real NSURL calls.
      - `startAccessingSecurityScopedResource` actually lets `watchdog`'s
        FSEvents/kqueue watch the chosen folder inside the sandbox — if
        this doesn't work, the core "watch a folder" feature may need to
        become drag-and-drop instead of background watching.
      - The codesigned, sandboxed `.app` launches without a Gatekeeper or
        `sandboxd` denial (check Console.app).
- [ ] Build and verify the signed `.pkg` (`extras/build_py2app_mas.sh`)
      installs and runs sandboxed on a clean Mac, not just the dev machine.
- [ ] Create the App Store Connect listing: metadata, screenshots, privacy
      questionnaire, review notes. Listing copy already drafted from an
      earlier session — needs to be pasted in.
- [ ] Submit for App Review. Budget for at least one rejection cycle —
      Apple may reject the "watch a folder in the background" pattern
      outright regardless of correct entitlements.

## Known gaps, unrelated to this work

- [ ] Pre-existing bug: `main.py --once` throws `FileNotFoundError` in
      non-MAS `--dir` mode. Reproduced independently on `HEAD` before any
      Venice/sandbox changes — not yet root-caused, not fixed (out of
      scope for the change that found it).
- [ ] Bookmark staleness behavior across OS upgrades, volume renames, or
      iCloud Drive folders is only observable through real, long-term
      usage — current code logs a warning and proceeds on `is_stale`, UX
      not yet validated.
