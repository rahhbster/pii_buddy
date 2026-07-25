# App Store Sandbox Compliance — Status

This document tracks what has and has not been done for the Mac App Store
(MAS) sandboxed build variant of PII Buddy. Be skeptical of any tool or
green checkmark that implies more than what's listed here — the honest
summary is: **the code and tests exist and pass; nothing about running the
actual sandboxed app on real macOS, or Apple's acceptance of it, has been
verified.**

## What's implemented and test-covered

- `pii_buddy/mac_sandbox/bridge.py` — `SandboxBridge` protocol +
  `PyObjCSandboxBridge` (real Foundation/AppKit calls, imported lazily).
- `pii_buddy/mac_sandbox/fake_bridge.py` — `FakeSandboxBridge`, an
  in-memory test double.
- `pii_buddy/mac_sandbox/bookmark_store.py` — `BookmarkStore`: persists a
  security-scoped bookmark as base64 JSON at
  `~/Library/Application Support/PII Buddy/folder_bookmark.json`, resolves
  it on demand, surfaces staleness and resolution failure as a
  `needs_regrant` flag rather than raising.
- `pii_buddy/menubar.py` — `WatchFolderMenuController` + a
  "Choose Watch Folder…" menu item, wired in only when
  `PII_BUDDY_MAS_BUILD=1` is set. Non-MAS builds never see this menu item
  and never import/execute this code path.
- `main.py` — `_mas_resolve_watch_root()`: on the MAS build, resolves the
  bookmark before calling `watcher.watch()`; on failure it shows a rumps
  alert directing the user to "Choose Watch Folder…" instead of crashing
  or silently watching nothing.
- `pii_buddy/watcher.py` — already accepted an injectable `input_dir`
  parameter (`watch(input_dir=INPUT_DIR, ...)`); this is what the MAS path
  uses to hand in the resolved, security-scoped `Path` instead of the
  hardcoded config default. No changes were needed here — added
  regression tests instead (`tests/mac_sandbox/test_watcher_injected_root.py`).
- `extras/entitlements_mas.plist` / `extras/entitlements_mas_debug.plist`
  — sandbox entitlements for the MAS build. `plutil -lint` confirms they
  parse as valid property lists. They deliberately do **not** include any
  `com.apple.security.temporary-exception.files.absolute-path.read-write`
  entry, since Apple rejects broad filesystem exceptions like that.
- `setup_py2app.py` — supports `PII_BUDDY_BUILD_VARIANT=mas` to build a
  separate MAS target (output under `dist/mas/`, `LSEnvironment` sets
  `PII_BUDDY_MAS_BUILD=1` automatically inside the built app) without
  changing the default (direct-download) build path at all.
- `extras/build_py2app_mas.sh` — new, separate script that builds the MAS
  variant, code-signs it with the sandbox entitlements (if
  `MAS_APP_SIGNING_ID` is set), and packages a `.pkg` via `productbuild`
  (if `MAS_INSTALLER_SIGNING_ID` is set). `extras/build_py2app.sh`
  (existing direct-download build) is untouched.

Test suite: `tests/mac_sandbox/` — `test_bookmark_store.py`,
`test_menubar_mas_flow.py`, `test_watcher_injected_root.py`,
`test_main_mas_branching.py`. All run under plain pytest with no real
PyObjC/NSURL/NSOpenPanel calls, so they run in normal CI (including
non-macOS runners) — everything is exercised through `FakeSandboxBridge`
or mocked `BookmarkStore` instances.

Run them with:

```
.venv/bin/python -m pytest tests/mac_sandbox/ -v
```

## What is explicitly NOT verified (needs a human, on real macOS)

Nothing below can be confirmed by writing more code or tests — they require
an actual signed build, an actual Apple Developer account, and/or an actual
App Store Connect submission.

1. **Does `PyObjCSandboxBridge` actually work?** The real
   `NSOpenPanel`/`bookmarkDataWithOptions:...`/
   `URLByResolvingBookmarkData:...` calls in `bridge.py` were written by
   reading Apple's documented signatures, not exercised — they've never
   been run. There could be a wrong selector name, wrong constant, or
   wrong tuple-unpacking assumption for what PyObjC returns. This can
   only be found by running the MAS build on macOS and clicking
   "Choose Watch Folder…" for real.

2. **Does `startAccessingSecurityScopedResource` actually let
   `watchdog`'s FSEvents/kqueue watch the chosen folder inside the
   sandbox?** This is the single biggest open risk in the whole plan
   (called out in the original plan too — "no CI proxy exists"). If it
   doesn't work, the MAS build's core feature (watch a folder, get
   redacted files) may simply not function even with entitlements
   correctly applied, and would need a different approach (e.g. drag-and-
   drop instead of background watching).

3. **Does the codesigned, sandboxed `.app` even launch without a Gatekeeper
   or sandbox violation?** Only visible via Console.app's `sandboxd` denial
   logs on a real Mac, with a real signature.

4. **App Review acceptance.** Apple may reject the "watch a folder in the
   background" pattern outright, sandboxed or not — this can only be
   learned by actually submitting through App Store Connect.

5. **Xcode / Apple Developer portal setup**, all fully manual and
   account-specific — none of it exists yet for this project:
   - Registering the app's Bundle ID (`dev.piibuddy.menubar`, or a
     distinct `.mas` variant — pick one) in the Apple Developer portal.
   - Creating and installing a "3rd Party Mac Developer Application"
     certificate and a "3rd Party Mac Developer Installer" certificate.
   - Creating and downloading a matching provisioning profile, and
     embedding it as `Contents/embedded.provisionprofile` in the built
     `.app` before signing (referenced but not automated by
     `extras/build_py2app_mas.sh`).

6. **Bookmark staleness across OS upgrades, volume renames, or iCloud
   Drive folders.** `BookmarkStore.resolve_bookmark()` surfaces the
   `is_stale` flag when the bridge reports it, and the code logs a
   warning and proceeds — but whether that's the right UX, and whether
   real staleness actually gets reported correctly by macOS in those
   scenarios, is only observable through real, long-term usage on a real
   Mac.

7. **App Store Connect listing**: metadata, screenshots, privacy
   questionnaire answers, review notes, TestFlight distribution/testing.
   None of this exists and none of it is code — it's created directly in
   App Store Connect by a human with access to the developer account.

## If you're picking this up to actually ship it

Rough order of manual work, after this code lands:

1. Get an Apple Developer Program membership (if not already enrolled)
   and create the two "3rd Party Mac Developer" certificates + a
   provisioning profile for the chosen Bundle ID, all in the Apple
   Developer portal / Xcode.
2. Run `PII_BUDDY_BUILD_VARIANT=mas MAS_APP_SIGNING_ID=... .venv/bin/python
   setup_py2app.py py2app`, or just `./extras/build_py2app_mas.sh` with
   both signing env vars set.
3. Launch the built `.app` locally (unsigned first is fine for a quick
   smoke test, signed for anything sandbox-related) and click
   "Choose Watch Folder…". Watch Console.app for `sandboxd` denials.
   Drop a file in the chosen folder and confirm a redacted file appears —
   this is the step that answers open question #2 above.
4. Only once step 3 actually works: sign properly, package the `.pkg`,
   and submit via App Store Connect / TestFlight.
