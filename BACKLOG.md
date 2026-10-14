# Backlog

Tracked follow-up work after the sandbox-compliance build
(`pii_buddy/mac_sandbox/`). See `app_store_sandbox.md` for the full
writeup of what's implemented/tested vs. unverified, and the
"if you're picking this up to actually ship it" section for the
detailed order of operations.

## Next

**Team-mode review is in flight (started 2026-10-14).** Three read-only
red-team agents are reviewing: backend security/privacy; frontend,
packaging, CI and tests; and the two unmerged branches
(`backlog-reshape`, `claude/pii-redaction-cost-analysis-SjAw1`).

1. Read the three reports. Triage into one small PR per concern, each on
   its own branch off `main`. Write the failing test first.
2. Merge nothing until the branch red-team verdict is in. Cost-analysis
   doc is suspected to belong in the PRIVATE repo
   (`rahhbster/pii_buddy_private`), not this public one. Unverified.
3. Do not delete any remote branch without asking the owner.

Still pending from before: **free sandbox smoke test** (not yet run).
Commands are in `app_store_sandbox.md` and the "Blocking submission"
list below. A real Mac and Console.app are required.

Env: `.venv` rebuilt on Python 3.13 (CI uses 3.12). `pytest` is not in
`requirements.txt`; `.venv/bin/pip install pytest` first. Suite: 79 pass.

## Open decisions

- **Does a sandboxed app get background folder access via
  `startAccessingSecurityScopedResource`?** The smoke test answers this.
  If it fails, "watch a folder" becomes drag-and-drop. That is a
  structural change, not a patch.
- **Will App Review accept the "watch a folder in the background"
  pattern?** Budget for one rejection cycle regardless of entitlements.
- **`origin/claude/pii-redaction-cost-analysis-SjAw1`**: two commits, one
  doc (`docs/pii_redaction_cost_analysis.md`, 1086 lines), never merged.
  Merge or delete.
- **Bookmark staleness** across OS upgrades, volume renames or iCloud
  Drive folders is only observable through long-term use. Code logs a
  warning and proceeds on `is_stale`; UX not validated.

### Blocking submission (after the smoke test passes)


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

- Nothing tried-and-failed yet. The `--once` + `--dir` `FileNotFoundError`
  was a real bug, now fixed: `ensure_dirs()` used a stale `ALL_DIRS` /
  `USER_BLOCKLISTS_DIR` binding captured at import time. Regression tests
  in `tests/test_dir_override.py`.
