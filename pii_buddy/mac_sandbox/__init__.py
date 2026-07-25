"""Sandbox-compliance support for the Mac App Store (MAS) build variant.

Everything in this package is additive and opt-in: it is only exercised
when the app is built/launched as the sandboxed MAS variant (see
``PII_BUDDY_MAS_BUILD`` in :mod:`pii_buddy.config`). The existing
direct-download/notarized build never imports this package's PyObjC-backed
bridge, and its behavior is completely unaffected.

Modules:
    bridge       -- ``SandboxBridge`` protocol + ``PyObjCSandboxBridge``
                     (real Foundation/AppKit calls, imported lazily).
    fake_bridge  -- ``FakeSandboxBridge``, an in-memory test double that
                     also doubles as a "MAS dry-run" dev mode.
    bookmark_store -- ``BookmarkStore``, persistence + orchestration for
                     security-scoped bookmarks. Platform-agnostic; takes
                     a bridge via dependency injection.
"""
