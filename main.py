#!/usr/bin/env python3
"""
PII Buddy — Drop files in, get redacted files out.

Usage:
    python main.py                  Watch the input folder (default: ~/PII_Buddy/input)
    python main.py --once FILE      Process a single file and exit
    python main.py --paste          Paste text via stdin, get redacted output
    python main.py --clipboard      Read clipboard, redact, write back to clipboard
    python main.py --restore REDACTED_FILE MAPPING_FILE   Restore PII
    python main.py --menubar           Mac menu bar app (requires: pip install rumps)

Set PII_BUDDY_DIR env var to change the base folder (default: ~/PII_Buddy).
"""

import argparse
import errno
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import pii_buddy.config as cfg
from pii_buddy.config import PII_BUDDY_MAS_BUILD


USER_BLOCKLIST_TEMPLATE = """\
# Your personal blocklist — terms here will NEVER be treated as a person's name.
# One per line, case-insensitive. Lines starting with # are comments.
#
# This file is yours and will never be overwritten by updates.
# Add company names, product names, or any terms that get incorrectly redacted.
#
# Examples:
# My Company Name
# Specific Product Name
# Internal Project Codename
"""


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def ensure_dirs():
    """Create every directory in cfg.ALL_DIRS.

    Reads cfg.ALL_DIRS (and cfg.USER_BLOCKLISTS_DIR) through the module
    rather than importing those names directly — a `--dir` override
    reassigns pii_buddy.config's attributes after this module is first
    imported, and a bare `from pii_buddy.config import ALL_DIRS` would
    keep pointing at the stale, pre-override list.
    """
    for d in cfg.ALL_DIRS:
        d.mkdir(parents=True, exist_ok=True)
    # Seed user blocklist if it doesn't exist
    user_bl = cfg.USER_BLOCKLISTS_DIR / "user_blocklist.txt"
    if not user_bl.exists():
        user_bl.write_text(USER_BLOCKLIST_TEMPLATE, encoding="utf-8")


def _show_mas_regrant_alert():
    """Direct the user to "Choose Watch Folder…" via a rumps alert.

    Best-effort: falls back to a log line if rumps/AppKit aren't
    available (e.g. this is somehow invoked outside the menu bar app).
    """
    try:
        import rumps

        rumps.alert(
            title="PII Buddy needs a folder",
            message=(
                "Choose a folder to watch from the menu bar icon: "
                "'Choose Watch Folder…'"
            ),
        )
    except Exception:
        logging.getLogger("pii_buddy").error(
            "No watch folder configured. Use 'Choose Watch Folder…' "
            "from the menu bar."
        )


def _mas_resolve_watch_root(store=None, alert_fn=None) -> Optional[Path]:
    """Resolve the sandboxed watch folder for the MAS build.

    Returns the resolved, currently-accessible Path, or None if the user
    needs to (re-)grant access — in which case an alert directs them to
    "Choose Watch Folder…" rather than raising or silently doing nothing.

    ``store`` and ``alert_fn`` are injectable so this branching logic can
    be unit tested with a mocked BookmarkStore, with no real PyObjC/
    NSURL/rumps calls.
    """
    logger = logging.getLogger("pii_buddy")

    if store is None:
        from pii_buddy.mac_sandbox.bookmark_store import BookmarkStore
        from pii_buddy.mac_sandbox.bridge import PyObjCSandboxBridge

        store = BookmarkStore(bridge=PyObjCSandboxBridge())
    if alert_fn is None:
        alert_fn = _show_mas_regrant_alert

    result = store.resolve_bookmark()
    if result.needs_regrant or result.path is None:
        alert_fn()
        return None

    if result.is_stale:
        logger.warning(
            "Watch folder bookmark is stale; access may fail. "
            "Re-choose the folder via 'Choose Watch Folder…' if issues occur."
        )

    if not store.start_accessing(result.path):
        alert_fn()
        return None

    return result.path


def main():
    parser = argparse.ArgumentParser(
        description="PII Buddy — redact PII from documents"
    )
    parser.add_argument(
        "--once",
        metavar="FILE",
        help="Process a single file and exit (instead of watching)",
    )
    parser.add_argument(
        "--restore",
        nargs=2,
        metavar=("REDACTED_FILE", "MAPPING_FILE"),
        help="Restore PII into a redacted file using its mapping",
    )
    parser.add_argument(
        "--paste",
        action="store_true",
        help="Read text from stdin (paste + Ctrl+D), print redacted output",
    )
    parser.add_argument(
        "--clipboard",
        action="store_true",
        help="Read from clipboard, redact, write result back to clipboard",
    )
    parser.add_argument(
        "--dir",
        metavar="PATH",
        help="Override the base directory (default: ~/PII_Buddy)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Download latest blocklists from GitHub",
    )
    parser.add_argument(
        "--update-app",
        action="store_true",
        help="Update PII Buddy to the latest version via git pull",
    )
    parser.add_argument(
        "--menubar",
        action="store_true",
        help="Launch Mac menu bar app (requires: pip install rumps)",
    )
    parser.add_argument(
        "--credits",
        action="store_true",
        help="Check your current credit balance",
    )
    parser.add_argument(
        "--buy",
        action="store_true",
        help="Open browser to purchase credits",
    )
    # Output format flags
    parser.add_argument(
        "--same-format",
        action="store_true",
        help="Output matches input format (PDF→PDF, DOCX→DOCX)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace input file with redacted version (backs up original)",
    )
    parser.add_argument(
        "--text-output",
        action="store_true",
        help="Also produce a .txt version alongside formatted output",
    )
    parser.add_argument(
        "--tag",
        metavar="TAG",
        default=None,
        help="Customize filename prefix (default: PII_FREE). Empty string = no prefix, appends _redacted",
    )
    parser.add_argument(
        "--keep-name",
        action="store_true",
        help="Keep original filename (output goes to output/ folder)",
    )
    # Verify flags
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Enable cloud verification after local redaction",
    )
    parser.add_argument(
        "--verify-key",
        metavar="KEY",
        default=None,
        help="PII Buddy Verify API key",
    )
    parser.add_argument(
        "--verify-endpoint",
        metavar="URL",
        default=None,
        help="Override verify API endpoint (default: https://api.piibuddy.com/v1)",
    )
    parser.add_argument(
        "--verify-confidence",
        metavar="N",
        type=float,
        default=None,
        help="Minimum confidence threshold for verify findings (default: 0.7)",
    )
    # Feedback flags
    parser.add_argument(
        "--rate",
        type=int,
        choices=[1, 2, 3, 4, 5],
        metavar="N",
        help="Rate the quality of the last redaction (1-5 stars)",
    )
    parser.add_argument(
        "--feedback",
        metavar="COMMENT",
        help="Submit feedback about detection quality (describe patterns, not actual PII)",
    )
    # Subscribe
    parser.add_argument(
        "--subscribe",
        metavar="EMAIL",
        help="Subscribe to PII Buddy product updates",
    )
    # Audit flags
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Disable structural self-audit (Pass 2)",
    )
    # OpenRouter flags
    parser.add_argument(
        "--openrouter",
        action="store_true",
        help="Enable OpenRouter LLM verification (Pass 3)",
    )
    parser.add_argument(
        "--openrouter-key",
        metavar="KEY",
        default=None,
        help="OpenRouter API key",
    )
    parser.add_argument(
        "--openrouter-model",
        metavar="ID",
        default=None,
        help="OpenRouter model (default: meta-llama/llama-3.1-8b-instruct:free)",
    )
    # Venice flags
    parser.add_argument(
        "--venice",
        action="store_true",
        help="Enable Venice TEE/E2EE confidential LLM verification (Pass 3b)",
    )
    parser.add_argument(
        "--venice-key",
        metavar="KEY",
        default=None,
        help="Venice API key",
    )
    parser.add_argument(
        "--venice-model",
        metavar="ID",
        default=None,
        help="Venice model (default: e2ee-qwen3-27b)",
    )
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("pii_buddy")

    if args.menubar:
        from pii_buddy.menubar import main as menubar_main
        menubar_main()
        return

    # Override base dir if requested
    if args.dir:
        cfg.BASE_DIR = Path(args.dir)
        cfg.INPUT_DIR = cfg.BASE_DIR / "input"
        cfg.OUTPUT_DIR = cfg.BASE_DIR / "output"
        cfg.MAPPINGS_DIR = cfg.BASE_DIR / "mappings"
        cfg.ORIGINALS_DIR = cfg.BASE_DIR / "originals"
        cfg.LOGS_DIR = cfg.BASE_DIR / "logs"
        cfg.USER_BLOCKLISTS_DIR = cfg.BASE_DIR / "blocklists"
        cfg.FEEDBACK_DIR = cfg.BASE_DIR / "feedback"
        # Every directory main.py/watcher.py might need to exist under the
        # overridden base — previously this list dropped blocklists/feedback,
        # so ensure_dirs() never created them under --dir either.
        cfg.ALL_DIRS = [
            cfg.INPUT_DIR, cfg.OUTPUT_DIR, cfg.MAPPINGS_DIR, cfg.ORIGINALS_DIR,
            cfg.LOGS_DIR, cfg.USER_BLOCKLISTS_DIR, cfg.FEEDBACK_DIR,
        ]

    ensure_dirs()

    # Resolve settings: CLI flags > settings.conf > hardcoded defaults
    from pii_buddy.settings import resolve_settings, seed_settings_file

    base_dir = cfg.BASE_DIR
    seed_settings_file(base_dir)

    settings = resolve_settings(
        base_dir=base_dir,
        cli_same_format=args.same_format,
        cli_overwrite=args.overwrite,
        cli_text_output=args.text_output,
        cli_tag=args.tag,
        cli_keep_name=args.keep_name,
        cli_verify=args.verify,
        cli_verify_key=args.verify_key,
        cli_verify_endpoint=args.verify_endpoint,
        cli_verify_confidence=args.verify_confidence,
        cli_no_audit=args.no_audit,
        cli_openrouter=args.openrouter,
        cli_openrouter_key=args.openrouter_key,
        cli_openrouter_model=args.openrouter_model,
        cli_venice=args.venice,
        cli_venice_key=args.venice_key,
        cli_venice_model=args.venice_model,
    )

    # Apply resolved paths back to config module (for code that reads config directly)
    cfg.INPUT_DIR = settings.input_dir
    cfg.OUTPUT_DIR = settings.output_dir

    if args.credits:
        try:
            from pii_buddy.verify_client import VerifyClient, VerifyError
        except ImportError:
            logger.error("Cloud verification is a premium feature. Visit https://piibuddy.com for details.")
            sys.exit(1)
        if not settings.verify_api_key:
            logger.error("No API key configured. Set one in settings.conf [verify] api_key or use --verify-key.")
            sys.exit(1)
        client = VerifyClient(
            api_key=settings.verify_api_key,
            endpoint=settings.verify_endpoint,
        )
        try:
            usage = client.check_usage()
            credits = usage.get("credits_remaining", "unknown")
            used = usage.get("credits_used", "unknown")
            plan = usage.get("plan", "unknown")
            logger.info(f"Credits remaining: {credits}")
            logger.info(f"Credits used:      {used}")
            logger.info(f"Plan:              {plan}")
        except VerifyError as e:
            logger.error(f"Failed to check credits: {e}")
            sys.exit(1)
        return

    if args.buy:
        import webbrowser
        purchase_url = "https://piibuddy.com"
        logger.info(f"Opening {purchase_url} ...")
        webbrowser.open(purchase_url)
        return

    if args.update_app:
        import subprocess

        app_dir = Path(__file__).resolve().parent
        logger.info(f"Updating PII Buddy in {app_dir}...")

        # Check for uncommitted changes
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=app_dir, capture_output=True, text=True,
        )
        if status.stdout.strip():
            logger.warning("You have uncommitted changes. Stashing them first...")
            subprocess.run(["git", "stash"], cwd=app_dir)

        # Pull latest
        result = subprocess.run(
            ["git", "pull", "--rebase"],
            cwd=app_dir, capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.error(f"git pull failed:\n{result.stderr}")
            sys.exit(1)

        output = result.stdout.strip()
        if "Already up to date" in output:
            logger.info("Already up to date.")
        else:
            logger.info(output)
            logger.info("Update complete. Restart PII Buddy to use the new version.")
        return

    if args.update:
        from pii_buddy.updater import update_blocklists
        from pii_buddy.validation import reload_blocklist

        updated = update_blocklists()
        if updated:
            reload_blocklist()
            logger.info("Blocklist update complete.")
        return

    if args.subscribe:
        import re as _re

        email = args.subscribe.strip()
        if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            logger.error("Invalid email format.")
            sys.exit(1)
        # Store locally until api.piibuddy.com is live
        subscribe_dir = cfg.BASE_DIR / "feedback"
        subscribe_dir.mkdir(parents=True, exist_ok=True)
        subscribe_file = subscribe_dir / "pending_subscriptions.txt"
        # Check for duplicates
        existing = subscribe_file.read_text(encoding="utf-8") if subscribe_file.exists() else ""
        if email in existing:
            logger.info(f"Already saved locally: {email}")
        else:
            with open(subscribe_file, "a", encoding="utf-8") as f:
                from datetime import datetime
                f.write(f"{email}\tcli\t{datetime.now().isoformat()}\n")
            logger.info(f"Address saved locally in {subscribe_file}: {email}")
            logger.info("No update server exists yet, so nothing was sent and you are not subscribed to anything.")
        return

    if args.rate or args.feedback:
        from pii_buddy.feedback import record_rating

        if args.rate:
            record_rating(
                rating=args.rate,
                comment=args.feedback or "",
                source="cli",
            )
            logger.info(f"Thanks for rating PII Buddy {'*' * args.rate}{'.' * (5 - args.rate)}")
        elif args.feedback:
            record_rating(
                rating=0,
                comment=args.feedback,
                source="cli",
            )
            logger.info("Feedback recorded. Thank you!")
        return

    if args.paste or args.clipboard:
        from datetime import datetime
        from pii_buddy.detector import detect_pii
        from pii_buddy.redactor import redact

        if args.clipboard:
            import subprocess
            result = subprocess.run(["pbpaste"], capture_output=True, text=True)
            text = result.stdout
            if not text.strip():
                logger.error("Clipboard is empty.")
                sys.exit(1)
            logger.info(f"Read {len(text)} chars from clipboard.")
        else:
            logger.info("Paste text below, then press Ctrl+D when done:\n")
            text = sys.stdin.read()
            if not text.strip():
                logger.error("No text received.")
                sys.exit(1)

        entities = detect_pii(text)
        logger.info(f"Found {len(entities)} PII entities.")
        redacted_text, mapping = redact(text, entities)

        # Pass 2: Structural audit (on by default)
        pre_audit_tags = len(mapping.get("tags", {}))
        if settings.audit_enabled:
            from pii_buddy.audit import audit_redacted
            redacted_text, mapping = audit_redacted(redacted_text, mapping)

        # Pass 3: OpenRouter LLM verification (optional, premium)
        if settings.openrouter_enabled and settings.openrouter_api_key:
            try:
                from pii_buddy.openrouter_verifier import openrouter_verify_and_patch
                redacted_text, mapping = openrouter_verify_and_patch(
                    redacted_text, mapping, settings
                )
            except ImportError:
                logger.warning("OpenRouter verification requires premium modules. Visit https://piibuddy.com")

        # Pass 3b: Venice TEE/E2EE confidential verification (optional, premium)
        if settings.venice_enabled and settings.venice_api_key:
            try:
                from pii_buddy.venice_verifier import venice_verify_and_patch
                redacted_text, mapping = venice_verify_and_patch(
                    redacted_text, mapping, settings
                )
            except ImportError:
                logger.warning("Venice verification requires premium modules. Visit https://piibuddy.com")

        # Upsell: if audit found extra PII and cloud verify is off
        post_tags = len(mapping.get("tags", {}))
        extra_found = post_tags - pre_audit_tags
        if extra_found > 0 and not (settings.verify_enabled and settings.verify_api_key):
            logger.info(
                f"  Audit found {extra_found} additional items. "
                "For deeper detection, try PII Buddy Verify: piibuddy.com"
            )

        # Pass 4: Cloud verification (optional, premium)
        if settings.verify_enabled and settings.verify_api_key:
            try:
                from pii_buddy.verifier import verify_and_patch
                redacted_text, mapping = verify_and_patch(
                    redacted_text, mapping, settings
                )
            except ImportError:
                logger.warning("Cloud verification requires premium modules. Visit https://piibuddy.com")

        # Save mapping file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mapping["metadata"] = {
            "source": "clipboard" if args.clipboard else "stdin",
            "processed_at": datetime.now().isoformat(),
            "entities_found": len(entities),
        }
        mapping_path = cfg.MAPPINGS_DIR / f"pasted_{timestamp}.map.json"
        mapping_path.write_text(
            json.dumps(mapping, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"Mapping saved: {mapping_path.name}")

        if args.clipboard:
            import subprocess
            subprocess.run(["pbcopy"], input=redacted_text, text=True)
            logger.info("Redacted text copied to clipboard. Paste it anywhere.")
        else:
            print("\n" + "=" * 50)
            print("REDACTED OUTPUT:")
            print("=" * 50)
            print(redacted_text)

        logger.info("")
        logger.info("How did we do? Rate this redaction:")
        logger.info("  ./run.sh --rate 1-5 [--feedback \"what we missed\"]")

        return

    if args.restore:
        from pii_buddy.restorer import restore

        redacted_path = Path(args.restore[0])
        mapping_path = Path(args.restore[1])

        if not mapping_path.is_file():
            logger.error(f"Mapping file not found: {mapping_path}")
            sys.exit(1)
        if not redacted_path.is_file():
            logger.error(f"Redacted file not found: {redacted_path}")
            sys.exit(1)
        # Error text names only the path and exception type, never contents.
        try:
            mapping_data = json.loads(mapping_path.read_text(encoding="utf-8"))
            if not isinstance(mapping_data, dict):
                raise ValueError("mapping is not a JSON object")
            tags = mapping_data.get("tags")
            if not isinstance(tags, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in tags.items()
            ):
                raise ValueError("mapping has no valid tags object")
        except (OSError, ValueError) as e:
            logger.error(f"Cannot read mapping file {mapping_path}: {type(e).__name__}")
            sys.exit(1)
        try:
            text = redacted_path.read_text(encoding="utf-8")
        except (OSError, ValueError) as e:
            logger.error(f"Cannot read redacted file {redacted_path}: {type(e).__name__}")
            sys.exit(1)
        restored = restore(text, mapping_path)

        # Build restored filename — strip known prefixes/suffixes
        restored_name = redacted_path.name
        # Try stripping tag prefix
        if settings.tag and restored_name.startswith(settings.tag + "_"):
            restored_name = restored_name[len(settings.tag) + 1:]
        elif restored_name.startswith("PII_FREE_"):
            restored_name = restored_name[len("PII_FREE_"):]
        # Add RESTORED_ prefix
        restored_name = f"RESTORED_{restored_name}"

        out_path = redacted_path.parent / restored_name
        # Restored text is plaintext PII: created 0600, never following a
        # symlink and never replacing an existing file (pick a free name).
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        stem, suffix = os.path.splitext(restored_name)
        try:
            fd = None
            for n in range(0, 1000):
                candidate = out_path if n == 0 else out_path.with_name(f"{stem}_{n}{suffix}")
                try:
                    fd = os.open(candidate, flags, 0o600)
                except (FileExistsError, OSError) as e:
                    if isinstance(e, FileExistsError) or e.errno == errno.ELOOP:
                        continue
                    raise
                out_path = candidate
                break
            if fd is None:
                raise FileExistsError("no free output name")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(restored)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
        except OSError as e:
            logger.error(f"Cannot write restored file {out_path}: {type(e).__name__}")
            sys.exit(1)
        logger.info(f"Restored: {out_path}")
        return

    if args.once:
        from pii_buddy.watcher import process_file

        filepath = Path(args.once).resolve()
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            sys.exit(1)

        if settings.overwrite:
            # Overwrite mode: process in place, no copy needed
            success = process_file(filepath, settings)
        else:
            # Copy to input dir if not already there
            dest = cfg.INPUT_DIR / filepath.name
            if filepath != dest.resolve():
                import shutil
                shutil.copy2(str(filepath), str(dest))
            success = process_file(dest, settings)

        sys.exit(0 if success else 1)

    # Default: watch mode
    from pii_buddy.watcher import watch

    logger.info("=" * 50)
    logger.info("PII Buddy")
    logger.info("=" * 50)
    logger.info(f"Input:    {cfg.INPUT_DIR}")
    logger.info(f"Output:   {cfg.OUTPUT_DIR}")
    logger.info(f"Mappings: {cfg.MAPPINGS_DIR}")
    if settings.output_format == "same":
        logger.info(f"Format:   same as input")
    if settings.overwrite:
        logger.info(f"Mode:     overwrite (originals backed up)")
    if settings.tag != "PII_FREE":
        logger.info(f"Tag:      {settings.tag!r}")
    if not settings.audit_enabled:
        logger.info(f"Audit:    disabled")
    if settings.openrouter_enabled:
        logger.info(f"OpenRouter: enabled ({settings.openrouter_model})")
    if settings.venice_enabled:
        logger.info(f"Venice:   enabled ({settings.venice_model}, TEE/E2EE)")
    if settings.verify_enabled:
        logger.info(f"Verify:   enabled ({settings.verify_endpoint})")
    logger.info("")

    if PII_BUDDY_MAS_BUILD:
        # Sandboxed build: never trust cfg.INPUT_DIR directly — resolve
        # the user-granted, security-scoped bookmark instead.
        watch_root = _mas_resolve_watch_root()
        if watch_root is None:
            return
        watch(watch_root, settings)
    else:
        watch(cfg.INPUT_DIR, settings)


if __name__ == "__main__":
    main()
