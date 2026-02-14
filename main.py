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
import json
import logging
import sys
from pathlib import Path

from pii_buddy.config import ALL_DIRS, INPUT_DIR, OUTPUT_DIR, MAPPINGS_DIR, USER_BLOCKLISTS_DIR


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
    for d in ALL_DIRS:
        d.mkdir(parents=True, exist_ok=True)
    # Seed user blocklist if it doesn't exist
    user_bl = USER_BLOCKLISTS_DIR / "user_blocklist.txt"
    if not user_bl.exists():
        user_bl.write_text(USER_BLOCKLIST_TEMPLATE, encoding="utf-8")


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
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("pii_buddy")

    if args.menubar:
        from pii_buddy.menubar import main as menubar_main
        menubar_main()
        return

    # Override base dir if requested
    if args.dir:
        import pii_buddy.config as cfg
        cfg.BASE_DIR = Path(args.dir)
        cfg.INPUT_DIR = cfg.BASE_DIR / "input"
        cfg.OUTPUT_DIR = cfg.BASE_DIR / "output"
        cfg.MAPPINGS_DIR = cfg.BASE_DIR / "mappings"
        cfg.ORIGINALS_DIR = cfg.BASE_DIR / "originals"
        cfg.LOGS_DIR = cfg.BASE_DIR / "logs"
        cfg.ALL_DIRS = [cfg.INPUT_DIR, cfg.OUTPUT_DIR, cfg.MAPPINGS_DIR, cfg.ORIGINALS_DIR, cfg.LOGS_DIR]

    ensure_dirs()

    # Resolve settings: CLI flags > settings.conf > hardcoded defaults
    import pii_buddy.config as cfg
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
            logger.info(f"Already subscribed: {email}")
        else:
            with open(subscribe_file, "a", encoding="utf-8") as f:
                from datetime import datetime
                f.write(f"{email}\tcli\t{datetime.now().isoformat()}\n")
            logger.info(f"Subscribed! You'll receive product updates at {email}")
            logger.info("(Subscription will sync when the update server is live.)")
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
        import json
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

        # Read mapping to find the original tag pattern
        mapping_data = json.loads(mapping_path.read_text(encoding="utf-8")) if mapping_path.exists() else {}
        original_file = mapping_data.get("metadata", {}).get("original_file", "")

        text = redacted_path.read_text(encoding="utf-8")
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
        out_path.write_text(restored, encoding="utf-8")
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
    if settings.verify_enabled:
        logger.info(f"Verify:   enabled ({settings.verify_endpoint})")
    logger.info("")
    watch(cfg.INPUT_DIR, settings)


if __name__ == "__main__":
    main()
