#!/usr/bin/env python3
"""
PII Buddy — Drop files in, get redacted files out.

Usage:
    python main.py                  Watch the input folder (default: ~/PII_Buddy/input)
    python main.py --once FILE      Process a single file and exit
    python main.py --paste          Paste text via stdin, get redacted output
    python main.py --clipboard      Read clipboard, redact, write back to clipboard
    python main.py --restore REDACTED_FILE MAPPING_FILE   Restore PII

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
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("pii_buddy")

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
    )

    # Apply resolved paths back to config module (for code that reads config directly)
    cfg.INPUT_DIR = settings.input_dir
    cfg.OUTPUT_DIR = settings.output_dir

    if args.update:
        from pii_buddy.updater import update_blocklists
        from pii_buddy.validation import reload_blocklist

        updated = update_blocklists()
        if updated:
            reload_blocklist()
            logger.info("Blocklist update complete.")
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
    logger.info("")
    watch(cfg.INPUT_DIR, settings)


if __name__ == "__main__":
    main()
