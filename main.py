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
import logging
import sys
from pathlib import Path

from pii_buddy.config import ALL_DIRS, INPUT_DIR, OUTPUT_DIR, MAPPINGS_DIR


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
        mapping_path = MAPPINGS_DIR / f"pasted_{timestamp}.map.json"
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
        text = redacted_path.read_text(encoding="utf-8")
        restored = restore(text, mapping_path)
        out_path = redacted_path.parent / redacted_path.name.replace("PII_FREE_", "RESTORED_")
        out_path.write_text(restored, encoding="utf-8")
        logger.info(f"Restored: {out_path}")
        return

    if args.once:
        from pii_buddy.watcher import process_file

        filepath = Path(args.once).resolve()
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            sys.exit(1)
        # If file is already in input dir, process in place; otherwise copy it
        dest = INPUT_DIR / filepath.name
        if filepath != dest.resolve():
            import shutil
            shutil.copy2(str(filepath), str(dest))
        success = process_file(dest)
        sys.exit(0 if success else 1)

    # Default: watch mode
    from pii_buddy.watcher import watch

    logger.info("=" * 50)
    logger.info("PII Buddy")
    logger.info("=" * 50)
    logger.info(f"Input:    {INPUT_DIR}")
    logger.info(f"Output:   {OUTPUT_DIR}")
    logger.info(f"Mappings: {MAPPINGS_DIR}")
    logger.info("")
    watch()


if __name__ == "__main__":
    main()
