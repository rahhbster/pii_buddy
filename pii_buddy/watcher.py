"""Watch input folder and process new files."""

import json
import logging
import re
import shutil
import time
from datetime import datetime, timedelta
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .config import (
    INPUT_DIR,
    MAPPINGS_DIR,
    ORIGINALS_DIR,
    ORIGINALS_RETENTION_HOURS,
    OUTPUT_DIR,
    SUPPORTED_EXTENSIONS,
)
from .detector import detect_pii
from .extractor import extract_text
from .redactor import redact
from .settings import Settings
from .writers import write_output, write_txt

logger = logging.getLogger("pii_buddy")


def _redact_filename(filename: str, person_map: dict) -> str:
    """
    Redact PII from a filename.

    Replaces name fragments found in the person mapping.
    e.g., "sarah_chen_resume.pdf" -> "sc_resume.pdf"
    """
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    redacted_stem = stem

    # Sort by length descending so "sarah_chen" is checked before "sarah"
    for surface, tag in sorted(person_map.items(), key=lambda x: len(x[0]), reverse=True):
        # Check for name in various filename formats: underscores, hyphens, dots, camelCase
        for separator in ["_", "-", ".", " "]:
            name_variant = surface.lower().replace(" ", separator)
            if name_variant in redacted_stem.lower():
                # Replace with initials (strip << >> from tag)
                initials = tag.strip("<>").lower()
                redacted_stem = re.sub(re.escape(name_variant), initials, redacted_stem, flags=re.IGNORECASE)

        # Also check for first/last names individually
        for part in surface.lower().split():
            if len(part) > 2 and part in redacted_stem.lower():
                initials = tag.strip("<>").lower()
                redacted_stem = re.sub(r'\b' + re.escape(part) + r'\b', initials, redacted_stem, flags=re.IGNORECASE)

    return redacted_stem + suffix


def _apply_tag(clean_name: str, settings: Settings) -> str:
    """Apply filename tag based on settings.

    Returns the final filename stem (no extension).
    """
    if settings.keep_name:
        return clean_name
    if settings.tag:
        return f"{settings.tag}_{clean_name}"
    # Empty tag — use _redacted suffix
    return f"{clean_name}_redacted"


def process_file(filepath: Path, settings: Settings = None) -> bool:
    """Process a single file. Returns True on success."""
    if settings is None:
        settings = Settings.defaults()

    if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
        logger.warning(f"Skipping unsupported file: {filepath.name}")
        return False

    logger.info(f"Processing: {filepath.name}")

    try:
        input_suffix = filepath.suffix.lower()

        # 1. Extract text
        text = extract_text(filepath)
        if not text.strip():
            logger.warning(f"No text extracted from {filepath.name}")
            return False

        # 2. Detect PII
        entities = detect_pii(text)
        logger.info(f"  Found {len(entities)} PII entities")

        # 3. Redact
        redacted_text, mapping = redact(text, entities)

        # 4. Redact the filename and apply tag
        clean_name = _redact_filename(filepath.stem, mapping.get("persons", {}))
        tagged_name = _apply_tag(clean_name, settings)

        # 5. Determine output location and write
        if settings.overwrite:
            # Overwrite mode: back up original, then write output to input location
            backup_dest = ORIGINALS_DIR / filepath.name
            shutil.copy2(str(filepath), str(backup_dest))
            logger.info(f"  Backup: originals/{filepath.name}")

            # Write in same format to the original file's location
            output_path = write_output(
                redacted_text,
                filepath.parent / filepath.stem,
                "same",
                input_suffix,
            )
            logger.info(f"  Overwritten: {output_path.name}")
        else:
            output_dir = settings.output_dir or OUTPUT_DIR
            # Write primary output
            output_path = write_output(
                redacted_text,
                output_dir / tagged_name,
                settings.output_format,
                input_suffix,
            )
            logger.info(f"  Output: {output_path.name}")

            # Write additional .txt if text_output is set and primary isn't .txt
            if settings.text_output and output_path.suffix.lower() != ".txt":
                txt_path = output_dir / f"{tagged_name}.txt"
                write_txt(redacted_text, txt_path)
                logger.info(f"  Text output: {txt_path.name}")

            # Move original to originals folder
            dest = ORIGINALS_DIR / filepath.name
            shutil.move(str(filepath), str(dest))
            logger.info(f"  Original moved to: originals/{filepath.name}")

        # 6. Save mapping for reversibility
        mapping["metadata"] = {
            "original_file": filepath.name,
            "output_file": output_path.name,
            "processed_at": datetime.now().isoformat(),
            "entities_found": len(entities),
        }
        mapping_path = MAPPINGS_DIR / f"{clean_name}.map.json"
        mapping_path.write_text(
            json.dumps(mapping, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"  Mapping: {mapping_path.name}")

        return True

    except Exception as e:
        logger.error(f"  Error processing {filepath.name}: {e}", exc_info=True)
        return False


def cleanup_originals():
    """Delete originals older than the retention period."""
    cutoff = datetime.now() - timedelta(hours=ORIGINALS_RETENTION_HOURS)
    for f in ORIGINALS_DIR.iterdir():
        if f.is_file():
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if mtime < cutoff:
                f.unlink()
                logger.info(f"Cleaned up original: {f.name}")


class NewFileHandler(FileSystemEventHandler):
    def __init__(self, settings: Settings = None):
        super().__init__()
        self.settings = settings or Settings.defaults()

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = Path(event.src_path)
        if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
            return
        # Small delay to let file finish writing
        time.sleep(1)
        process_file(filepath, self.settings)

    def on_moved(self, event):
        """Also handle files moved into the folder."""
        if event.is_directory:
            return
        filepath = Path(event.dest_path)
        if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
            return
        time.sleep(1)
        process_file(filepath, self.settings)


def watch(input_dir: Path = INPUT_DIR, settings: Settings = None):
    """Start watching the input directory. Blocks until interrupted."""
    handler = NewFileHandler(settings)
    observer = Observer()
    observer.schedule(handler, str(input_dir), recursive=False)
    observer.start()
    logger.info(f"Watching: {input_dir}")
    logger.info("Drop PDF, DOCX, or TXT files into the input folder.")
    logger.info("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(60)
            cleanup_originals()
    except KeyboardInterrupt:
        observer.stop()
        logger.info("\nStopped.")
    observer.join()
