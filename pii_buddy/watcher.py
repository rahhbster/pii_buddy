"""Watch input folder and process new files."""

import json
import logging
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

logger = logging.getLogger("pii_buddy")


def process_file(filepath: Path) -> bool:
    """Process a single file. Returns True on success."""
    if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
        logger.warning(f"Skipping unsupported file: {filepath.name}")
        return False

    logger.info(f"Processing: {filepath.name}")

    try:
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

        # 4. Save redacted output
        stem = filepath.stem
        output_path = OUTPUT_DIR / f"PII_FREE_{stem}.txt"
        output_path.write_text(redacted_text, encoding="utf-8")
        logger.info(f"  Output: {output_path.name}")

        # 5. Save mapping for reversibility
        mapping["metadata"] = {
            "original_file": filepath.name,
            "processed_at": datetime.now().isoformat(),
            "entities_found": len(entities),
        }
        mapping_path = MAPPINGS_DIR / f"{stem}.map.json"
        mapping_path.write_text(
            json.dumps(mapping, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"  Mapping: {mapping_path.name}")

        # 6. Move original to originals folder
        dest = ORIGINALS_DIR / filepath.name
        shutil.move(str(filepath), str(dest))
        logger.info(f"  Original moved to: originals/{filepath.name}")

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
    def on_created(self, event):
        if event.is_directory:
            return
        filepath = Path(event.src_path)
        if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
            return
        # Small delay to let file finish writing
        time.sleep(1)
        process_file(filepath)

    def on_moved(self, event):
        """Also handle files moved into the folder."""
        if event.is_directory:
            return
        filepath = Path(event.dest_path)
        if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
            return
        time.sleep(1)
        process_file(filepath)


def watch(input_dir: Path = INPUT_DIR):
    """Start watching the input directory. Blocks until interrupted."""
    handler = NewFileHandler()
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
