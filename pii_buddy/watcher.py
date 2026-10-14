"""Watch input folder and process new files."""

import json
import logging
import os
import re
import shutil
import stat
import time
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import config as cfg
from .config import INPUT_DIR, ORIGINALS_RETENTION_HOURS, SUPPORTED_EXTENSIONS
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
                # Replace with initials from tag
                initials = tag.removeprefix("<NAME ").removesuffix(">").lower() if tag.startswith("<NAME ") else tag.strip("<>").lower()
                redacted_stem = re.sub(re.escape(name_variant), initials, redacted_stem, flags=re.IGNORECASE)

        # Also check for first/last names individually
        for part in surface.lower().split():
            if len(part) > 2 and part in redacted_stem.lower():
                initials = tag.removeprefix("<NAME ").removesuffix(">").lower() if tag.startswith("<NAME ") else tag.strip("<>").lower()
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


def _safe_to_unlink_input(filepath: Path, output_path: Path) -> bool:
    if output_path == filepath or not filepath.exists():
        return False
    try:
        if output_path.stat().st_size == 0:
            return False
        return not os.path.samefile(output_path, filepath)
    except OSError:
        return False


def process_file(filepath: Path, settings: Settings = None) -> bool:
    """Process a single file. Returns True on success."""
    if settings is None:
        settings = Settings.defaults()

    if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
        logger.warning(f"Skipping unsupported file: {filepath.name}")
        return False

    logger.info(f"Processing: {filepath.name}")

    mapping_path = None
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

        # 3.5a Structural audit (on by default)
        if settings.audit_enabled:
            from .audit import audit_redacted
            redacted_text, mapping = audit_redacted(redacted_text, mapping)

        # 3.5b OpenRouter LLM verification (optional, premium)
        if settings.openrouter_enabled and settings.openrouter_api_key:
            try:
                from .openrouter_verifier import openrouter_verify_and_patch
                redacted_text, mapping = openrouter_verify_and_patch(
                    redacted_text, mapping, settings
                )
            except ImportError:
                logger.warning("OpenRouter verification requires premium modules. Visit https://piibuddy.com")

        # 3.5b-2 Venice TEE/E2EE confidential verification (optional, premium)
        if settings.venice_enabled and settings.venice_api_key:
            try:
                from .venice_verifier import venice_verify_and_patch
                redacted_text, mapping = venice_verify_and_patch(
                    redacted_text, mapping, settings
                )
            except ImportError:
                logger.warning("Venice verification requires premium modules. Visit https://piibuddy.com")

        # 3.5c Cloud verification (optional, premium)
        if settings.verify_enabled and settings.verify_api_key:
            try:
                from .verifier import verify_and_patch
                redacted_text, mapping = verify_and_patch(
                    redacted_text, mapping, settings
                )
            except ImportError:
                logger.warning("Cloud verification requires premium modules. Visit https://piibuddy.com")

        # 4. Redact the filename and apply tag
        clean_name = _redact_filename(filepath.stem, mapping.get("persons", {}))
        tagged_name = _apply_tag(clean_name, settings)

        # 5. Determine output location and write
        cfg.ensure_private_dir(cfg.ORIGINALS_DIR)
        cfg.ensure_private_dir(cfg.MAPPINGS_DIR)

        # Claim the mapping name first and derive the output stem from it, so
        # a reprocessed filename gives `PII_FREE_c.<stamp>.txt` and
        # `PII_FREE_c.<stamp>.map.json` rather than two unrelated suffixes.
        if settings.overwrite:
            mapping_path = cfg.claim_name(cfg.MAPPINGS_DIR, clean_name, ".map.json")
        else:
            mapping_path = cfg.claim_name(cfg.MAPPINGS_DIR, tagged_name, ".map.json")
            tagged_name = mapping_path.name.removesuffix(".map.json")

        if settings.overwrite:
            # Overwrite mode: back up original, then write output to input location
            backup_dest = cfg.claim_path(cfg.ORIGINALS_DIR / filepath.name)
            shutil.copyfile(str(filepath), str(backup_dest))
            stored_original = backup_dest.name
            logger.info(f"  Backup: originals/{stored_original}")

            # Write in same format to the original file's location
            output_path = write_output(
                redacted_text,
                filepath.parent / filepath.stem,
                "same",
                filepath.suffix,
                overwrite_existing=True,
            )
            logger.info(f"  Overwritten: {output_path.name}")

            # A .doc is rewritten as .docx, which leaves the PII-bearing
            # original beside the output; the backup above already holds it.
            # Only after the output is verified, and never when it is the
            # input itself (resolved-path comparison misses case-variant
            # names on case-insensitive filesystems).
            if _safe_to_unlink_input(filepath, output_path):
                filepath.unlink()
        else:
            output_dir = settings.output_dir or cfg.OUTPUT_DIR
            output_dir.mkdir(parents=True, exist_ok=True)
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
                txt_path = cfg.claim_name(output_dir, tagged_name, ".txt", 0o666)
                write_txt(redacted_text, txt_path)
                logger.info(f"  Text output: {txt_path.name}")

            # Move original to originals folder (owner-only, never replacing
            # an earlier original that happens to share the filename)
            dest = cfg.claim_path(cfg.ORIGINALS_DIR / filepath.name)
            os.chmod(filepath, 0o600)
            shutil.move(str(filepath), str(dest))
            stored_original = dest.name
            logger.info(f"  Original moved to: originals/{stored_original}")

        # 6. Save mapping for reversibility
        mapping["metadata"] = {
            "original_file": filepath.name,
            "stored_original": stored_original,
            "output_file": output_path.name,
            "mapping_file": mapping_path.name,
            "processed_at": datetime.now().isoformat(),
            "entities_found": len(entities),
        }
        cfg.write_private_text(
            mapping_path,
            json.dumps(mapping, indent=2, ensure_ascii=False),
        )
        logger.info(f"  Mapping: {mapping_path.name}")
        logger.info("")
        logger.info("  How did we do? Rate this redaction:")
        logger.info("    ./run.sh --rate 1-5 [--feedback \"what we missed\"]")

        return True

    except Exception as e:
        if mapping_path is not None:
            try:
                if mapping_path.stat().st_size == 0:
                    mapping_path.unlink()
            except OSError:
                pass
        logger.error(f"  Error processing {filepath.name}: {e}", exc_info=True)
        return False


def cleanup_originals(retention_hours: float = ORIGINALS_RETENTION_HOURS) -> int:
    """Delete originals older than the retention period. Returns the count removed.

    Only regular files directly inside the originals folder are touched;
    symlinks are never followed.
    """
    cutoff = time.time() - retention_hours * 3600
    removed = 0
    try:
        entries = list(cfg.ORIGINALS_DIR.iterdir())
    except FileNotFoundError:
        return 0
    for f in entries:
        try:
            st = f.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_mtime >= cutoff:
                continue
            f.unlink()
            removed += 1
            logger.info(f"Cleaned up original: {f.name}")
        except OSError as e:
            logger.warning(f"Could not clean up {f.name}: {e}")
    return removed


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
