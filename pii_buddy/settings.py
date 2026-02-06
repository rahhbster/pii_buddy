"""Settings management — config file loading and CLI/config/default merging."""

import configparser
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .config import SETTINGS_FILENAME

logger = logging.getLogger("pii_buddy")

# Default settings.conf content (all values commented out)
SETTINGS_TEMPLATE = """\
# PII Buddy Settings
# Uncomment and change values as needed. CLI flags override these settings.

[paths]
# input_dir = input
# output_dir = output

[output]
# format = txt          # "txt" or "same"
# tag = PII_FREE        # empty = no prefix, appends _redacted
# overwrite = false
# text_output = false

[verify]
# enabled = false
# api_key =
# endpoint = https://api.piibuddy.dev/v1
# confidence_threshold = 0.7
# canaries = false
"""


@dataclass
class Settings:
    """Resolved settings for a PII Buddy run."""
    base_dir: Path = field(default=None)
    input_dir: Path = field(default=None)
    output_dir: Path = field(default=None)
    output_format: str = "txt"        # "txt" or "same"
    tag: str = "PII_FREE"             # prefix tag; empty string = use _redacted suffix
    keep_name: bool = False           # preserve original filename exactly
    overwrite: bool = False           # replace input file (backs up original)
    text_output: bool = False         # also produce .txt alongside formatted output
    verify_enabled: bool = False      # enable cloud verification after local redaction
    verify_api_key: str = ""          # PII Buddy Verify API key
    verify_endpoint: str = "https://api.piibuddy.dev/v1"
    verify_confidence: float = 0.7    # minimum confidence threshold for findings
    verify_canaries: bool = False     # inject canary PII to test provider accuracy

    @classmethod
    def defaults(cls) -> "Settings":
        """Return a Settings instance with all hardcoded defaults."""
        return cls()


def load_config_file(base_dir: Path) -> dict:
    """Load settings.conf from base_dir. Returns a flat dict of found values."""
    config_path = base_dir / SETTINGS_FILENAME
    if not config_path.exists():
        return {}

    parser = configparser.ConfigParser()
    parser.read(str(config_path), encoding="utf-8")

    values = {}

    if parser.has_option("paths", "input_dir"):
        values["input_dir"] = parser.get("paths", "input_dir").strip()
    if parser.has_option("paths", "output_dir"):
        values["output_dir"] = parser.get("paths", "output_dir").strip()

    if parser.has_option("output", "format"):
        values["output_format"] = parser.get("output", "format").strip()
    if parser.has_option("output", "tag"):
        values["tag"] = parser.get("output", "tag").strip()
    if parser.has_option("output", "overwrite"):
        values["overwrite"] = parser.getboolean("output", "overwrite")
    if parser.has_option("output", "text_output"):
        values["text_output"] = parser.getboolean("output", "text_output")

    # [verify] section
    if parser.has_option("verify", "enabled"):
        values["verify_enabled"] = parser.getboolean("verify", "enabled")
    if parser.has_option("verify", "api_key"):
        values["verify_api_key"] = parser.get("verify", "api_key").strip()
    if parser.has_option("verify", "endpoint"):
        values["verify_endpoint"] = parser.get("verify", "endpoint").strip()
    if parser.has_option("verify", "confidence_threshold"):
        values["verify_confidence"] = parser.getfloat("verify", "confidence_threshold")
    if parser.has_option("verify", "canaries"):
        values["verify_canaries"] = parser.getboolean("verify", "canaries")

    return values


def resolve_settings(
    base_dir: Path,
    cli_same_format: bool = False,
    cli_overwrite: bool = False,
    cli_text_output: bool = False,
    cli_tag: str = None,
    cli_keep_name: bool = False,
    cli_verify: bool = False,
    cli_verify_key: str = None,
    cli_verify_endpoint: str = None,
    cli_verify_confidence: float = None,
) -> Settings:
    """
    Three-tier merge: CLI flags > settings.conf > hardcoded defaults.

    cli_tag=None means "not specified on CLI" (use config/default).
    cli_tag="" means "explicitly set to empty" (use _redacted suffix).
    """
    defaults = Settings.defaults()
    conf = load_config_file(base_dir)

    # --- output_format ---
    output_format = defaults.output_format
    if "output_format" in conf:
        output_format = conf["output_format"]
    if cli_same_format:
        output_format = "same"

    # --- tag ---
    tag = defaults.tag
    if "tag" in conf:
        tag = conf["tag"]
    if cli_tag is not None:
        tag = cli_tag

    # --- keep_name ---
    keep_name = cli_keep_name

    # --- overwrite ---
    overwrite = defaults.overwrite
    if "overwrite" in conf:
        overwrite = conf["overwrite"]
    if cli_overwrite:
        overwrite = True
    # --overwrite implies --same-format
    if overwrite:
        output_format = "same"

    # --- text_output ---
    text_output = defaults.text_output
    if "text_output" in conf:
        text_output = conf["text_output"]
    if cli_text_output:
        text_output = True

    # --- paths ---
    input_rel = conf.get("input_dir", "input")
    output_rel = conf.get("output_dir", "output")
    input_dir = base_dir / input_rel
    output_dir = base_dir / output_rel

    # --- verify ---
    verify_enabled = defaults.verify_enabled
    if "verify_enabled" in conf:
        verify_enabled = conf["verify_enabled"]
    if cli_verify:
        verify_enabled = True

    verify_api_key = defaults.verify_api_key
    if "verify_api_key" in conf:
        verify_api_key = conf["verify_api_key"]
    if cli_verify_key is not None:
        verify_api_key = cli_verify_key

    verify_endpoint = defaults.verify_endpoint
    if "verify_endpoint" in conf:
        verify_endpoint = conf["verify_endpoint"]
    if cli_verify_endpoint is not None:
        verify_endpoint = cli_verify_endpoint

    verify_confidence = defaults.verify_confidence
    if "verify_confidence" in conf:
        verify_confidence = conf["verify_confidence"]
    if cli_verify_confidence is not None:
        verify_confidence = cli_verify_confidence

    verify_canaries = defaults.verify_canaries
    if "verify_canaries" in conf:
        verify_canaries = conf["verify_canaries"]

    # --verify requires an API key
    if verify_enabled and not verify_api_key:
        logger.warning("--verify requires an API key (--verify-key or settings.conf)")
        verify_enabled = False

    return Settings(
        base_dir=base_dir,
        input_dir=input_dir,
        output_dir=output_dir,
        output_format=output_format,
        tag=tag,
        keep_name=keep_name,
        overwrite=overwrite,
        text_output=text_output,
        verify_enabled=verify_enabled,
        verify_api_key=verify_api_key,
        verify_endpoint=verify_endpoint,
        verify_confidence=verify_confidence,
        verify_canaries=verify_canaries,
    )


def seed_settings_file(base_dir: Path) -> None:
    """Create settings.conf with commented-out defaults if it doesn't exist."""
    config_path = base_dir / SETTINGS_FILENAME
    if not config_path.exists():
        config_path.write_text(SETTINGS_TEMPLATE, encoding="utf-8")
        logger.info(f"Created default settings file: {config_path}")
