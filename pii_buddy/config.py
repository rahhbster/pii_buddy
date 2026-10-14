import logging
import os
import stat
from datetime import datetime
from pathlib import Path

# Base directory — defaults to ~/PII_Buddy but can be overridden via env var
BASE_DIR = Path(os.environ.get("PII_BUDDY_DIR", Path.home() / "PII_Buddy"))

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
MAPPINGS_DIR = BASE_DIR / "mappings"
ORIGINALS_DIR = BASE_DIR / "originals"
LOGS_DIR = BASE_DIR / "logs"
USER_BLOCKLISTS_DIR = BASE_DIR / "blocklists"
FEEDBACK_DIR = BASE_DIR / "feedback"

ALL_DIRS = [INPUT_DIR, OUTPUT_DIR, MAPPINGS_DIR, ORIGINALS_DIR, LOGS_DIR, USER_BLOCKLISTS_DIR, FEEDBACK_DIR]

# Set (by the MAS build's entry point / Info.plist environment, or manually
# for local dry-run testing) when running as the sandboxed Mac App Store
# variant. Gates sandbox-only behavior (security-scoped bookmarks, the
# "Choose Watch Folder…" menu item, cloud-verify feature availability) so
# the existing direct-download/notarized build is completely unaffected.
PII_BUDDY_MAS_BUILD = os.environ.get("PII_BUDDY_MAS_BUILD", "0") == "1"

# Supported file extensions
SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".doc", ".txt"}

# How long to keep originals before cleanup (hours)
ORIGINALS_RETENTION_HOURS = 24

# Settings file
SETTINGS_FILENAME = "settings.conf"

# GitHub repo for blocklist updates
GITHUB_REPO = "rahhbster/pii_buddy"
GITHUB_BRANCH = "main"
GITHUB_BLOCKLIST_PATH = "pii_buddy/data/blocklists/person_blocklist.txt"

# Tag formats for each PII type
TAG_TEMPLATES = {
    "PERSON": "<NAME {initials}>",
    "EMAIL": "<<EMAIL_{n}>>",
    "PHONE": "<<PHONE_{n}>>",
    "SSN": "<<SSN_{n}>>",
    "URL": "<<URL_{n}>>",
    "DOB": "<<DOB_{n}>>",
    "ID_NUMBER": "<<ID_{n}>>",
    "ADDRESS": "<<ADDR_{n}>>",
}


_warned_dirs: set = set()


def ensure_private_dir(path: Path) -> None:
    """Create a directory readable only by the owner.

    A pre-existing directory is only tightened (group/other bits dropped,
    owner rwx guaranteed), never loosened, a symlink is left alone, and its contents are not visited.
    """
    try:
        path.mkdir(mode=0o700, parents=True)
        return
    except FileExistsError:
        pass
    if path.is_symlink():
        return  # never chmod through a link to somewhere else
    try:
        current = stat.S_IMODE(path.stat().st_mode)
        # An owner lacking r or x has locked themselves out; restore rwx. An
        # owner who has r and x (e.g. a deliberate 0o500) is left as-is.
        owner = current & 0o700
        if owner & 0o500 != 0o500:
            owner = 0o700
        if current != owner:
            os.chmod(path, owner)
    except OSError as e:
        # e.g. a directory owned by another user: keep working, tell once.
        if path not in _warned_dirs:
            _warned_dirs.add(path)
            logging.getLogger("pii_buddy").warning(
                f"Could not tighten permissions on {path} ({type(e).__name__})"
            )


def tighten_private_files(directory: Path) -> None:
    """Drop group/other bits from regular files we own directly inside `directory`.

    Files created before the 0600 policy keep their old modes otherwise.
    Never loosens, never follows symlinks, ignores every error.
    """
    try:
        entries = list(directory.iterdir())
        uid = os.getuid()
    except (OSError, AttributeError):
        return
    for f in entries:
        try:
            st = f.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != uid:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o177 == 0:
                continue
            fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                os.fchmod(fd, mode & 0o600)
            finally:
                os.close(fd)
        except OSError:
            continue


_tightened_dirs: set = set()


def tighten_private_files_once(directory: Path) -> None:
    """tighten_private_files, at most once per directory per process."""
    if directory not in _tightened_dirs:
        _tightened_dirs.add(directory)
        tighten_private_files(directory)


def write_private_text(path: Path, text: str) -> None:
    """Write a file that is 0600 from the moment it exists (no chmod-after-write window)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def claim_path(path: Path, mode: int = 0o600) -> Path:
    """Atomically create an empty file at `path`, or at a unique sibling if taken.

    Never overwrites an existing file. The first claimant keeps the bare
    name; later ones get `<stem>.<YYYYmmddTHHMMSS>[-n]<suffix>`.
    """
    return claim_name(path.parent, path.stem, path.suffix, mode)


def claim_name(directory: Path, stem: str, suffix: str, mode: int = 0o600) -> Path:
    """Like claim_path but with an explicit stem and (possibly compound) suffix."""
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    candidate = directory / f"{stem}{suffix}"
    n = 0
    while True:
        try:
            os.close(os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode))
            return candidate
        except FileExistsError:
            n += 1
            tail = stamp if n == 1 else f"{stamp}-{n - 1}"
            candidate = directory / f"{stem}.{tail}{suffix}"
