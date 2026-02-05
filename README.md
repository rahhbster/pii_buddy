# PII Buddy

A lightweight utility that watches a folder on your computer and automatically redacts Personally Identifiable Information (PII) from documents. Drop a file in, get a clean file out.

Built for processing resumes, transcripts, and other documents where PII needs to be stripped before sharing or review.

## What It Redacts

| PII Type | Example Input | Replacement |
|---|---|---|
| **Names** | Steve Johnson | `<<SJ>>` |
| **First-name references** | Steve | `<<SJ>>` (linked to full name) |
| **ALL CAPS names** | STEVE JOHNSON | `<<SJ>>` (resume headers) |
| **Email addresses** | steve@gmail.com | `<<EMAIL_1>>` |
| **Phone numbers** | (555) 867-5309 | `<<PHONE_1>>` |
| **Social Security Numbers** | 123-45-6789 | `<<SSN_1>>` |
| **URLs / LinkedIn** | linkedin.com/in/steve | `<<URL_1>>` |
| **Street addresses** | 123 Oak St, Apt 4B | `<<ADDRESS_1>>` |
| **Dates of birth** | 03/15/1988 | `<<DOB_1>>` |
| **ID numbers** (DL, passport) | D1234567 | `<<ID_NUMBER_1>>` |
| **Credential IDs** | AWS-CP-2847163 | `<<ID_NUMBER_2>>` |

City, state, and country are preserved. Date ranges and relative dates (e.g., "January 2020 - Present", "10+ years") are left intact. Filenames containing PII are also redacted (e.g., `sarah_chen_resume.txt` becomes `PII_FREE_sc_resume.txt`).

In transcripts, each person's name is replaced with a unique initials-based tag, and all references to that person (full name, first name) use the same tag throughout the document.

## Reversibility

Every processed file gets a companion `.map.json` file that stores the mapping between tags and original values. This means PII can be restored later if needed.

## Requirements

- **macOS** or **Linux** (Windows support possible but untested)
- **Python 3.9+** (Python 3.12 recommended)
  - On macOS with Homebrew: `brew install python@3.12`

## Installation

```bash
# Clone the repo
git clone https://github.com/rahhbster/pii_buddy.git
cd pii_buddy

# Run setup (creates virtual environment, installs dependencies, downloads NLP models)
./setup.sh
```

Setup takes about 2-3 minutes. It will:
1. Find a suitable Python 3.9+ on your system
2. Create an isolated virtual environment in `.venv/`
3. Install dependencies (spaCy, watchdog, pdfplumber, python-docx)
4. Download spaCy English language models (`en_core_web_md` ~40MB, `en_core_web_sm` ~12MB fallback)
5. Create the working folder structure at `~/PII_Buddy/`

## Folder Structure

After setup, a `PII_Buddy` folder is created in your home directory:

```
~/PII_Buddy/
├── input/       # Drop files here to be processed
├── output/      # Redacted files appear here (PII_FREE_*.txt)
├── mappings/    # JSON mapping files for reversibility
├── originals/   # Originals are moved here after processing
├── blocklists/  # Your personal blocklist (never overwritten by updates)
└── logs/        # Processing logs
```

To use a different location, set the `PII_BUDDY_DIR` environment variable before running setup or the tool:

```bash
export PII_BUDDY_DIR=/path/to/your/folder
./setup.sh
```

## Usage

### Watch Mode (primary usage)

Start the folder watcher — it runs continuously and processes files as they appear:

```bash
./run.sh
```

Then drag/drop or copy any PDF, DOCX, or TXT file into `~/PII_Buddy/input/`. The redacted version appears in `~/PII_Buddy/output/` within seconds.

```
12:16:07  Watching: /Users/you/PII_Buddy/input
12:16:07  Drop PDF, DOCX, or TXT files into the input folder.
12:16:07  Press Ctrl+C to stop.

12:16:12  Processing: sarah_chen_resume.txt
12:16:13    Found 28 PII entities
12:16:13    Output: PII_FREE_sc_resume.txt
12:16:13    Mapping: sc_resume.map.json
12:16:13    Original moved to: originals/sarah_chen_resume.txt
```

Press `Ctrl+C` to stop watching.

### Single File Mode

Process one file and exit:

```bash
./run.sh --once /path/to/document.pdf
```

### Clipboard Mode (macOS)

Reads from your clipboard, redacts PII, and puts the result back on your clipboard:

```bash
./run.sh --clipboard
```

Workflow: Copy text anywhere (Cmd+C) → run the command → paste the redacted version (Cmd+V).

### Paste Mode

Paste or pipe text directly via stdin:

```bash
./run.sh --paste
```

Then paste your text and press `Ctrl+D` when done. The redacted output prints to the terminal.

You can also pipe text in:

```bash
cat notes.txt | ./run.sh --paste
pbpaste | ./run.sh --paste
```

Both clipboard and paste modes save a mapping file to `~/PII_Buddy/mappings/` so the redaction is still reversible.

### Restore PII

Re-insert PII into a redacted file using its mapping:

```bash
./run.sh --restore ~/PII_Buddy/output/PII_FREE_sc_resume.txt ~/PII_Buddy/mappings/sc_resume.map.json
```

This creates a `RESTORED_sc_resume.txt` file in the output folder.

### Custom Directory

Override the working directory for a single run:

```bash
./run.sh --dir /path/to/custom/folder
```

## Supported File Types

| Format | Input | Output |
|---|---|---|
| PDF (`.pdf`) | Extracts text from all pages | Plain text (`.txt`) |
| Word (`.docx`) | Extracts paragraph text | Plain text (`.txt`) |
| Plain text (`.txt`) | Read directly | Plain text (`.txt`) |

## How It Works

PII Buddy uses a two-pass detection pipeline for accuracy:

### Pass 1: Detection (permissive)

All potential PII is identified using multiple methods:

- **Regex patterns** catch structured PII: emails, phone numbers, SSNs, URLs, dates, ID numbers, credential IDs, street addresses
- **spaCy NER** (`en_core_web_md` model with 514K word vectors) catches person names and contextual dates
- **ALL CAPS detection** catches names in resume headers that spaCy misses
- **Document type auto-detection** identifies resumes vs transcripts vs general documents
- Regex matches take priority when they overlap with spaCy entities

### Pass 2: Validation (selective)

Each PERSON entity is scored on a 0.0-1.0 confidence scale using multiple signals:

- **Blocklist check** — 140+ known false positives (job titles, certifications, section headers, geographic terms) are immediately rejected
- **Job title pattern matching** — "Senior Software Engineer", "Cloud Practitioner", etc. are filtered out
- **Certification detection** — "AWS Certified", "Scrum Alliance", etc. are filtered out
- **Section header detection** — "Professional Summary", "Education", etc. are filtered out
- **POS tag analysis** — proper nouns (NNP) boost confidence; non-nouns reduce it
- **Cross-entity validation** — if spaCy tags something as ORG/GPE/LOC, it won't be treated as a person
- **Structural checks** — word count, capitalization patterns, international name support

Entities scoring below 0.6 confidence are rejected. This eliminates false positives while keeping real names.

### Post-detection

- **Redaction** — Each PII item is replaced with a tagged placeholder. Names become initials-based tags; other types get numbered sequential tags
- **Filename redaction** — PII in filenames is also replaced (e.g., `sarah_chen_resume.txt` → `sc_resume.txt`)
- **Mapping** — A JSON file records every tag-to-original-value pair for later restoration
- **Cleanup** — Originals are moved to the `originals/` folder and automatically deleted after 24 hours

## Example

**Input** (`sarah_chen_resume.txt`):
```
SARAH CHEN
Senior Product Manager
sarah.chen@outlook.com | (415) 892-3047

2847 Mission Street, Apt 12
San Francisco, CA 94110

Collaborate with engineering lead David Park and design director Lisa Nakamura
```

**Output** (`PII_FREE_sc_resume.txt`):
```
<<SC>>
Senior Product Manager
<<EMAIL_1>> | <<PHONE_1>>

<<ADDRESS_1>>
San Francisco, CA 94110

Collaborate with engineering lead <<DP>> and design director <<LN>>
```

Note that "Senior Product Manager" is correctly left intact (not a person), while all actual names are redacted. The filename is also redacted from `sarah_chen_resume` to `sc_resume`.

**Mapping** (`sc_resume.map.json`):
```json
{
  "tags": {
    "<<SC>>": "Sarah Chen",
    "<<DP>>": "David Park",
    "<<LN>>": "Lisa Nakamura",
    "<<EMAIL_1>>": "sarah.chen@outlook.com",
    "<<PHONE_1>>": "(415) 892-3047",
    "<<ADDRESS_1>>": "2847 Mission Street, Apt 12"
  },
  "persons": {
    "Sarah Chen": "<<SC>>",
    "David Park": "<<DP>>",
    "Lisa Nakamura": "<<LN>>"
  }
}
```

## Blocklists

PII Buddy uses a three-tier blocklist system to prevent false positives. All blocklists are loaded together — a term in any list will never be treated as a person's name.

### Tier 1: Official Blocklist (updated from GitHub)

```
pii_buddy/data/blocklists/person_blocklist.txt
```

Ships with 140+ entries covering job titles, certifications, resume section headers, and geographic terms. This file is **overwritten** when you run `--update` (see below).

### Tier 2: Your Personal Blocklist (never overwritten)

```
~/PII_Buddy/blocklists/user_blocklist.txt
```

This file is yours. Add company names, product names, or any terms that get incorrectly redacted. It will **never** be overwritten by updates. One entry per line, case-insensitive:

```
# My terms to never redact
My Company Name
Specific Product Name
Internal Project Codename
```

### Tier 3: Package Custom Blocklist

```
pii_buddy/data/blocklists/custom_blocklist.txt
```

A template file in the package for quick edits. Note: this file lives in the git repo, so local changes may be overwritten by `git pull`.

Changes to any blocklist take effect on the next file processed (no restart needed).

### Updating Blocklists

Pull the latest official blocklist from GitHub:

```bash
./run.sh --update
```

This downloads the newest `person_blocklist.txt` from the repo, backs up your current version, and shows what changed. Your personal `user_blocklist.txt` is never touched.

Run this periodically to pick up new false-positive terms as they're added to the project.

## Troubleshooting

**`setup.sh` fails with Python version error**
You need Python 3.9+. On macOS: `brew install python@3.12`

**spaCy model download fails**
Run manually:
```bash
.venv/bin/python -m spacy download en_core_web_md
```

**A non-person term keeps getting redacted**
Add it to `~/PII_Buddy/blocklists/user_blocklist.txt` (one term per line). This file is never overwritten by updates.

**Files not being detected in watch mode**
Make sure the file extension is `.pdf`, `.docx`, or `.txt`. Other formats are skipped.

**Names not being detected**
The medium model (`en_core_web_md`) handles most English names well. For better accuracy on unusual names, upgrade to the transformer model (slower, requires more disk):
```bash
.venv/bin/python -m spacy download en_core_web_trf
```
Then edit `pii_buddy/detector.py` and change `SPACY_MODEL = "en_core_web_md"` to `SPACY_MODEL = "en_core_web_trf"`.

## Architecture

```
pii_buddy/
├── main.py              # Entry point (watch, --once, --paste, --clipboard, --restore, --update)
├── pii_buddy/
│   ├── config.py        # Folder paths, supported extensions, tag templates, GitHub config
│   ├── detector.py      # PII detection (regex + spaCy NER + ALL CAPS + doc type)
│   ├── validation.py    # Confidence scoring, blocklists, false positive filtering
│   ├── redactor.py      # Tag replacement, name grouping, initials generation
│   ├── extractor.py     # Text extraction from PDF / DOCX / TXT
│   ├── restorer.py      # Reverse redaction using mapping files
│   ├── watcher.py       # Folder monitoring, file pipeline, filename redaction
│   ├── updater.py       # Download latest blocklists from GitHub
│   └── data/
│       └── blocklists/
│           ├── person_blocklist.txt   # Official blocklist (updated via --update)
│           └── custom_blocklist.txt   # Package-level custom blocklist
├── setup.sh             # One-command setup
├── run.sh               # One-command run
└── requirements.txt     # Python dependencies
```

## License

MIT
