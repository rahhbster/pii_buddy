# PII Buddy

A lightweight utility that watches a folder on your computer and automatically redacts Personally Identifiable Information (PII) from documents. Drop a file in, get a clean file out.

Built for processing resumes, transcripts, and other documents where PII needs to be stripped before sharing or review.

## What It Redacts

| PII Type | Example Input | Replacement |
|---|---|---|
| **Names** | Steve Johnson | `<<SJ>>` |
| **First-name references** | Steve | `<<SJ>>` (linked to full name) |
| **Email addresses** | steve@gmail.com | `<<EMAIL_1>>` |
| **Phone numbers** | (555) 867-5309 | `<<PHONE_1>>` |
| **Social Security Numbers** | 123-45-6789 | `<<SSN_1>>` |
| **URLs / LinkedIn** | linkedin.com/in/steve | `<<URL_1>>` |
| **Street addresses** | 123 Oak St, Apt 4B | `<<ADDRESS_1>>` |
| **Dates of birth** | 03/15/1988 | `<<DOB_1>>` |
| **ID numbers** (DL, passport) | D1234567 | `<<ID_NUMBER_1>>` |

City, state, and country are preserved. Date ranges and relative dates (e.g., "January 2020 - Present", "10+ years") are left intact.

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

# Run setup (creates virtual environment, installs dependencies, downloads NLP model)
./setup.sh
```

Setup takes about 1-2 minutes. It will:
1. Find a suitable Python 3.9+ on your system
2. Create an isolated virtual environment in `.venv/`
3. Install dependencies (spaCy, watchdog, pdfplumber, python-docx)
4. Download the spaCy English language model (~12MB)
5. Create the working folder structure at `~/PII_Buddy/`

## Folder Structure

After setup, a `PII_Buddy` folder is created in your home directory:

```
~/PII_Buddy/
├── input/      # Drop files here to be processed
├── output/     # Redacted files appear here (PII_FREE_*.txt)
├── mappings/   # JSON mapping files for reversibility
├── originals/  # Originals are moved here after processing
└── logs/       # Processing logs
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

12:16:12  Processing: resume_john_doe.pdf
12:16:13    Found 14 PII entities
12:16:13    Output: PII_FREE_resume_john_doe.txt
12:16:13    Mapping: resume_john_doe.map.json
12:16:13    Original moved to: originals/resume_john_doe.pdf
```

Press `Ctrl+C` to stop watching.

### Single File Mode

Process one file and exit:

```bash
./run.sh --once /path/to/document.pdf
```

### Restore PII

Re-insert PII into a redacted file using its mapping:

```bash
./run.sh --restore ~/PII_Buddy/output/PII_FREE_resume.txt ~/PII_Buddy/mappings/resume.map.json
```

This creates a `RESTORED_resume.txt` file in the output folder.

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

1. **File detection** — `watchdog` monitors the input folder for new files
2. **Text extraction** — `pdfplumber` (PDF) or `python-docx` (Word) extracts raw text
3. **PII detection** — Two-pass approach:
   - **Regex patterns** catch structured PII: emails, phone numbers, SSNs, URLs, dates, ID numbers, street addresses
   - **spaCy NER** catches names and contextual dates that regex misses
   - Regex matches take priority when they overlap with spaCy entities
4. **Redaction** — Each PII item is replaced with a tagged placeholder. Names become initials-based tags; other types get numbered sequential tags
5. **Mapping** — A JSON file records every tag-to-original-value pair for later restoration
6. **Cleanup** — Originals are moved to the `originals/` folder and automatically deleted after 24 hours

## Example

**Input** (`resume.txt`):
```
Steve Johnson
Senior Software Engineer
steve.johnson@gmail.com | (555) 867-5309

123 Oak Street, Apt 4B
Denver, CO 80202

Reported to Mary Jackson, VP of Engineering
```

**Output** (`PII_FREE_resume.txt`):
```
<<SJ>>
Senior Software Engineer
<<EMAIL_1>> | <<PHONE_1>>

<<ADDRESS_1>>
Denver, CO 80202

Reported to <<MJ>>, VP of Engineering
```

**Mapping** (`resume.map.json`):
```json
{
  "tags": {
    "<<SJ>>": "Steve Johnson",
    "<<MJ>>": "Mary Jackson",
    "<<EMAIL_1>>": "steve.johnson@gmail.com",
    "<<PHONE_1>>": "(555) 867-5309",
    "<<ADDRESS_1>>": "123 Oak Street, Apt 4B"
  },
  "persons": {
    "Steve Johnson": "<<SJ>>",
    "Mary Jackson": "<<MJ>>",
    "Steve": "<<SJ>>"
  }
}
```

## Troubleshooting

**`setup.sh` fails with Python version error**
You need Python 3.9+. On macOS: `brew install python@3.12`

**spaCy model download fails**
Run manually: `.venv/bin/python -m spacy download en_core_web_sm`

**Files not being detected in watch mode**
Make sure the file extension is `.pdf`, `.docx`, or `.txt`. Other formats are skipped.

**Names not being detected**
spaCy's small model (`en_core_web_sm`) works well for common English names but may miss unusual ones. For better accuracy, you can upgrade to the medium model:
```bash
.venv/bin/python -m spacy download en_core_web_md
```
Then edit `pii_buddy/detector.py` and change `en_core_web_sm` to `en_core_web_md`.

## License

MIT
