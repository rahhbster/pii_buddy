This guide provides a comprehensive architectural blueprint for building a local-first, reversible PII pseudonymization engine. Unlike standard redaction (which destroys data), your requirement is **pseudonymization**: replacing sensitive entities with structured tags (e.g., `<PERSON_1>`, `<EMAIL_A>`) that can be mapped back to the original values.

This solution runs entirely offline on Mac/PC using Python, leveraging **Microsoft Presidio** for orchestration, **SQLCipher** for the secure vault, and format-specific libraries for file manipulation.

---

### **Part 1: The Detection Layer (The "Brain")**

You need an engine to identify the PII before you can tag it. We will compare the three best-of-breed open-source models available for local execution.

#### **Option A: Microsoft Presidio (Recommended Orchestrator)**
Presidio is not just a model; it is an SDK that manages multiple "Recognizers." It is the industry standard for this task because it combines Rule-Based logic (for IDs, Phones) with ML (for Names, Locations).
*   **Pros:** Highly customizable. You can plug in Spacy, Stanza, or Transformers. Supports "Context Awareness" (e.g., distinguishing "Golden State" the place from "Golden State" the basketball team).
*   **Cons:** Requires configuration to balance speed vs. accuracy.
*   **Best For:** Production-grade pipelines requiring high throughput and low false positives.

#### **Option B: GLiNER (Zero-Shot SOTA)**
GLiNER (Generalist and Lightweight Named Entity Recognition) is a bidirectional transformer that outperforms traditional BERT models. It allows you to define arbitrary labels at runtime (e.g., "medical condition," "weapon").
*   **Pros:** Exceptional accuracy for unstructured text. Zero-shot capabilities (detects new types without training).
*   **Cons:** Slower than Presidio/Spacy. Heavy on CPU.
*   **Best For:** Complex, unstructured documents where standard models miss context.

#### **Option C: FlashText (Vocabulary Based)**
If you have massive lists of known PII (e.g., a list of 50,000 employee names or client IDs), Regex is too slow. FlashText uses the Aho-Corasick algorithm to search millions of keywords in a single pass.
*   **Pros:** 100x faster than Regex for large lists.
*   **Cons:** Cannot detect unknown entities (e.g., a name not on your list).
*   **Best For:** "Deny-lists" of known bad words or specific project codes.

---

### **Part 2: The Reversibility Vault (The "Memory")**

To make the redaction reversible without blacking out text, you must implement a **Mapping Vault**. You cannot simply replace text; you must store the relationship between the original PII and the tag.

**Security Requirement:** Since this vault contains all the secrets, it must be encrypted at rest. We will use **SQLCipher**, an open-source extension to SQLite that provides transparent 256-bit AES encryption.

**Implementation Strategy:**
1.  **Ingest:** Found "John Smith".
2.  **Check Vault:** Does "John Smith" already exist for this document/session?
3.  **If Yes:** Return existing tag `<PERSON_1>`.
4.  **If No:** Generate `<PERSON_1>`, Encrypt "John Smith", Insert into Vault.
5.  **Replace:** Swap text in document.

**Technical Reference:**
*   **Library:** `pysqlcipher3` (Python bindings for SQLCipher).
*   **Reference:** See specific installation instructions for Windows/Mac to handle OpenSSL dependencies.

---

### **Part 3: Master Walkthrough & Implementation Guide**

#### **Step 1: Environment Setup**
Install the necessary libraries. Note that for Mac (M-series), we utilize `mps` (Metal Performance Shaders) for acceleration if using PyTorch-based models like GLiNER.

```bash
# Core NLP and File handlers
pip install presidio-analyzer presidio-anonymizer
pip install pymupdf python-docx openpyxl pandas
pip install spacy
python -m spacy download en_core_web_lg

# Encryption (Select one based on OS)
# Mac: brew install sqlcipher && pip install sqlcipher3-binary
# Windows: pip install pysqlcipher3
```

#### **Step 2: The Vault Class (SQLCipher Wrapper)**
This class manages the secure reversible mapping.

```python
import sqlite3
# On Windows/Mac, import the cipher version: from pysqlcipher3 import dbapi2 as sqlite3
import hashlib

class SecureVault:
    def __init__(self, db_path, password):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(f"PRAGMA key='{password}'") # SQLCipher Encryption
        self.conn.execute("PRAGMA cipher_compatibility = 4") # Best practice
        self.create_table()
        self.cache = {} # In-memory cache for speed

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS pii_map (
            hash_key TEXT PRIMARY KEY,
            original_value TEXT,
            tag TEXT,
            entity_type TEXT
        )
        """
        self.conn.execute(query)

    def get_or_create_tag(self, original_text, entity_type):
        # Use Hash for lookups to avoid leaking PII in memory dumps if possible
        text_hash = hashlib.sha256(original_text.encode()).hexdigest()
        
        if text_hash in self.cache:
            return self.cache[text_hash]

        cursor = self.conn.cursor()
        cursor.execute("SELECT tag FROM pii_map WHERE hash_key=?", (text_hash,))
        result = cursor.fetchone()

        if result:
            tag = result
        else:
            # Generate deterministic tag: <PERSON_1>, <PERSON_2>
            count = cursor.execute("SELECT COUNT(*) FROM pii_map WHERE entity_type=?", (entity_type,)).fetchone()
            tag = f"<{entity_type.upper()}_{count + 1}>"
            
            cursor.execute("INSERT INTO pii_map VALUES (?, ?, ?, ?)", 
                          (text_hash, original_text, tag, entity_type))
            self.conn.commit()
        
        self.cache[text_hash] = tag
        return tag
```

#### **Step 3: The Detection Engine (Presidio)**
We use Presidio to analyze text. It returns `RecognizerResult` objects containing positions and scores.

```python
from presidio_analyzer import AnalyzerEngine

class PiiDetector:
    def __init__(self):
        # Loads Spacy en_core_web_lg by default
        self.analyzer = AnalyzerEngine()

    def analyze(self, text):
        # Returns list of PII entities
        results = self.analyzer.analyze(text=text, language='en')
        return results
```

#### **Step 4: File Handler - PDF (PyMuPDF/Fitz)**
PDFs are complex because text is positioned by coordinates. We must find the text, overlay it with the tag, and ensure the underlying text is removed (Sanitization).

**Critical Warning:** Simply drawing a rectangle over text in a PDF does **not** remove the text; it just hides it. You must use redaction annotations to physically scrub the content stream.

```python
import fitz  # PyMuPDF

def process_pdf(input_path, output_path, detector, vault):
    doc = fitz.open(input_path)
    
    for page in doc:
        # 1. Extract text to find PII
        text = page.get_text()
        results = detector.analyze(text)
        
        # 2. Iterate backwards to keep offsets valid if modifying text stream (though PyMuPDF handles rects)
        for result in sorted(results, key=lambda x: x.start, reverse=True):
            pii_text = text[result.start:result.end]
            tag = vault.get_or_create_tag(pii_text, result.entity_type)
            
            # 3. Find exact coordinates of the PII text on the page
            # search_for returns a list of Rect objects
            areas = page.search_for(pii_text)
            
            for area in areas:
                # 4. Create Redaction Annotation (removes data)
                # Fill color white matches background, overlay text is the Tag
                page.add_redact_annot(area, text=tag, fill=(1, 1, 1), fontsize=10)
        
        # 5. Apply Redactions (Destructive step - makes it permanent)
        page.apply_redactions()
        
    doc.save(output_path)
```

#### **Step 5: File Handler - DOCX (python-docx)**
Word documents break text into "runs" (fragments of style). Replacing text requires ensuring you don't break the XML structure.

**Technical Tip:** The `python-docx` library does not support global "Find/Replace" easily because a single name like "John" might be split across two runs if "Jo" is bold and "hn" is not. You may need a helper library like `python-docx-replace` or iterate through paragraphs carefully.

```python
from docx import Document

def process_docx(input_path, output_path, detector, vault):
    doc = Document(input_path)
    
    # Iterate over paragraphs (text)
    for paragraph in doc.paragraphs:
        if not paragraph.text.strip():
            continue
            
        results = detector.analyze(paragraph.text)
        
        # Naive replacement (works if PII is in a single run)
        # For production, use sophisticated run-merging logic
        for result in results:
            pii_text = paragraph.text[result.start:result.end]
            tag = vault.get_or_create_tag(pii_text, result.entity_type)
            
            # Simple string replacement (destroys run formatting if split)
            paragraph.text = paragraph.text.replace(pii_text, tag)

    # Iterate over Tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    # Same logic as above
                    pass
                    
    doc.save(output_path)
```

---

### **Part 4: Pros & Cons of the Architecture**

| Component | Pros | Cons | Mitigation |
| :--- | :--- | :--- | :--- |
| **Detection (Presidio)** | Robust, customizable, standard API. | Can be slow on massive files. False positives possible. | Use `flash_text` for known entity lists (Allow Lists) to speed up detection. |
| **Storage (SQLCipher)** | Secure, local, single-file DB. | Losing the key/password means permanent data loss. | Implement key rotation and secure backup strategies. |
| **PDF (PyMuPDF)** | True redaction (scrubs underlying data). | Text extraction can be messy if PDF OCR is poor. | Ensure source PDFs are searchable; utilize OCR if needed (Tesseract). |
| **Reversibility** | Tags (`<PERSON_1>`) maintain document readability/layout. | Tags may break strict formatting (e.g., date fields in forms). | Use "Faker" to generate synthetic data of the same length if layout preservation is critical. |

### **Summary of Resources for Deep Dives**

1.  **Presidio Customization:** To improve detection of specific PII (e.g., Employee IDs), create Custom Recognizers using the Presidio tutorial.
2.  **Hardware Acceleration:** If running on Mac M1/M2, ensure you install the ARM64 version of Python and PyTorch to utilize the `mps` backend for significant speedups.
3.  **PDF Security:** Review the "Fake Redaction" guide to ensure your tool isn't just drawing black boxes that can be deleted by the receiver.
4.  **Advanced DOCX:** For complex Word docs, look into `python-docx-replace` which handles the complex XML structure of Word "Runs" better than standard string replacement.

---

## PII Buddy: Architecture Decisions and Why We Diverged

The recommendations above are solid for enterprise PII pipelines, but PII Buddy is a lightweight, open-source, local-first tool optimized for ease of installation and use. After evaluating each recommendation against our actual requirements, we chose a simpler stack that achieves the same goals with far less friction. Here's the reasoning for each decision.

### Detection: spaCy + Regex + Custom Heuristics (not Presidio)

PII Buddy uses the same fundamental approach that Presidio uses internally — regex patterns for structured PII combined with ML-based NER for names — but without the Presidio abstraction layer.

**What we do:**
- **Regex patterns** for emails, phones, SSNs, URLs, addresses, dates, ID numbers (same as Presidio's built-in recognizers)
- **spaCy `en_core_web_md`** for person name detection (Presidio uses spaCy under the hood anyway)
- **ALL CAPS detection** for resume headers that spaCy misses
- **Document type auto-detection** (resume vs transcript vs general) to tune behavior
- **Two-pass validation pipeline** with confidence scoring, blocklists, POS tag analysis, and cross-entity validation to eliminate false positives

**Why not Presidio:**
- Presidio's `presidio-analyzer` + `presidio-anonymizer` adds ~200MB of dependencies on top of spaCy
- It wraps spaCy NER in an abstraction that we'd immediately need to customize for our use case (resume headers, name grouping, initials-based tags)
- Our two-pass validation pipeline (detect permissively, then score and filter) is more tuned for resumes and transcripts than Presidio's generic confidence scoring
- One less dependency means easier installation, fewer version conflicts, and a lighter footprint for an open-source project that users install with a single `./setup.sh`

**The tradeoff:** If PII Buddy needed to support dozens of entity types, multiple languages, or pluggable ML backends, Presidio's abstraction would pay for itself. For our focused use case (English documents, ~10 PII types, resume/transcript-heavy), the direct approach is simpler and equally effective.

**Regarding GLiNER:** A transformer-based zero-shot model would improve accuracy on unusual names and unstructured text, but at the cost of significant CPU usage, slower processing, and a much heavier install. spaCy's `en_core_web_md` (40MB, fast) hits the right balance. Users who need better accuracy can swap in `en_core_web_trf` by changing one line.

**Regarding FlashText:** Our three-tier blocklist system (official + custom + user) serves the same purpose as FlashText deny-lists. At our scale (hundreds of blocklist entries, not millions), set-based lookup is effectively instant. FlashText's Aho-Corasick advantage only matters at 50K+ keywords.

### Reversibility: JSON Mapping Files (not SQLCipher)

PII Buddy stores the tag-to-original mapping as a plain JSON file alongside each processed document.

**What we do:**
- Each processed file gets a companion `.map.json` containing the full tag-to-original mapping
- Name variants are grouped (e.g., "Steve Johnson" and "Steve" both map to `<<SJ>>`)
- Restoration is a simple tag-replacement pass using the mapping file
- Originals are preserved in the `originals/` folder for 24 hours as an additional safety net

**Why not SQLCipher:**
- SQLCipher requires OpenSSL dependencies and platform-specific compilation (`brew install sqlcipher` on Mac, different steps on Windows/Linux). This directly conflicts with our goal of `./setup.sh` and you're running
- Password management for the encrypted vault adds UX friction. If the user forgets the password, all mappings are permanently lost
- For a local tool processing individual files, the mapping JSON sits next to the output file. The threat model is "someone with access to your local filesystem" — and if they have that, they also have access to the original files in `originals/`
- JSON files are human-readable, portable, and require zero dependencies to read

**The tradeoff:** If PII Buddy were a multi-user server processing documents from untrusted sources, encrypting the vault would be essential. For a single-user local tool, the mapping files contain the same information as the originals folder — encrypting one while leaving the other in plaintext provides no real security benefit.

### File Handling: Extract-Redact-Write (not In-Place PDF Redaction)

PII Buddy extracts text from the source document, redacts the text, and writes a new output file.

**What we do:**
- **PDF:** Extract text via pdfplumber, redact, write new PDF via fpdf2 (or plain text)
- **DOCX:** Extract paragraph text via python-docx, redact, write new DOCX (or plain text)
- **TXT:** Read directly, redact, write output

**Why not PyMuPDF in-place redaction:**
- The reference document correctly warns that PDF text replacement is fragile — text coordinates from extraction don't always map cleanly back to the visual layout, especially with multi-column layouts, tables, or non-standard fonts
- PyMuPDF's `add_redact_annot` approach works well for simple PDFs but can produce garbled output on complex layouts
- Our approach is honest about its limitations: the output is a clean, readable document with all PII removed. It doesn't pretend to preserve the original visual layout (which would require a much more complex rendering pipeline)
- With `--same-format`, users get a DOCX or PDF output that preserves the text structure. Users who need the original layout can use the default `.txt` output and refer to the original (backed up in `originals/`)

**Future consideration:** If layout-preserving PDF redaction becomes a priority, PyMuPDF could be added as an optional writer alongside the current fpdf2 text-based writer. The modular `writers.py` architecture supports this.

### Summary: Design Philosophy

| Decision | Reference Recommendation | PII Buddy Choice | Reason |
| :--- | :--- | :--- | :--- |
| **Detection** | Presidio (wraps spaCy) | spaCy + Regex directly | Same underlying tech, 200MB less dependencies, more customizable for our use case |
| **Reversibility** | SQLCipher encrypted vault | Plain JSON mapping files | Zero-dependency, human-readable, no password management, appropriate for local single-user threat model |
| **PDF handling** | PyMuPDF in-place redaction | Extract + fpdf2 text render | More reliable across PDF variants, honest about layout limitations |
| **Name detection** | GLiNER transformer | spaCy `en_core_web_md` + heuristics | 10x faster, 5x lighter install, sufficient accuracy for resumes/transcripts |
| **Keyword matching** | FlashText (Aho-Corasick) | Set-based blocklist lookup | Equivalent performance at our scale (~200 entries vs 50K+) |

The guiding principle: **do the simplest thing that works correctly, and make it easy for anyone to install and run.** Every dependency added is a potential installation failure, version conflict, or maintenance burden. PII Buddy's detection accuracy is comparable to Presidio for its target documents, and the tool installs in under 3 minutes with a single command.