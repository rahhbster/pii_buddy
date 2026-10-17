"""Deterministic synthetic documents (fake data only) for the latency-guard tests."""
import base64
import json
import random
import uuid

R = random.Random(7)
WORDS = ("the quick brown fox jumps over a lazy dog while several tired engineers review quarterly numbers and "
         "argue about nothing important today because the committee postponed everything again").split()


def prose(n, rng=None):
    rng = rng or R
    out, size = [], 0
    while size < n:
        s = " ".join(rng.choice(WORDS) for _ in range(rng.randint(6, 18))).capitalize() + rng.choice([". ", ". ", "! ", "? ", "; "])
        out.append(s)
        size += len(s)
    return "".join(out)[:n]


def resume(n):
    block = ("Alex Sample\n12 Example Street, Testville, TS 00000\nalex.sample@example.test | (555) 010-0142 | linkedin.com/in/alexsample\n"
             "EXPERIENCE\nSenior Engineer, Widget Corp, Jan 2010 - Mar 2020\n"
             + "- Led a team of five engineers shipping the billing platform (+35% revenue, -20% latency).\n" * 6
             + "EDUCATION\nB.S. Computer Science, Example University, 2003\nSKILLS: Python, C++, C#, SQL; Kubernetes/Docker\n\n")
    return (block * (n // len(block) + 1))[:n]


def csv(n):
    out, size, i = ["id,first,last,email,phone,date,amount\n"], 0, 0
    while size < n:
        i += 1
        row = f"{i},Alex,Sample,alex{i}@example.test,555-010-{i % 9000 + 1000},2024-01-{i % 28 + 1:02d},{i}.50\n"
        out.append(row); size += len(row)
    return "".join(out)[:n]


def legal(n):
    cl = ("1.1 \"Agreement\" means this agreement, including Schedule A (the \"Schedule\"); (a) the Parties shall, pursuant to Section 4(b)(ii), "
          "indemnify and hold harmless...; (b) notwithstanding the foregoing, neither Party is liable for consequential damages; "
          "see also Exhibit B-2 at p. 14 \u00b6 3 [sic]. ")
    return (cl * (n // len(cl) + 1))[:n]


def source_code(n):
    fn = ('def compute_total(items, *, tax_rate=0.07):\n    """Return the sum."""\n    total = 0\n    for it in items:\n'
          '        if it["qty"] > 0 and it.get("price") is not None:\n            total += it["qty"] * it["price"]  # (qty * price)\n'
          '    return round(total * (1 + tax_rate), 2)\n\nclass Foo(Bar):\n    x = {"a": [1, 2, 3], "b": (4, 5)}\n    def __init__(self): self.y = lambda z: z**2 + 1\n\n')
    return (fn * (n // len(fn) + 1))[:n]


def js_code(n):
    fn = ('const f = (a, b) => { return a.map(x => `${x}:${b}`).filter(Boolean).join(","); };\nconst re = /^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)@example\\.test$/i;\n'
          'fetch("https://api.example.test/v1/items?id=42&sort=asc").then(r => r.json()).catch(console.error);\n')
    return (fn * (n // len(fn) + 1))[:n]


def email_thread(n):
    msg = ("On Mon, Jan 5, 2026 at 10:15 AM Sam Example <sam@example.test> wrote:\n> Thanks for the update.\n>> Can we move the call to Thursday?\n"
           ">>> Original message follows >>>\n> > > nested quoting > > >\nBest,\nAlex\n\n")
    return (msg * (n // len(msg) + 1))[:n]


def logs(n):
    rng = random.Random(3)
    out, size = [], 0
    while size < n:
        line = (f"2026-01-05T10:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}Z INFO req={uuid.UUID(int=rng.getrandbits(128))} "
                f"hash={rng.getrandbits(256):064x} url=https://svc.example.test/api/v1/items/{rng.getrandbits(40):x}?a=1&b=2 status=200\n")
        out.append(line); size += len(line)
    return "".join(out)[:n]


def md_table(n):
    row = "| Name | Role | Start | Salary |\n|------|:----:|------:|-------:|\n| Alex | Eng | 2020-01-01 | $120,000 |\n| Sam | PM | 2019-05-01 | $130,000 |\n"
    return (row * (n // len(row) + 1))[:n]


def b64(n):
    rng = random.Random(n)
    return base64.b64encode(bytes(rng.getrandbits(8) for _ in range(n)))[:n].decode()


def b64_wrapped(n):
    s = b64(n)
    return "\n".join(s[i:i + 76] for i in range(0, len(s), 76))


def url_list(n, per=300):
    rng = random.Random(11)
    out, size = [], 0
    while size < n:
        u = "https://www.example.test/path/" + "/".join(f"seg{rng.getrandbits(20):x}" for _ in range(per // 14)) + "?q=" + "&".join(f"k{i}=v{rng.getrandbits(12)}" for i in range(5))
        out.append(u); size += len(u) + 1
    return "\n".join(out)[:n]


def link_heavy(n, urlchars=300):
    rng = random.Random(5)
    out, size = [], 0
    while size < n:
        u = "https://cdn.example.test/a/" + "".join(rng.choice("abcdef0123456789-_/") for _ in range(urlchars)) + ".html"
        s = prose(120, rng) + " " + u + " "
        out.append(s); size += len(s)
    return "".join(out)[:n]


def cjk(n, kind):
    rng = random.Random(kind)
    if kind == "zh":
        chars = [chr(c) for c in range(0x4E00, 0x4E00 + 3000)]; punct = "\uff0c\u3002\u3001\uff1b\uff1a\uff1f\uff01\u201c\u201d\uff08\uff09\u300a\u300b"
    elif kind == "ja":
        chars = [chr(c) for c in range(0x3041, 0x3096)] + [chr(c) for c in range(0x4E00, 0x4E00 + 800)]; punct = "\u3001\u3002\u300c\u300d\uff08\uff09\uff01\uff1f\u30fb"
    elif kind == "ko":
        chars = [chr(c) for c in range(0xAC00, 0xAC00 + 2000)]; punct = ".,!?"
    elif kind == "ar":
        chars = [chr(c) for c in range(0x0621, 0x063B)] + [chr(c) for c in range(0x0641, 0x064B)]; punct = "\u060c\u061b\u061f."
    else:
        chars = [chr(c) for c in range(0x0915, 0x0939)] + ["\u093e", "\u093f", "\u0940", "\u0941", "\u0947", "\u094b"]; punct = "\u0964,?!"
    spaced = kind in ("ko", "ar", "hi")
    out, size = [], 0
    while size < n:
        sent = "".join(rng.choice(chars) for _ in range(rng.randint(5, 30))) + rng.choice(punct)
        if spaced:
            sent = " ".join(sent[i:i + rng.randint(2, 6)] for i in range(0, len(sent), 4)) + " "
        out.append(sent); size += len(sent)
    return "".join(out)[:n]


def json_min(n):
    rng = random.Random(9)
    items, size = [], 2
    while size < n:
        it = {"id": rng.getrandbits(32), "name": "Alex", "tags": ["a", "b"], "ok": True, "v": rng.random(), "nested": {"k": [1, 2, 3], "s": "text, with: punct"}}
        s = json.dumps(it, separators=(",", ":"))
        items.append(s); size += len(s) + 1
    return ("[" + ",".join(items) + "]")[:n]


def json_pretty(n):
    return json.dumps([{"id": i, "name": "Alex", "tags": ["a", "b"]} for i in range(n // 60)], indent=2)[:n]


def html(n):
    row = '<div class="row"><a href="https://www.example.test/x?y=1&amp;z=2">link</a><p>Some <b>bold</b> text.</p></div>\n'
    return (row * (n // len(row) + 1))[:n]


def hexdump(n):
    rng = random.Random(2)
    return "\n".join(" ".join(f"{rng.getrandbits(8):02x}" for _ in range(16)) for _ in range(n // 48))[:n]


def realistic():
    d = {}
    for n in (20_000, 50_000):
        d[f"prose_{n}"] = prose(n)
        d[f"resume_{n}"] = resume(n)
        d[f"csv_{n}"] = csv(n)
        d[f"legal_{n}"] = legal(n)
        d[f"code_py_{min(n, 40_000)}"] = source_code(min(n, 40_000))
        d[f"code_js_{n}"] = js_code(n)
        d[f"email_{n}"] = email_thread(n)
        d[f"logs_{n}"] = logs(n)
        d[f"mdtable_{n}"] = md_table(n)
        d[f"html_{n}"] = html(n)
        d[f"jsonpretty_{min(n, 30_000)}"] = json_pretty(min(n, 30_000))
        d[f"hexdump_{min(n, 30_000)}"] = hexdump(min(n, 30_000))
    for n in (2000, 5000, 8000, 11_000, 20_000, 40_000, 50_000):
        d[f"b64_{n}"] = b64(n)
    d["b64wrapped_30000"] = b64_wrapped(30_000)
    d["b64_in_text"] = prose(1000) + " " + b64(11_000) + " " + prose(1000)
    d["urllist_30000"] = url_list(30_000)
    d["urllist_50000_per150"] = url_list(50_000, 150)
    d["linkheavy_30000_300"] = link_heavy(30_000, 270)
    d["linkheavy_50000_330"] = link_heavy(50_000, 330)
    for k in ("zh", "ja", "ko", "ar", "hi"):
        d[f"{k}_prose_30000"] = cjk(30_000, k)
    for n in (2000, 5000, 30_000):
        d[f"zh_para_{n}"] = cjk(n, "zh").replace(" ", "")
    d["ja_para_4000"] = cjk(4000, "ja")
    d["ja_para_30000"] = cjk(30_000, "ja")
    d["zh_para_50000"] = cjk(50_000, "zh")
    d["json_min_30000"] = json_min(30_000)
    d["json_min_50000"] = json_min(50_000)
    d["json_min_40000"] = json_min(40_000)
    d["json_nospace_20000"] = json_nospace(20_000)
    return d


def json_nospace(n):
    rng = random.Random(1)
    items, size = [], 2
    while size < n:
        it = {"id": rng.getrandbits(32), "name": "Alex", "tags": ["a", "b"], "ok": True, "v": rng.random(),
              "nested": {"k": [1, 2, 3], "s": "textwithpunct"}}
        s = json.dumps(it, separators=(",", ":"))
        items.append(s)
        size += len(s) + 1
    return ("[" + ",".join(items) + "]")[:n]
