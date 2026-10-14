"""Proof that the suite-wide guard in tests/conftest.py really blocks writes.

Runs in a subprocess with a fake HOME so nothing here can reach the owner's
real directories even if the guard were broken.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = r'''
import importlib.util, io, json, os, pathlib, plistlib, shutil, subprocess, sys
import pytest

spec = importlib.util.spec_from_file_location("guard_conftest", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mp = pytest.MonkeyPatch()
mod.install_guards(mp)

home = os.environ["HOME"]
la = os.path.join(home, "Library", "LaunchAgents")
pb = os.path.join(home, "PII_Buddy")
P = pathlib.Path
cases = {
    "builtins.open": lambda: open(la + "/a.plist", "w"),
    "io.open": lambda: io.open(la + "/a.plist", "w"),
    "Path.open": lambda: P(la + "/a.plist").open("w"),
    "Path.write_text": lambda: P(la + "/a.plist").write_text("x"),
    "Path.write_bytes": lambda: P(la + "/a.plist").write_bytes(b"x"),
    "os.open": lambda: os.open(la + "/a.plist", os.O_CREAT | os.O_WRONLY),
    "os.mkdir": lambda: os.mkdir(pb),
    "os.makedirs": lambda: os.makedirs(pb + "/x/y"),
    "Path.mkdir": lambda: P(pb).mkdir(parents=True),
    "os.chmod": lambda: os.chmod(pb, 0o777),
    "os.symlink": lambda: os.symlink("/etc/hosts", pb),
    "os.link": lambda: os.link("/etc/hosts", pb + "/l"),
    "os.truncate": lambda: os.truncate(la + "/a.plist", 0),
    "os.replace": lambda: os.replace("/nonexistent-src", la + "/a.plist"),
    "os.rename": lambda: os.rename("/nonexistent-src", la + "/a.plist"),
    "os.unlink": lambda: os.unlink(la + "/a.plist"),
    "os.remove": lambda: os.remove(la + "/a.plist"),
    "shutil.move": lambda: shutil.move("/nonexistent-src", la + "/a.plist"),
    "plistlib.dump": lambda: plistlib.dump(
        {}, type("F", (), {"name": la + "/a.plist"})()
    ),
    "os.utime": lambda: os.utime(la + "/a.plist"),
    "os.chown": lambda: os.chown(la + "/a.plist", -1, -1),
    "os.rmdir": lambda: os.rmdir(pb),
    "os.removedirs": lambda: os.removedirs(pb + "/x/y"),
    "shutil.rmtree": lambda: shutil.rmtree(pb),
    "shutil.copytree": lambda: shutil.copytree("/nonexistent-src", pb + "/c"),
    "Path.rmdir": lambda: P(pb).rmdir(),
    "subprocess.run": lambda: subprocess.run(["pbcopy"]),
    "subprocess.run(shell)": lambda: subprocess.run("echo x | pbcopy", shell=True),
    "subprocess.Popen": lambda: subprocess.Popen(["pbpaste"]),
    "subprocess.check_output": lambda: subprocess.check_output(["pbpaste"]),
    "subprocess.check_call": lambda: subprocess.check_call(["launchctl", "list"]),
    "subprocess.call": lambda: subprocess.call(["/nonexistent/bin/pbcopy"]),
    "os.system": lambda: os.system("pbcopy"),
    "os.popen": lambda: os.popen("pbpaste"),
    "os.execv": lambda: os.execv("pbcopy", ["pbcopy"]),
    "os.execvp": lambda: os.execvp("launchctl", ["launchctl"]),
    "os.execl": lambda: os.execl("pbcopy", "pbcopy"),
    "os.spawnv": lambda: os.spawnv(os.P_WAIT, "pbcopy", ["pbcopy"]),
    "os.spawnvp": lambda: os.spawnvp(os.P_WAIT, "launchctl", ["launchctl"]),
    "os.spawnl": lambda: os.spawnl(os.P_WAIT, "pbpaste", "pbpaste"),
    "subprocess.run(osascript)": lambda: subprocess.run(["osascript", "-e", "1"]),
    "subprocess.run(gh)": lambda: subprocess.run(["gh", "pr", "list"]),
    "os.system(gh)": lambda: os.system("gh auth status"),
    "subprocess.run(open)": lambda: subprocess.run(["open", "https://example.invalid"]),
    "os.system(open)": lambda: os.system("open https://example.invalid"),
    "subprocess.run(/usr/bin/open)": lambda: subprocess.run(
        ["/usr/bin/open", "https://example.invalid"]
    ),
}
# Linux-only; absent on macOS, so only exercised where they exist.
if hasattr(os, "setxattr"):
    cases["os.setxattr"] = lambda: os.setxattr(la + "/a.plist", "user.x", b"1")
    cases["os.removexattr"] = lambda: os.removexattr(la + "/a.plist", "user.x")
out = {}
for name, fn in cases.items():
    try:
        fn()
        out[name] = "NOT BLOCKED"
    except BaseException as e:
        out[name] = "blocked" if type(e).__name__ == "Failed" else "other:" + type(e).__name__
print(json.dumps(out))
'''

EXPECTED = [
    "builtins.open", "io.open", "Path.open", "Path.write_text",
    "Path.write_bytes", "os.open", "os.mkdir", "os.makedirs", "Path.mkdir",
    "os.chmod", "os.symlink", "os.link", "os.truncate", "os.replace",
    "os.rename", "os.unlink", "os.remove", "shutil.move", "plistlib.dump",
    "os.utime", "os.chown", "os.rmdir", "os.removedirs", "shutil.rmtree",
    "shutil.copytree", "Path.rmdir", "subprocess.run", "subprocess.run(shell)",
    "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "subprocess.call", "os.system", "os.popen", "os.execv", "os.execvp",
    "os.execl", "os.spawnv", "os.spawnvp", "os.spawnl",
    "subprocess.run(osascript)", "subprocess.run(gh)", "os.system(gh)",
    "subprocess.run(open)", "os.system(open)", "subprocess.run(/usr/bin/open)",
]


@pytest.fixture(scope="module")
def result():
    with tempfile.TemporaryDirectory(prefix="pii_buddy_meta_") as td:
        fake_home = Path(td) / "home"
        fake_home.mkdir()
        env = {
            "HOME": str(fake_home),
            "PII_BUDDY_DIR": str(Path(td) / "base" / "PII_Buddy"),
            # No pbcopy/pbpaste/launchctl/osascript/gh on PATH: if a guard ever fails, the
            # call dies with FileNotFoundError instead of touching the clipboard.
            "PATH": str(Path(td) / "emptybin"),
            "PYTHONPATH": str(ROOT),
        }
        proc = subprocess.run(
            [sys.executable, "-c", SCRIPT, str(ROOT / "tests" / "conftest.py")],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        data["_home_after"] = sorted(
            str(p.relative_to(fake_home)) for p in fake_home.rglob("*")
        )
        return data


@pytest.mark.parametrize("call", EXPECTED)
def test_guarded_call_raises_on_protected_path(result, call):
    assert result[call] == "blocked"


def test_nothing_was_created_under_fake_home(result):
    assert result["_home_after"] == []
