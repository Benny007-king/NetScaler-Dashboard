"""The pages must work in a browser that cannot reach the internet, and the time
zone must follow TZ.

    python tests/test_offline.py      # needs the app's Python packages; uses a temporary directory
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "static", "vendor")
ok_n = bad_n = 0


def check(cond, what):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what)


print("-- bundled libraries")
listed = {}
for line in open(os.path.join(VENDOR, "SHA256SUMS"), encoding="utf-8"):
    digest, name = line.split(None, 1)
    listed[name.strip()] = digest
on_disk = set()
for base, _, names in os.walk(VENDOR):
    for n in names:
        rel = os.path.relpath(os.path.join(base, n), VENDOR).replace(os.sep, "/")
        if rel != "SHA256SUMS":
            on_disk.add(rel)
check(on_disk == set(listed), "SHA256SUMS lists exactly the files in static/vendor"
      + ("" if on_disk == set(listed) else " (differs: %s)" % sorted(on_disk ^ set(listed))))
wrong = [n for n in sorted(on_disk & set(listed))
         if hashlib.sha256(open(os.path.join(VENDOR, n), "rb").read()).hexdigest() != listed[n]]
check(not wrong, "every bundled file matches its checksum" + ("" if not wrong else " (changed: %s)" % wrong))

print("-- the pages")
os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", TZ="Europe/London")
sys.path.insert(0, ROOT)
import app as dash   # noqa: E402

c = dash.app.test_client()
EXTERNAL = re.compile(r"""<(?:script|link|img|iframe|source)\b[^>]*?\b(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", re.I)
LOCAL = re.compile(r"""\b(?:src|href)\s*=\s*["'](/static/[^"'?#]+)""")
login = c.get("/login")
html = {"login": login.get_data(as_text=True)}
with c.session_transaction() as s:
    s["logged_in"] = True; s["username"] = "admin"; s["must_change_password"] = False
dashboard = c.get("/")
html["dashboard"] = dashboard.get_data(as_text=True)
check(login.status_code == 200 and dashboard.status_code == 200, "the login page and the dashboard render")
for name in ("change_password.html",):
    html[name] = open(os.path.join(ROOT, "templates", name), encoding="utf-8").read()
for name, text in html.items():
    hits = EXTERNAL.findall(text)
    check(not hits, "%s loads nothing from another host" % name)
    check(not re.search(r"@import\s+(?:url\()?\s*[\"']?(?:https?:)?//", text), "%s imports no outside stylesheet" % name)
refs = sorted({m for text in html.values() for m in LOCAL.findall(text)})
check(len(refs) >= 7, "the pages reference the bundled files (%d)" % len(refs))
missing = [r for r in refs if c.get(r).status_code != 200]
check(not missing, "every referenced static file is served" + ("" if not missing else " (missing: %s)" % missing))
css = open(os.path.join(VENDOR, "fonts.css"), encoding="utf-8").read()
fonts = re.findall(r"url\(([^)]+)\)", css)
check(fonts and all(os.path.isfile(os.path.join(VENDOR, f)) for f in fonts) and "//" not in css.split("*/", 1)[1],
      "fonts.css points only at font files that are bundled")

csp = dashboard.headers.get("Content-Security-Policy", "")
check("http" not in csp, "the content security policy allows no other host")
r = c.get("/static/vendor/chart-4.5.1.umd.js")
check("immutable" in r.headers.get("Cache-Control", ""), "bundled files are cached by the browser")
check("immutable" not in dashboard.headers.get("Cache-Control", ""), "...and the pages are not")

print("-- time zone")
check(dash.APP_TZ_NAME == "Europe/London" and str(dash.APP_TZ) == "Europe/London", "TZ sets the dashboard's time zone")
check('const APP_TZ = "Europe/London";' in html["dashboard"], "the page shows times in that zone")


def in_child(tz):
    env = dict(os.environ, DATA_DIR=tempfile.mkdtemp(), APP_SSL="0")
    env.pop("TZ", None)
    if tz is not None:
        env["TZ"] = tz
    out = subprocess.run([sys.executable, "-c",
                          "import sys; sys.path.insert(0, %r); import app; print('ZONE=' + app.APP_TZ_NAME)" % ROOT],
                         env=env, capture_output=True, text=True, timeout=120)
    m = re.search(r"ZONE=(\S+)", out.stdout)
    return m.group(1) if m else "start failed: " + (out.stderr or out.stdout)[-300:]


check(in_child(None) == "Asia/Jerusalem", "without TZ it stays Asia/Jerusalem")
got = in_child("Not/A_Zone")
check(got == "Asia/Jerusalem", "an unknown TZ does not stop the start (%s)" % got)
got = in_child("America/New_York")
check(got == "America/New_York", "another zone is taken as given (%s)" % got)

print("\npassed %d, failed %d" % (ok_n, bad_n))
sys.exit(1 if bad_n else 0)
