"""Trusted lab startup: immutable image inputs, disposable application data."""

import importlib
import os
import runpy
import shutil
import subprocess
import sys
from wsgiref.simple_server import make_server

mode, entry, symbol = sys.argv[1:]
shutil.copytree(
    "/app", "/work/application", ignore=shutil.ignore_patterns("vendor", "_colossus_runtime")
)
os.chdir("/work/application")
sys.path[:0] = ["/work/application", "/app/vendor"]
os.environ["PYTHONPATH"] = "/app/vendor"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

if mode == "flask-script":
    import flask

    original = flask.Flask.run

    def run(self, *args, **kwargs):
        return original(
            self,
            host="0.0.0.0",
            port=5000,
            debug=False,
            use_reloader=False,
            use_debugger=False,
            threaded=False,
        )

    flask.Flask.run = run
    sys.argv = [entry]
    runpy.run_path(entry, run_name="__main__")
elif mode == "bottle-script":
    import bottle

    original = bottle.run

    def run(app=None, *args, **kwargs):
        return original(
            app=app,
            host="0.0.0.0",
            port=5000,
            server="wsgiref",
            quiet=True,
            reloader=False,
            debug=False,
        )

    bottle.run = run
    sys.argv = [entry]
    runpy.run_path(entry, run_name="__main__")
elif mode == "wsgi":
    module = importlib.import_module(entry.removesuffix(".py").replace("/", "."))
    application = getattr(module, symbol)
    make_server("0.0.0.0", 5000, application).serve_forever()
elif mode == "django":
    subprocess.run([sys.executable, entry, "migrate", "--noinput"], check=True, timeout=120)
    sys.argv = [entry, "runserver", "0.0.0.0:8000", "--noreload"]
    runpy.run_path(entry, run_name="__main__")
else:
    raise SystemExit("Unsupported runtime profile")
