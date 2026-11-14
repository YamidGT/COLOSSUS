"""Run actual isolation checks against the dedicated, pinned gVisor worker."""

import json
from dataclasses import asdict
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.sandbox.launcher import SandboxLauncher

launcher = SandboxLauncher()
preflight = launcher.preflight()
assert preflight["ready"], preflight
program = """import json, os, socket
s=socket.socket(); s.settimeout(1)
r={"uid":os.getuid(),"gvisor":"gvisor" in open("/proc/version").read(),
"external_denied":s.connect_ex(("1.1.1.1",443))!=0,
"host_home_absent":not os.path.exists("/Users/danieldiaz"),
"docker_socket_absent":not os.path.exists("/var/run/docker.sock"),
"provider_keys_absent":not any(k in os.environ for k in ("MISTRAL_API_KEY","GROQ_API_KEY"))}
try:
 open("/etc/colossus-probe","w").write("x")
 r["root_readonly"]=False
except OSError:
 r["root_readonly"]=True
print(json.dumps(r))
"""
result = launcher.run(
    new_id(), "verify", {"isolation.py": program.encode()}, ["python", "isolation.py"]
)
assert result.exit_code == 0, asdict(result)
checks = json.loads(result.stdout)
assert checks["uid"] == 1000 and all(value for key, value in checks.items() if key != "uid"), checks
out = Path("artifacts/bootstrap")
out.mkdir(parents=True, exist_ok=True)
(out / "sandbox-isolation.json").write_text(
    json.dumps({"preflight": preflight, "result": asdict(result), "checks": checks}, indent=2)
    + "\n"
)
print(json.dumps(checks, indent=2))
