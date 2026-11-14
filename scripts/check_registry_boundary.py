"""Check live registry allowlisting and builder isolation without another target repo."""

import json
from importlib.resources import files
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.sandbox.dependency_builder import registry_origins
from colossus.sandbox.launcher import LABEL, SandboxLauncher


def main():
    launcher = SandboxLauncher()
    project_id = new_id()
    private = launcher.network(project_id)
    egress = "colossus-egress-" + new_id()
    proxy = worker = None
    created_egress = False
    try:
        launcher.checked(
            "network",
            "create",
            "--label",
            LABEL + "=true",
            "--label",
            "org.colossus.project=" + project_id,
            egress,
        )
        created_egress = True
        artifact = launcher.package(
            {
                "registry_proxy.py": files("colossus.sandbox")
                .joinpath("registry_proxy.py")
                .read_bytes(),
                "origins.json": json.dumps(registry_origins()).encode(),
            },
            ["python", "-I", "/app/registry_proxy.py"],
        )
        proxy = launcher.create(
            project_id,
            "registry",
            private,
            memory_mb=512,
            image=artifact["artifact_digest"],
            application=True,
            start=False,
        )
        launcher.checked("network", "connect", egress, proxy)
        launcher.checked("start", proxy)
        address = launcher.inspect(proxy)["NetworkSettings"]["Networks"][private]["IPAddress"]
        worker = launcher.create(project_id, "build", private)
        script = """import http.client,json,os,socket,sys
address=sys.argv[1]
result={'http':{},'direct_connections':{},'provider_keys_present':any(k.endswith('API_KEY') for k in os.environ)}
for method,path in [('GET','/health'),('GET','/simple/flask/'),('GET','https://example.com/'),('GET','/files/../../metadata'),('GET','/simple/flask/?host=evil'),('CONNECT','169.254.169.254:80')]:
 c=http.client.HTTPConnection(address,8080,timeout=20);c.request(method,path);r=c.getresponse();r.read();result['http'][method+' '+path]=r.status;c.close()
for address,port in [('1.1.1.1',443),('169.254.169.254',80),('2606:4700:4700::1111',443)]:
 try:
  c=socket.create_connection((address,port),timeout=.5);c.close();result['direct_connections'][address]='connected'
 except OSError:result['direct_connections'][address]='denied'
print(json.dumps(result))
"""
        outcome = launcher.execute(
            worker, ["python", "-I", "-c", script, address], 90, workdir="/work"
        )
        assert outcome.exit_code == 0 and not outcome.timed_out, outcome
        report = json.loads(outcome.stdout)
        assert report["http"]["GET /health"] == report["http"]["GET /simple/flask/"] == 200
        assert all(
            status in {403, 501}
            for path, status in report["http"].items()
            if path not in {"GET /health", "GET /simple/flask/"}
        )
        assert all(value == "denied" for value in report["direct_connections"].values())
        assert not report["provider_keys_present"]
        report |= {
            "target_repositories_run": [],
            "model_calls": 0,
            "proxy_artifact": artifact,
            "runtime": "runsc",
        }
        Path("artifacts/bootstrap/registry-boundary.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps(report, indent=2))
    finally:
        for environment in (worker, proxy):
            if environment:
                launcher.destroy(environment)
        launcher.destroy_network(private, project_id)
        if created_egress:
            launcher.destroy_network(egress, project_id)


if __name__ == "__main__":
    main()
