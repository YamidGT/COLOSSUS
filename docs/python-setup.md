# Python setup, dependency provenance and offline rebuilds

The Python adapter adds automatic setup for unambiguous module-level Flask/Bottle applications and a Django `manage.py` profile. It reads source using the AST and static requirement metadata; discovery does not import applications or execute their build scripts. Only the Flask path has live owned-fixture evidence so far. DSVW remains the sole public target tested in this implementation phase.

## Build path

```text
public source -> static requirements + application recipe
                          |
                          v
                  gVisor pip builder -- internal network -- registry proxy
                          |                                  |
                          |                          fixed TLS origins only
                          |                          pypi.org / files.pythonhosted.org
                          v
              installed vendor files + inventory + pip report
                          |
                immutable runtime bundle
                          |
editable source ----------+--> COPY-only image --> isolated application
```

Only the short-lived credential-free proxy has an egress network. It serves normalized package-index paths and wheel/metadata file paths, validates the remote TLS hostname, and never offers CONNECT tunneling, arbitrary URL forwarding or redirects. The launcher resolves only the two fixed registry names and rejects private/non-global addresses. On the current gVisor host, Docker's embedded loopback DNS is unavailable; using those resolved addresses preserves TLS origin checking. Both proxy networks must be attached before startup.

Pip runs inside gVisor with isolated configuration, a single local index, binary-only resolution, no cache and no bytecode compilation. Direct URL/VCS/local root requirements and pip configuration flags are rejected. Requirements include files must stay inside the source layout; dynamic pyproject dependency metadata needs another build profile. Downloaded wheel origins and hashes are checked in the installer report, and installed distributions must agree with that report. Unsupported source-only distributions, incompatible wheels and inconsistent metadata stop setup rather than falling back to host execution.

Limits: 100 direct/installed packages, 32 MiB per registry file, 200 MiB transferred per proxy, 512 proxy requests, eight concurrent proxy connections, 100 MiB exported result, two CPU and 2 GiB for the builder. The proxy uses 512 MiB. The existing overall onboarding deadline also applies. The proxy, builder and their networks are removed on success/failure; teardown refuses foreign resources and treats already-removed owned resources idempotently.

The implementation follows the primary [pip installation documentation](https://pip.pypa.io/en/stable/cli/pip_install/) and [wheel format specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/). This is a restricted registry/build profile, not a general network proxy or a replacement dependency resolver.

## Runtime and evidence

`source.files` remains the editable repository snapshot. `source.runtime_files` contains the locked installed dependencies and controller-owned startup helper, with a separate tree hash. Patchers do not see or edit that bundle. Packaging binds the combined source/runtime tree; ordinary source repairs reuse the same dependency bytes offline. Dependency-update proposals must deliberately produce a new locked bundle and re-run gates; that route remains separate implementation work.

The Flask/Bottle helper starts from an immutable image, copies application source into bounded disposable scratch for local database/state initialization, and imports dependencies from the image's protected `vendor/` directory. Flask script profiles force an internal bind address and disable the debugger/reloader; this setup transformation is recorded in the recipe. WSGI profiles import the declared module-level application. Django has an implementation for migrations plus a local development server, but has not been live-calibrated here. External databases/caches and missing settings are not silently mocked. Application startup data is not assumed to be a deterministic seed unless the profile establishes it.

A recipe in `colossus-app.json` can declare a Python entrypoint/readiness probe under `declared-python-v1`. It cannot claim the DSVW security profile or select its own proof authority. Ambiguous apps require a chosen subdirectory or explicit recipe. Readiness means an expected HTTP response, not functional correctness or security.

After setup, generic Python projects can execute recurring discovery and bounded probes. Without an approved protected repair oracle, the cycle records `NO_CHANGE` with explicit `repair=UNSUPPORTED` and `formal=UNSUPPORTED`; findings remain visible. It does not fabricate a successful repair/promotion. Full generic repair, application-specific protected workflows, additional service/language adapters and automatic recipe revision remain outstanding.

## Observed checks

```sh
uv run python scripts/check_registry_boundary.py
uv run python scripts/check_python_setup.py
uv run python scripts/check_operator_api.py
```

The first checks real proxy allowlisting and direct IPv4/IPv6/metadata denial. The second uses owned fixture source in place of GitHub intake, with real launcher RPC, pip installation, packaging, startup and a T0 investigation. It runs no additional public repository and makes no model call. The third uses actual pinned DSVW GitHub intake and the real operator API/worker. Their reports are retained under `artifacts/bootstrap`; see [implementation status](implementation-status.md) for measured results. These are integration checks, not repository-campaign or public-benchmark scores.
