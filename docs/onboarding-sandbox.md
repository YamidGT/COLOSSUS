# Repository onboarding and isolated execution

Owners: B for onboarding, A for launcher/security boundary. Inputs/outputs follow contracts.md; deadlines follow runtime.md. A public URL is enough to begin; success depends on available configuration and supported runtime. No source execution is permitted in the control plane.

## Source intake

Accept HTTPS GitHub repository URLs, normalize owner/repo and optional ref/subdirectory; reject credentials in URL and arbitrary schemes/hosts. Gateway resolves an immutable commit, retrieves an archive or quarantined clone and verifies extraction boundaries. Submodules/LFS are disabled until separately resolved against allowed source hosts and size limits. Initial limits: 200 MiB downloaded source, 1 GiB expanded tree, 100,000 files; explicit profile override required for larger projects. Reject archive traversal, device nodes and escaping symlinks. Keep licenses/provenance.

For blind repair evaluation, expose only the selected source snapshot, no `.git`, future commits, solution files or fixed-version references. The evaluator retains those separately. Operational upstream-update mode can obtain upstream fixes through the gateway; label it distinctly from synthesized repair.

## Discovery and recipe planning

Inspect package/build manifests, Dockerfiles, Compose, CI workflows, examples and README as untrusted text. Identify app root, language/runtime, architecture, services, internal ports, storage, configuration, test commands and migrations. A monorepo with multiple plausible apps yields NEEDS_CONFIGURATION unless deterministic selection or provided subdir resolves it.

Select: validated repo recipe -> pinned trusted buildpack/template -> model-generated recipe. [Buildpacks detection](https://buildpacks.io/docs/for-platform-operators/concepts/lifecycle/detect/) is reusable for supported stacks. A Dockerfile's existence does not prove that it builds from source; prebuilt-image-only recipes do not satisfy source-repair validation. Setup modifications are recorded independently from repair diffs.

The recipe validator prohibits privileged/host network/PID/IPC modes, runtime sockets, arbitrary host mounts, device access, extra capabilities and mutable base-image tags at execution. It constrains service count and total resources. Build commands may be arbitrary project code **inside** the isolated builder; a command allowlist is not a substitute for that boundary. Preserve network restrictions even if setup instructions request disabling them.

## Build and dependency access

Run on a dedicated lab Linux host. Selected isolation profile: rootless Docker plus validated gVisor runtime for untrusted repository jobs, with nonroot users, all capabilities dropped, no-new-privileges, default-deny network, read-only root and bounded scratch. Preflight actual host/kernel/architecture and tool compatibility. If this combination cannot run a target, use a separately configured disposable VM worker or mark UNSUPPORTED; do not silently fall back to ordinary host execution. Container isolation reduces risk, not a proof against escape. [gVisor installation](https://gvisor.dev/docs/user_guide/install/), [rootless Docker](https://docs.docker.com/engine/security/rootless/).

Dependency preparation is a separate builder phase with a controlled registry proxy. Only enrolled package registries and predeclared sources are reachable. No cloud metadata, controller IPs, loopback services, arbitrary DNS tunnel or target-selected origins. No model or deployment secret enters this environment. Download/package-install hooks still execute as untrusted code inside isolation. Cache dependencies and record lock/resolution hashes; subsequent candidate builds use the same locked inputs offline, except for explicitly proposed dependency updates which create a new manifest revision.

For supported stack templates, use a pinned builder image: run repository build commands in the isolated worker, export bounded build outputs, then assemble the runtime image with a controller-owned COPY-only packaging recipe using a trusted base without ONBUILD hooks. Packaging executes no repository code. Dynamic application dependencies must be included in the manifest/output, not downloaded at startup. A general Dockerfile requiring privileged build features or unsupported system setup uses the separately validated disposable-VM build backend or returns UNSUPPORTED. Never execute an arbitrary repo Dockerfile with the host daemon merely because runtime containers use runsc.

Use base-image and worker-tool images by digest/platform. Record toolchains. Never expose raw BuildKit/Docker sockets inside a repository job. A fixed build executor mediates image creation outside untrusted namespaces; backend selection must demonstrate its isolation in preflight. If the host cannot safely build untrusted recipes, setup is blocked for that profile.

## Startup and readiness

Generate an internal network per case. Start required DB/cache services with generated synthetic credentials and per-case volumes. Apply migrations only to disposable data. Route tests to fixed service IDs; no public listening ports. Inspect image configuration/startup logs to establish ports and health, then run a positive request/test. A running process alone is not readiness.

For unavailable SaaS dependencies, record NEEDS_CONFIGURATION or use an explicit mock profile. A mock never counts as real third-party integration. Libraries use build/test-harness jobs and a consumer harness for deployment validation; do not invent a web server. All generated data and configuration get hashes and seeds.

Publish TargetManifest only after baseline readiness and baseline functional tests have a recorded outcome. Existing test failures can be recorded as known failures with fixed identity; do not silently suppress newly failing tests. Return READY, NEEDS_CONFIGURATION, UNSUPPORTED or SETUP_FAILED.

## Investigation and candidate environments

Baseline and candidate are separate copies/volumes from pristine inputs. A probe worker shares the target network; controller/gateway do not. Resolve service ID to pinned case IP/port, disable redirects, limit HTTP methods/body sizes/rate and count requests. Fuzzers run in a profile-specific offline harness with CPU/time limits. Networked web scans and memory-crash library cases are separate profiles.

Model-generated tests are supplemental; protected reference tests and proof definitions are read-only. Collect only regular files under designated output roots with a size cap. Destroy worker before importing results; validate hashes and ownership. Logs/HTML are escaped in the UI; no generated JavaScript executes in the operator interface.

Reaper runs every minute, respects lease/deadline and labels; it removes only positively identified COLOSSUS case resources. Evidence export failure preserves the case within a bounded quarantine allocation and stops admitting new work if storage is exhausted. Never use global Docker prune.

## Implementation steps and acceptance

1. Build source resolver/extractor with malicious-path fixtures.
2. Define stack detectors and frozen recipe schema; test valid and hostile Compose/Docker examples.
3. Implement launcher profiles and prove denied target-to-controller/external/metadata/cross-case connectivity, including IPv6 and redirects.
4. Add Python, Node, Java and C library setup adapters using repo evidence; unsupported profiles remain explicit.
5. Implement database seeds, readiness, library harness and TargetManifest generation.
6. Test clean rebuild, setup retry cap, missing configuration, incompatible architecture, worker timeout, disk cap, forced cancellation and evidence-before-teardown. Require real image/tool reports before calling a profile supported.
