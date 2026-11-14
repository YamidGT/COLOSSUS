# Local credentials and configuration boundary

Owner A. The root `.env` contains the two provider keys Daniel supplied: `MISTRAL_API_KEY` and `GROQ_API_KEY`. Values are local only, Git-ignored and permissioned 0600. Their presence has been checked without printing values; neither key was tested or used for inference during documentation. The committed [.env.example](../.env.example) contains blank placeholders only.

At implementation bootstrap, the trusted local launcher loads the file without shell evaluation and passes only the provider variables needed by the gateway process/container. Avoid broad Compose `env_file` propagation to every service. Controller, CLI, frontend, proof jobs, target builds, target runtime and evaluator mounts must not inherit provider keys. Remote host setup uses that host's local secret store or equivalent permission-restricted file; Git will not transport `.env`.

A supplied Groq key does not establish funded quota or authorization to spend. GLM Flash via Mistral remains default. Groq stays disabled until its task profile and separate budget are configured as described in [model strategy](model-strategy.md). Never auto-switch providers merely because credentials exist.

Doctor reports provider `configured/missing` and optional capability-test results, never values or prefixes. No secrets in command arguments, exception dumps, API responses, report exports, snapshots, screenshots or model context. Browser operator sessions and CLI operator tokens are separately generated credentials; provider keys are never login credentials. See [frontend authentication](frontend.md).

Before a commit, verify `.env` is ignored and untracked; before a frontend build, verify no provider env is passed through a `VITE_` variable or injected into static bundles. The example file is safe to commit. Keep placeholder/default configuration distinct from real target/model validation.
