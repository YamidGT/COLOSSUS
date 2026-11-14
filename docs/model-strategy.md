# Model selection, provider limits and cost calibration

Owner A implements the gateway; B/C/D define task profiles and evaluate outcomes. Updated 14 November 2026. This supersedes the draft's generic `mistral-small-latest` / `mistral-large-latest` defaults. Main inference uses the existing Mistral credit; local machines are execution workers, not assumed high-throughput inference servers.

## Decision and evidence

Use **`zai-glm-5-3-flash` through `https://api.mistral.ai/v1`** as the initial coding, triage and proof-hint model. Daniel reports an earlier successful API/proof test and approximately 1M tokens/minute account capacity. That is user-reported, not independently rerun or a measured sustained throughput result in this repository. Preserve the original test artifacts if available; otherwise record `evidence_origin=user_report` and calibrate at M0. A basic proof test establishes neither repair quality nor red-team task suitability.

The [Mistral model page](https://docs.mistral.ai/models/zai-glm-5-3-flash) documents the model, function calling and structured outputs. That supports using it as a candidate agent model, not declaring it the best coding model. GLM's documented reasoning choices include `low`, `high` and `max`; the value `none` is unsupported. Use low for routine triage and high for patch/proof tasks only after the endpoint capability test. [Reasoning documentation](https://docs.mistral.ai/inference/conversations/reasoning).

## Price snapshot, USD per million tokens

| Provider / exact model ID | Input | Output | 10M input + 10M output | Role |
|---|---:|---:|---:|---|
| Mistral `zai-glm-5-3-flash` | 0.15 | 0.50 | 6.50 | Default |
| Mistral `codestral-2508` | 0.30 | 0.90 | 12.00 | Optional calibrated coding fallback |
| Mistral `deepseek-v4-1-flash-1017` | 0.30 | 1.20 | 15.00 | Optional independent candidate/review model; public-preview stability caveat |
| Groq `openai/gpt-oss-20b` | 0.075 | 0.30 | 3.75 | Optional simple-task cost comparator |
| Groq `openai/gpt-oss-120b` | 0.15 | 0.60 | 7.50 | Optional difficult-fix/review comparator |

Primary price sources: [GLM Flash](https://docs.mistral.ai/models/zai-glm-5-3-flash), [Codestral](https://docs.mistral.ai/models/codestral-25-08), [DeepSeek Flash](https://docs.mistral.ai/models/deepseek-v4-flash-1017), [Groq model/pricing catalog](https://console.groq.com/docs/models), [Groq 20B](https://console.groq.com/docs/model/openai/gpt-oss-20b). Refresh prices against the actual account before spending. These totals are token arithmetic, not forecast campaign cost; they omit extra calls and any additional billed tokens not in the stated counts. Use reported billing categories without double-counting reasoning tokens already included in output. Reserve without cache discounts unless their accounting is reliably established.

Groq requires separate credentials and funding: Mistral credit cannot pay it. Daniel reports a prior Groq account limit of only 8,000 tokens/minute; this is not a universal provider limit and is not remeasured here. Groq is disabled by default. Its budget is zero until configured separately, while all enabled providers remain subject to the shared campaign ledger. A different model's opinion is supplementary evidence, never independent mathematical verification or permission to deploy.

## Task routing

- T0: deterministic static/dependency tools; no LLM.
- T1: GLM Flash, bounded context, low reasoning when supported; triage and select approved local probe profiles.
- T2: GLM Flash with deeper context/high reasoning and additional task budget within the existing case cap. Tiers describe work, not an unmeasured “small versus large” quality ordering.
- Repair and proof hints: GLM Flash high reasoning, same three-candidate cap; Dafny decides proof success. Keep default 32k input / 8k total billed output reservation ceiling for these profiles, subject to tested API semantics.
- Transport fallback: Codestral only after capability/calibration success. DeepSeek is an explicitly selected experiment or reviewed fallback profile. Do not silently switch in scored runs. Record requested/actual model, endpoint, reasoning setting and fallback cause.

Model selection configuration is exact IDs, not mutable `latest` aliases. Even an exact public ID may not identify immutable weights: record response model/version metadata and run date, and do not claim stronger reproducibility than the provider exposes. Existing global concurrency two, task deadlines, 20 requests/case and dollar ceilings still apply despite the reported high token allowance.

## Red-team constraints and refusal handling

Separate three questions: account/endpoint availability, model willingness on a task, and provider policy. The earlier pasted advice is context, not a blanket permission determination. [Mistral usage policy](https://legal.mistral.ai/terms/usage-policy/) prohibits security compromise and circumventing protections. [Groq policy](https://console.groq.com/docs/legal/ai-policy) restricts offensive cyber activity/automated vulnerability discovery and exploitation and describes a lawful-research exception route. Neither a successful API response nor open weights establishes authorization for a particular hosted workflow.

Our scope remains authorized local training copies, bounded probes, vulnerability analysis, patching and verification. Do not use model fallback to evade a safety refusal or attempt to bypass provider filters. For any intended task whose provider coverage is unresolved, record that limitation and obtain provider clarification before enabling that task; continue the supported work. This is not an extra approval requirement for writing these documents or building the platform. Do not test public deployments or broaden probe effects to make a model cooperate.

Record `refused`, `provider_policy_block`, `rate_limited`, `unsupported_parameter`, `invalid_output`, `transport_error` and `success` as separate gateway reason codes. For refusals, retain bounded redacted evidence and mark the task incomplete; no hidden retries on other providers. For transient network/429 errors, bounded backoff honors Retry-After and existing deadline/reservation rules. Do not infer policy from generic error wording without evidence.

We have not measured refusal rates for these models on the actual workload. Evaluate allowed task completion and effect containment, not ability to jailbreak providers. Prompt injections embedded in local target content test COLOSSUS's trust boundary; they are not instructions to circumvent hosted-service protections.

## Implementation and calibration

1. Add versioned model profiles with provider, exact ID, supported parameters, prices/date/source, billed-token mapping, quotas, task capabilities and fallback rules. Secrets remain gateway-only. Persist profile hash on each task.
2. M0 capability probes: basic response, schema output, named-function arguments, representative code patch, one proof-hint task and refusal/error classification fixtures. Use small output caps; log real versus simulated errors separately.
3. Configure RPM/TPM from account evidence and observed headers. Token-bucket admission reserves prompt plus maximum billable output across concurrent calls; 429 shrinks admission rather than triggering account rotation.
4. Calibrate on DSVW/VAmPI development cases. Compare cost and time per candidate passing build, functional/security gates and applicable formal obligations. Count every failed attempt. Keep heldout targets out of this selection step.
5. Freeze one model/task-profile set before the repository campaign and three benchmark samples. Changing models or reasoning settings creates a new experimental configuration; benchmark results identify fallback separately.
6. Use offline error fixtures to test ledger races, uncertain timeout charges and failover. Verify that a refusal cannot become a success or trigger a more permissive model path.

Example planning arithmetic: a GLM request with 32k input and 8k billed output is USD 0.0088 at this price snapshot; twenty such requests are USD 0.176. Real use may differ through repeated context, reasoning, retries and provider accounting. The USD 2 case limit remains a ceiling, not a target; host build/test/proof time may dominate even when tokens are inexpensive.
