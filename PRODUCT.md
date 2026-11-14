# COLOSSUS operator experience

Documentation-stage product brief. Daniel owns product decisions; session A owns CLI, API and frontend implementation. Read [project context](docs/project-context.md) for the full system and [design rules](DESIGN.md) before interface work.

## Users and job

A developer or security engineer gives COLOSSUS a public repository URL and supervises its recurring local defence cycle. They need to see whether setup worked, what was found, what changed, which checks support the change, what needs their decision, and whether the running version is healthy. The first version serves one trusted operator on a local machine or an SSH tunnel to the Oracle host. Multi-user accounts, tenancy and remote production administration are later extensions.

The primary interaction is a repository action center. The CLI supports the same work for terminal users and scripts. Neither client runs scanners, models, builds or deployment logic itself: all operations go through the controller and its existing authority boundaries.

## Essential journey

1. Start the platform, verify readiness, then add a GitHub URL.
2. See isolated setup progress or an actionable reason it cannot continue.
3. Start the first cycle, or choose “Add and run” to queue it after setup.
4. Follow discovery, repair and verification; see measured time/cost and remaining limits.
5. If policy requires review, inspect the diff, gate results and guarantee limits; approve the exact artifact or reject it with a reason.
6. See promotion, observation and recovery. The next cycle uses the refreshed deployed mirror.
7. Return to the action queue when a decision or failure needs attention; export evidence when needed.

## Product rules

- One clear next action per task. Readiness, remaining risk and uncertainty are visible without opening raw logs.
- Automatic actions follow the enrolled policy. Do not add repetitive confirmations for ordinary lab runs, and never imply URL enrollment authorizes production access.
- “No findings” is a scan result, not a security guarantee. Proof claims name the component/property and assumptions.
- A successful click means the server accepted an operation, not that the operation finished. Preserve pending/failed/recovery states.
- Minimal interface: repository list, repository action center, case review page. Settings live in a small project panel; raw logs/evidence are secondary details.
- Public target content is untrusted. No target HTML, images, scripts or advisory links load automatically inside the operator origin.

## Initial success criteria

In usability checks, a new operator can enroll a repository, identify why a run is blocked, distinguish tested from formally proved scope, review the exact patch and identify the deployed version without assistance. Record task completion, errors and time with at least two teammates; these are pilot usability checks, not population-level research. Preserve one end-to-end CLI/UI parity test for every state-changing operation.

## Boundaries

The platform remains the full recurring cyberdefence system. This operator experience adds usable controls to that system; it does not replace execution with a dashboard simulation. No global “security score,” agent chat console, marketing landing page, terminal emulator or multi-service metrics wall is required. Design-only mock states must be clearly separated from real runtime data.
