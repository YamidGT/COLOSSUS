import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { setCsrf } from "./api";
import { Call, HOSTILE, mockFetch } from "./test/fixtures";

afterEach(() => setCsrf(null));

// Shapes follow Controller.snapshot()/actions() and cycle.py case records.
function snapshot(overrides: Record<string, unknown> = {}) {
  return {
    project_id: "p1",
    display_name: "erev0s/VAmPI",
    repo_url: "https://github.com/erev0s/VAmPI",
    revision: 3,
    setup_state: "READY",
    admission_state: "active",
    active_cycle: null,
    attention_count: 0,
    deployment_summary: {},
    mirror_summary: {},
    cost_summary: { unit: "micro_usd" },
    feed_freshness: [],
    owner_policy_id: "lab_auto",
    assurance_profile: "tested",
    reason: null,
    allowed_actions: [
      { action: "run", resource_id: "p1", eligible: true, disabled_reason: null, required_confirmation: false },
      { action: "pause", resource_id: "p1", eligible: true, disabled_reason: null, required_confirmation: false },
    ],
    ...overrides,
  };
}

type Routes = Record<string, unknown>;

function serve(routes: Routes, extra?: (call: Call) => { status?: number; body?: unknown } | undefined) {
  return mockFetch((call) => {
    const special = extra?.(call);
    if (special) return special;
    if (call.url === "/api/v1/session") return { body: { operator: "local", csrf_token: "csrf-1" } };
    const path = call.url.replace("/api/v1", "");
    if (path in routes) return { body: routes[path] };
    return { status: 404, body: { error: { code: "not_found", message: "Resource not found" } } };
  });
}

function open(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

const projectRoutes = (snap = snapshot(), more: Routes = {}) => ({
  "/projects/p1/status": snap,
  "/projects/p1/actions": { items: [] },
  "/projects/p1/findings": { items: [] },
  ...more,
});

describe("hostile repository text renders as text", () => {
  it("on the repository list", async () => {
    serve({ "/projects": { items: [snapshot({ display_name: HOSTILE, repo_url: HOSTILE })], next_cursor: null } });
    const { container } = open("/");
    expect(await screen.findByRole("link", { name: HOSTILE })).toBeInTheDocument();
    expect(container.querySelector("img, script")).toBeNull();
  });

  it("on the project page (name, reason, findings, action items)", async () => {
    serve(
      projectRoutes(snapshot({ display_name: HOSTILE, reason: HOSTILE }), {
        "/projects/p1/findings": { items: [{ finding_id: "f1", title: HOSTILE, status: "suspected" }] },
        "/projects/p1/actions": { items: [{ action_id: "a1", title: HOSTILE, reason: HOSTILE, kind: "setup", allowed_actions: [] }] },
      }),
    );
    const { container } = open("/projects/p1");
    expect(await screen.findByRole("heading", { level: 1, name: HOSTILE })).toBeInTheDocument();
    expect(await screen.findAllByText(HOSTILE)).not.toHaveLength(0);
    expect(container.querySelector("img, script")).toBeNull();
    expect(container.innerHTML).not.toContain("<img");
  });

  it("on the case page (gate ids, scope, reasons)", async () => {
    serve({
      "/cases/c1": {
        case_id: "c1",
        project_id: "p1",
        status: "REVIEW_READY",
        assurance_summary: { profile: "tested", formal: "UNSUPPORTED" },
        gate_results: [{ gate_id: "g", check_profile_id: HOSTILE, status: "pass", proof_outcome: null, scope: [HOSTILE], reason: HOSTILE }],
      },
    });
    const { container } = open("/projects/p1/cases/c1");
    expect(await screen.findByText(HOSTILE, { selector: "p.font-medium" })).toBeInTheDocument();
    expect(container.querySelector("img, script")).toBeNull();
  });
});

describe("case review", () => {
  it("shows UNKNOWN exactly, never as a pass, and shows the assurance profile", async () => {
    serve({
      "/cases/c1": {
        case_id: "c1",
        project_id: "p1",
        status: "REVIEW_READY",
        assurance_summary: { profile: "tested", formal: "UNKNOWN" },
        gate_results: [
          { gate_id: "g1", check_profile_id: "formal-coverage-v1", status: "pass", proof_outcome: "UNKNOWN", scope: ["SQL adapter"], assumptions: ["bounded input"] },
        ],
      },
    });
    open("/projects/p1/cases/c1");
    const row = (await screen.findByText("formal-coverage-v1")).closest("li")!;
    expect(row).toHaveTextContent("Proof UNKNOWN");
    expect(row.textContent).not.toMatch(/PROVED|verified|passed/i);
    expect(row.querySelector('[class*="text-ok"], [class*="bg-ok"]')).toBeNull();
    expect(screen.getByText("Assurance profile").nextElementSibling).toHaveTextContent("tested");
    expect(screen.getByText("Formal outcome").nextElementSibling).toHaveTextContent("UNKNOWN");
  });
});

describe("project actions", () => {
  it("shows the server's disabled reason and the resume control for a paused project", async () => {
    serve(
      projectRoutes(
        snapshot({
          admission_state: "paused",
          allowed_actions: [
            { action: "run", resource_id: "p1", eligible: false, disabled_reason: "Project is paused, not ready or already running", required_confirmation: false },
            { action: "resume", resource_id: "p1", eligible: true, disabled_reason: null, required_confirmation: false },
          ],
        }),
      ),
    );
    open("/projects/p1");
    const run = await screen.findByRole("button", { name: "Run cycle" });
    expect(run).toBeDisabled();
    expect(run).toHaveAccessibleDescription("Project is paused, not ready or already running");
    expect(screen.getByRole("button", { name: "Resume schedule" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Pause schedule" })).toBeNull();
  });

  it("runs a cycle with CSRF, Idempotency-Key and the manual trigger body", async () => {
    const user = userEvent.setup();
    const calls = serve(projectRoutes(), (call) =>
      call.method === "POST" ? { status: 202, body: { operation_id: "op1", status: "accepted" } } : undefined,
    );
    open("/projects/p1");
    await user.click(await screen.findByRole("button", { name: "Run cycle" }));
    await screen.findByText("Run cycle: accepted (accepted)");
    const post = calls.find((call) => call.method === "POST")!;
    expect(post.url).toBe("/api/v1/projects/p1/cycles");
    expect(post.headers["x-csrf-token"]).toBe("csrf-1");
    expect(post.headers["idempotency-key"]).toBeTruthy();
    expect(JSON.parse(post.body!)).toEqual({ trigger: "manual" });
  });

  it("offers retry setup and review links only from server action items", async () => {
    serve(
      projectRoutes(snapshot({ setup_state: "SETUP_FAILED" }), {
        "/projects/p1/actions": {
          items: [
            {
              action_id: "p1:setup",
              project_id: "p1",
              case_id: null,
              kind: "setup",
              title: "Repository setup needs attention",
              reason: "Build stopped: Python version unsupported",
              allowed_actions: [{ action: "retry_setup", resource_id: "p1", eligible: false, disabled_reason: "Resume project before retrying", required_confirmation: false }],
              disabled_reasons: {},
            },
            { action_id: "c1:review", project_id: "p1", case_id: "c1", kind: "review", title: "Review case", reason: "Review candidate evidence", allowed_actions: [] },
          ],
        },
      }),
    );
    open("/projects/p1");
    const row = (await screen.findByText("Build stopped: Python version unsupported")).closest("li")!;
    const retry = within(row).getByRole("button", { name: "Retry setup" });
    expect(retry).toBeDisabled();
    expect(retry).toHaveAccessibleDescription("Resume project before retrying");
    expect(screen.getByRole("link", { name: "Review patch" })).toHaveAttribute("href", "/projects/p1/cases/c1");
  });

  it("offers cancel for an active cycle behind a confirmation", async () => {
    const user = userEvent.setup();
    const calls = serve(projectRoutes(snapshot({ active_cycle: { cycle_id: "cy1", status: "PATCHING" } })), (call) =>
      call.method === "POST" ? { status: 202, body: { operation_id: "op2", status: "accepted" } } : undefined,
    );
    open("/projects/p1");
    await user.click(await screen.findByRole("button", { name: "Cancel cycle" }));
    expect(calls.some((call) => call.method === "POST")).toBe(false);
    expect(screen.getByRole("dialog", { name: "Cancel this cycle?" })).toBeInTheDocument();
    await user.click(screen.getAllByRole("button", { name: "Cancel cycle" }).at(-1)!);
    await screen.findByText("Cancel cycle: accepted (accepted)");
    expect(calls.find((call) => call.method === "POST")!.url).toBe("/api/v1/cycles/cy1/cancel");
  });
});

describe("session", () => {
  it("exchanges the login code and uses the returned CSRF token on writes", async () => {
    const user = userEvent.setup();
    let signedIn = false;
    const calls = mockFetch((call) => {
      if (call.url === "/api/v1/session")
        return signedIn
          ? { body: { operator: "local", csrf_token: "from-session" } }
          : { status: 401, body: { error: { code: "unauthorized", message: "Operator authentication required" } } };
      if (call.url === "/api/v1/sessions/exchange") {
        signedIn = true;
        return { body: { operator: "local", csrf_token: "from-exchange" } };
      }
      if (call.url === "/api/v1/projects") return { body: { items: [], next_cursor: null } };
      if (call.method === "POST") return { status: 202, body: { operation_id: "op", status: "accepted" } };
      return { status: 404, body: { error: { code: "not_found", message: "x" } } };
    });
    open("/");
    await user.type(await screen.findByLabelText("Login code"), "one-use-code");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("No repositories enrolled.")).toBeInTheDocument();
    const exchange = calls.find((call) => call.url === "/api/v1/sessions/exchange")!;
    expect(JSON.parse(exchange.body!)).toEqual({ code: "one-use-code" });
    expect(exchange.headers["x-csrf-token"]).toBeUndefined();
  });
});
