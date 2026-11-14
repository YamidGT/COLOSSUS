import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { ActionButton, AllowedAction } from "./actions";
import { setCsrf } from "./api";
import { mockFetch } from "./test/fixtures";

afterEach(() => setCsrf(null));

const eligible: AllowedAction = {
  action: "run",
  resource_id: "p1",
  expected_revision: 1,
  eligible: true,
  disabled_reason: null,
  required_confirmation: false,
};
const accepted = { status: 202, body: { operation_id: "op1", status: "accepted" } };

describe("ActionButton", () => {
  it("reuses the same Idempotency-Key when the operator retries a failed action", async () => {
    const user = userEvent.setup();
    let attempt = 0;
    setCsrf("tok");
    const calls = mockFetch(() => (++attempt === 1 ? new TypeError("Failed to fetch") : accepted));
    render(<ActionButton label="Run cycle" path="/projects/p1/cycles" body={{ trigger: "manual" }} allowed={eligible} />);

    await user.click(screen.getByRole("button", { name: "Run cycle" }));
    await user.click(await screen.findByRole("button", { name: "Retry run cycle" }));
    await screen.findByText("Run cycle: accepted (accepted)");

    expect(calls).toHaveLength(2);
    expect(calls[0]!.headers["idempotency-key"]).toBeTruthy();
    expect(calls[1]!.headers["idempotency-key"]).toBe(calls[0]!.headers["idempotency-key"]);
    expect(calls[1]!.headers["x-csrf-token"]).toBe("tok");
    expect(JSON.parse(calls[1]!.body!)).toEqual({ trigger: "manual" });
  });

  it("uses a new key for a new deliberate action after the first was accepted", async () => {
    const user = userEvent.setup();
    const calls = mockFetch(() => accepted);
    render(<ActionButton label="Run cycle" path="/projects/p1/cycles" allowed={eligible} />);
    await user.click(screen.getByRole("button", { name: "Run cycle" }));
    await screen.findByText("Run cycle: accepted (accepted)");
    await user.click(screen.getByRole("button", { name: "Run cycle" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0]!.headers["idempotency-key"]).not.toBe(calls[1]!.headers["idempotency-key"]);
  });

  it("shows the server's rejection and offers no same-key retry for a 409", async () => {
    const user = userEvent.setup();
    mockFetch(() => ({ status: 409, body: { error: { code: "project_paused", message: "Resume the project before starting work" } } }));
    render(<ActionButton label="Run cycle" path="/projects/p1/cycles" allowed={eligible} />);
    await user.click(screen.getByRole("button", { name: "Run cycle" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Resume the project before starting work");
    expect(screen.queryByRole("button", { name: "Retry run cycle" })).toBeNull();
  });

  it("disables an ineligible action and shows the server's disabled_reason", () => {
    const calls = mockFetch(() => accepted);
    render(
      <ActionButton
        label="Run cycle"
        path="/projects/p1/cycles"
        allowed={{ ...eligible, eligible: false, disabled_reason: "Project is paused, not ready or already running" }}
      />,
    );
    const button = screen.getByRole("button", { name: "Run cycle" });
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription("Project is paused, not ready or already running");
    expect(calls).toHaveLength(0);
  });

  it("disables changes while the data is stale", () => {
    render(<ActionButton label="Run cycle" path="/projects/p1/cycles" allowed={eligible} stale />);
    expect(screen.getByRole("button", { name: "Run cycle" })).toBeDisabled();
    expect(screen.getByText(/Connection is stale/)).toBeInTheDocument();
  });

  it("confirms a consequential action before sending it", async () => {
    const user = userEvent.setup();
    const calls = mockFetch(() => accepted);
    render(
      <ActionButton label="Cancel cycle" path="/cycles/cy1/cancel" allowed={null} confirm={{ title: "Cancel this cycle?", body: "Evidence is kept." }} />,
    );
    await user.click(screen.getByRole("button", { name: "Cancel cycle" }));
    expect(screen.getByRole("dialog", { name: "Cancel this cycle?" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Keep as is" }));
    expect(calls).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Cancel cycle" }));
    await user.click(screen.getAllByRole("button", { name: "Cancel cycle" }).at(-1)!);
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]!.url).toBe("/api/v1/cycles/cy1/cancel");
  });
});
