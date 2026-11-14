import { afterEach, describe, expect, it } from "vitest";
import { ApiError, api, setCsrf } from "./api";
import { mockFetch } from "./test/fixtures";

afterEach(() => setCsrf(null));

describe("api", () => {
  it("sends the CSRF token and an Idempotency-Key on POST to same-origin /api/v1", async () => {
    const calls = mockFetch(() => ({ status: 202, body: { operation_id: "op1", status: "accepted" } }));
    setCsrf("csrf-abc");
    await api("/projects/p1/cycles", { method: "POST", body: JSON.stringify({ trigger: "manual" }) });
    const call = calls[0]!;
    expect(call.url).toBe("/api/v1/projects/p1/cycles");
    expect(call.headers["x-csrf-token"]).toBe("csrf-abc");
    expect(call.headers["idempotency-key"]).toBeTruthy();
    expect(call.headers["content-type"]).toBe("application/json");
  });

  it("keeps a caller-supplied Idempotency-Key instead of generating a new one", async () => {
    const calls = mockFetch(() => ({ body: { operation_id: "op1", status: "accepted" } }));
    await api("/projects/p1/pause", { method: "POST", headers: { "Idempotency-Key": "fixed-key" } });
    await api("/projects/p1/pause", { method: "POST", headers: { "Idempotency-Key": "fixed-key" } });
    expect(calls.map((call) => call.headers["idempotency-key"])).toEqual(["fixed-key", "fixed-key"]);
  });

  it("sends the CSRF token on DELETE /session and not on reads", async () => {
    const calls = mockFetch(() => ({ body: { status: "logged_out" } }));
    setCsrf("tok");
    await api("/session", { method: "DELETE" });
    await api("/projects");
    expect(calls[0]!.headers["x-csrf-token"]).toBe("tok");
    expect(calls[1]!.headers["x-csrf-token"]).toBeUndefined();
    expect(calls[1]!.headers["idempotency-key"]).toBeUndefined();
  });

  it("maps the error envelope and a network failure", async () => {
    mockFetch(() => ({ status: 409, body: { error: { code: "project_paused", message: "Resume the project before starting work" } } }));
    const error = (await api("/projects/p1/cycles", { method: "POST" }).catch((caught: unknown) => caught)) as ApiError;
    expect(error.status).toBe(409);
    expect(error.message).toBe("Resume the project before starting work");

    mockFetch(() => new TypeError("Failed to fetch"));
    const offline = (await api("/projects").catch((caught: unknown) => caught)) as ApiError;
    expect(offline.status).toBe(0);
  });
});
