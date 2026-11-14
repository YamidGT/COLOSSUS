// Test helpers. FIXTURES ONLY: they do not establish runtime correctness against a live controller.
import { vi } from "vitest";

export const HOSTILE = `<img src=x onerror="alert(1)"><script>alert('xss')</script>`;

export interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
}

type Handler = (call: Call) => { status?: number; body?: unknown; headers?: Record<string, string> } | Error;

/** Stubs global fetch with a route handler and records every call. */
export function mockFetch(handler: Handler) {
  const calls: Call[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => (headers[key] = value));
    const call: Call = {
      method: init?.method ?? "GET",
      url: String(input),
      headers,
      body: init?.body as string | undefined,
    };
    calls.push(call);
    const result = handler(call);
    if (result instanceof Error) throw result;
    const status = result.status ?? 200;
    return new Response(status === 304 || result.body === undefined ? null : JSON.stringify(result.body), {
      status,
      headers: { "Content-Type": "application/json", ...(result.headers ?? {}) },
    });
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}
