import { ReactNode, useCallback, useEffect, useId, useRef, useState } from "react";
import { ApiError, api } from "./api";

/** AllowedAction from the controller read models (docs/contracts.md). A UI hint only. */
export type AllowedAction = {
  action: string;
  resource_id: string;
  expected_revision?: number | null;
  eligible: boolean;
  disabled_reason: string | null;
  required_confirmation: boolean;
};

export type Receipt = { operation_id: string; status: string; kind?: string };

/** Whether the identical request (same Idempotency-Key) may be sent again. */
export function canRetrySameRequest(error: ApiError) {
  return error.status === 0 || error.status === 429 || error.status >= 500;
}

/**
 * One user action = one Idempotency-Key. The key is generated on the first attempt and
 * reused for every retry of that action, so a retry after a dropped connection returns
 * the original receipt instead of starting new work. It is discarded after the server
 * accepted the action or the operator dismissed the failure.
 */
export function useAction(path: string, body: unknown | undefined, onAccepted?: () => void) {
  const key = useRef<string | null>(null);
  const inFlight = useRef(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);

  const run = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    if (!key.current) key.current = crypto.randomUUID();
    setPending(true);
    setError(null);
    setReceipt(null);
    try {
      const result = await api<Receipt>(path, {
        method: "POST",
        headers: { "Idempotency-Key": key.current },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      key.current = null;
      setReceipt(result);
      onAccepted?.();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught : new ApiError(0, String(caught)));
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  }, [path, body, onAccepted]);

  const dismiss = useCallback(() => {
    key.current = null;
    setError(null);
  }, []);

  return { pending, error, receipt, run, dismiss };
}

function Dialog({
  open,
  title,
  confirmLabel,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean;
  title: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const keep = useRef<HTMLButtonElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId();
  const bodyId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      opener.current = document.activeElement;
      // Native modal dialog: the page behind is inert and Escape fires "cancel".
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
      keep.current?.focus();
    } else if (!open && dialog.open) {
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
      if (opener.current instanceof HTMLElement) opener.current.focus();
    }
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      aria-describedby={bodyId}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
      className="m-auto w-[min(92vw,480px)] rounded-lg border border-[#7b8794] bg-surface p-6 text-ink backdrop:bg-black/40"
    >
      <h2 id={titleId} className="mb-2 text-lg font-semibold">
        {title}
      </h2>
      <div id={bodyId} className="mb-6">
        {children}
      </div>
      <div className="flex flex-wrap justify-end gap-2">
        <button ref={keep} type="button" onClick={onCancel} className="h-11 rounded-md border border-[#7b8794] bg-surface px-4">
          Keep as is
        </button>
        <button type="button" onClick={onConfirm} className="h-11 rounded-md bg-accent px-4 text-white">
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

/**
 * Renders one controller action. Eligibility and the disabled reason come only from the
 * server's AllowedAction; `allowed === null` means the read model offers no hint for this
 * action and the server's rejection reason is shown after submit.
 */
export function ActionButton({
  label,
  path,
  body,
  allowed,
  stale,
  onAccepted,
  confirm,
}: {
  label: string;
  path: string;
  body?: unknown;
  allowed: AllowedAction | null;
  stale?: boolean;
  onAccepted?: () => void;
  confirm?: { title: string; body: string };
}) {
  const action = useAction(path, body, onAccepted);
  const [asking, setAsking] = useState(false);
  const reasonId = useId();
  const reason =
    allowed && !allowed.eligible
      ? allowed.disabled_reason || "The controller reports this action is not permitted now"
      : stale
        ? "Connection is stale; waiting for a fresh snapshot before allowing changes"
        : null;
  const needsConfirm = Boolean(confirm) || Boolean(allowed?.required_confirmation);

  return (
    <div className="flex flex-col gap-1">
      <button
        type="button"
        onClick={() => (needsConfirm ? setAsking(true) : void action.run())}
        disabled={reason !== null || action.pending}
        aria-busy={action.pending || undefined}
        aria-describedby={reason ? reasonId : undefined}
        className="h-11 rounded-md border border-[#7b8794] bg-surface px-4 font-medium disabled:cursor-not-allowed disabled:opacity-60"
      >
        {label}
      </button>
      {reason ? (
        <p id={reasonId} className="max-w-xs text-[13px] leading-[18px] text-muted">
          {reason}
        </p>
      ) : null}
      <p role="status" className="text-[13px] leading-[18px] text-muted">
        {action.pending ? `${label}: sending` : action.receipt ? `${label}: accepted (${action.receipt.status})` : ""}
      </p>
      {action.error ? (
        <div role="alert" className="rounded-md bg-bad-tint px-3 py-2 text-bad">
          <p>
            {action.error.status === 0 ? "Disconnected: " : ""}
            {action.error.message}
          </p>
          <div className="mt-2 flex gap-2">
            {canRetrySameRequest(action.error) ? (
              <button type="button" onClick={() => void action.run()} className="h-11 rounded-md border border-bad bg-surface px-4">
                Retry {label.toLowerCase()}
              </button>
            ) : null}
            <button type="button" onClick={action.dismiss} className="h-11 rounded-md border border-bad bg-surface px-4">
              Dismiss
            </button>
          </div>
        </div>
      ) : null}
      <Dialog
        open={asking}
        title={confirm?.title ?? `${label}?`}
        confirmLabel={label}
        onCancel={() => setAsking(false)}
        onConfirm={() => {
          setAsking(false);
          void action.run();
        }}
      >
        {confirm?.body ?? "The controller rechecks this request before acting."}
      </Dialog>
    </div>
  );
}
