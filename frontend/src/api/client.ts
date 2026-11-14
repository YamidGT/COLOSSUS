import { mutationIntent } from './intents'
import type { components } from './schema'

export type Project = components['schemas']['ProjectSnapshot']
export type Case = components['schemas']['CaseReview']
export type Finding = components['schemas']['Finding']
export type Action = components['schemas']['ActionItem']
export type Receipt = components['schemas']['OperationReceipt']
export type Gate = components['schemas']['GateResult']
let csrf = ''
export function setCsrf(value: string) { csrf = value }
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message) }
}
export async function api<T>(path: string, options: { method?: string; body?: unknown; signal?: AbortSignal; key?: string } = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const body = options.body === undefined ? undefined : JSON.stringify(options.body)
  const intent = method === 'GET' ? null : mutationIntent(method, path, body, options.key)
  const response = await fetch('/api/v1' + path, { method, credentials: 'same-origin', signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000),
    headers: { 'Accept': 'application/json', ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(method === 'GET' ? {} : { 'X-CSRF-Token': csrf, 'Idempotency-Key': intent!.key }) },
    body,
  })
  const data = await response.json()
  if (response.ok || (response.status >= 400 && response.status < 500)) intent?.resolve()
  if (!response.ok) {
    if (response.status === 401 && path !== '/sessions/exchange') window.dispatchEvent(new Event('colossus:session-expired'))
    throw new ApiError(response.status, data.error?.code ?? 'request_failed', data.error?.message ?? 'The controller could not complete this request.')
  }
  return data as T
}
export async function artifact(id: string, projectId: string): Promise<string> {
  const response = await fetch(`/api/v1/artifacts/${encodeURIComponent(id)}/download?project_id=${encodeURIComponent(projectId)}`, { credentials: 'same-origin' })
  if (!response.ok) throw new Error('Evidence is unavailable. Refresh the case and try again.')
  const data = await response.text()
  if (data.length > 200000) return data.slice(0, 200000) + '\n[Preview limited to 200,000 characters]'
  return data
}
export function text(value: Record<string, unknown> | null | undefined, key: string, fallback = 'Not available') { const result = value?.[key]; return result === null || result === undefined ? fallback : String(result) }
export function money(value: unknown) { return typeof value === 'number' ? '$' + (value / 1e6).toFixed(value < 10000 ? 4 : 2) : 'Not available' }
export function label(value: string) { return value.toLowerCase().replaceAll('_', ' ').replace(/^./, x => x.toUpperCase()) }
