// Keep a mutation's identity until the controller resolves its response.
const unresolved = new Map<string, string>()
export function mutationIntent(method: string, path: string, body: string | undefined, supplied?: string) {
  const fingerprint = JSON.stringify([method, path, body])
  let key = supplied ?? unresolved.get(fingerprint)
  if (!key) key = crypto.randomUUID()
  unresolved.set(fingerprint, key)
  return { key, resolve: () => { if (unresolved.get(fingerprint) === key) unresolved.delete(fingerprint) } }
}
