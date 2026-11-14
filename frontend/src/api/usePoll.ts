import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './client'

export function usePoll<T>(path: string, interval = 10000) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)
  const [nonce, setNonce] = useState(0)
  const refresh = useCallback(() => setNonce(x => x + 1), [])
  const failures = useRef(0)
  useEffect(() => {
    const abort = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    let running = false
    const poll = async () => {
      if (document.hidden || running || abort.signal.aborted) return
      running = true
      try {
        const next = await api<T>(path, { signal: abort.signal })
        if (!abort.signal.aborted) { setData(next); setError(null); setUpdated(new Date()); failures.current = 0 }
      } catch (failure) {
        if (!abort.signal.aborted) { setError(failure instanceof Error ? failure.message : 'Connection interrupted.'); failures.current++ }
      } finally {
        running = false
        if (!abort.signal.aborted) timer = setTimeout(poll, Math.min(30000, interval * Math.max(1, 2 ** failures.current)))
      }
    }
    const focus = () => { clearTimeout(timer); void poll() }
    void poll()
    document.addEventListener('visibilitychange', focus)
    window.addEventListener('focus', focus)
    return () => { abort.abort(); clearTimeout(timer); document.removeEventListener('visibilitychange', focus); window.removeEventListener('focus', focus) }
  }, [path, interval, nonce])
  return { data, error, updated, refresh, fresh: !!data && !error }
}
