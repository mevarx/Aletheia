import { useEffect, useRef, useState } from 'react'

const TRY_URLS = [
  'https://github.com/mevarx/Aletheia',
  'https://github.com/cisco/secure-ai-skill-scanner',
]

export default function App() {
  const [url, setUrl] = useState(TRY_URLS[0])
  const [semantic, setSemantic] = useState(true)
  const [gemma, setGemma] = useState(null)
  const [logs, setLogs] = useState([])
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const logRef = useRef(null)
  const esRef = useRef(null)

  useEffect(() => {
    fetch('/api/ollama/status')
      .then((r) => r.json())
      .then(setGemma)
      .catch(() => setGemma({ gemma_enabled: false, hint: 'backend not running' }))
  }, [])

  useEffect(() => {
    logRef.current?.scrollTo(0, logRef.current.scrollHeight)
  }, [logs])

  function stop() {
    esRef.current?.close()
    esRef.current = null
    setRunning(false)
  }

  function scan() {
    stop()
    setLogs([])
    setResult(null)
    setError(null)
    setRunning(true)
    const es = new EventSource(
      `/api/scan/stream?url=${encodeURIComponent(url)}&semantic=${semantic ? 1 : 0}`
    )
    esRef.current = es
    es.addEventListener('log', (e) => {
      try {
        setLogs((l) => [...l, JSON.parse(e.data).line])
      } catch { /* ignore */ }
    })
    es.addEventListener('semantic', (e) => {
      try {
        const d = JSON.parse(e.data)
        setLogs((l) => [...l, `── semantic ${d.file} (${d.text.length} chars) ──`])
      } catch { /* ignore */ }
    })
    es.addEventListener('result', (e) => {
      setResult(JSON.parse(e.data))
      stop()
    })
    es.addEventListener('error', (e) => {
      try {
        const d = e.data ? JSON.parse(e.data) : null
        if (d?.message) setError(d.message)
      } catch { /* ignore */ }
      if (!esRef.current) return
      // EventSource fires a generic error on close; only surface if no result
      setRunning(false)
    })
    es.onerror = () => {
      // closed by server after `result` — nothing to do when we have one
      setRunning((r) => {
        if (r) setTimeout(() => setError((prev) => prev ?? 'stream ended — is `aletheia serve` running on :8000?'), 0)
        return false
      })
    }
  }

  const worst = result?.worst
  const badge =
    worst === 'CRITICAL' ? 'crit' : worst === 'SUSPICIOUS' ? 'susp' : worst ? 'ok' : ''

  return (
    <div className="wrap">
      <h1><em>Aletheia</em> — scan a skill from GitHub</h1>
      <p className="sub">Read what runs, not what is shown. Live logs stream while the bundle is cloned, verified, admitted, and explained.</p>

      <div className="card">
        <label>GitHub URL</label>
        <div className="row">
          <input value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
          <button onClick={scan} disabled={running || !url}> {running ? 'Scanning…' : 'Scan'} </button>
          {running && <button className="ghost" onClick={stop}>Stop</button>}
        </div>
        <div className="row small">
          {TRY_URLS.map((u) => (
            <button key={u} className="ghost" onClick={() => setUrl(u)}>{u.replace('https://github.com/', '')}</button>
          ))}
        </div>
        <div className="row small">
          <label><input type="checkbox" checked={semantic} onChange={(e) => setSemantic(e.target.checked)} /> Gemma semantic verdicts</label>
          <span className={`pill ${gemma?.gemma_enabled ? 'ok' : 'off'}`}>
            {gemma == null ? 'checking Gemma…' : gemma.gemma_enabled ? `Gemma on — ${gemma.model}` : `Gemma off — ${gemma.hint ?? ''}`}
          </span>
        </div>
        {!gemma?.gemma_enabled && (
          <p className="hint">To enable Gemma: <code>ollama pull gemma3:4b</code> (or set <code>ALETHEIA_MODEL</code>), then re-scan. Deterministic verdicts work without it.</p>
        )}
      </div>

      <div className="grid">
        <div className="card">
          <h3>Live log</h3>
          <div className="logs" ref={logRef}>
            {logs.length === 0 && <span className="dim">clone → walk → verify → admit → semantic — each step appears here as it happens.</span>}
            {logs.map((l, i) => <div key={i}>{l}</div>)}
          </div>
          {error && <p className="err">{error}</p>}
        </div>
        <div className="card">
          <h3>Verdict {worst && <span className={`pill ${badge}`}>{worst}</span>}</h3>
          {!result && <p className="dim">No result yet.</p>}
          {result && (
            <>
              <p className="dim">critical={result.critical} clean={result.clean} suspicious={result.suspicious} · admit={result.admission?.admitted ? 'ADMITTED' : 'REFUSED'}</p>
              {(result.files ?? []).slice(0, 20).map((f) => (
                <div key={f.source} className="file">
                  <b>[{f.verdict}]</b> {f.source}
                  <div className="dim">{f.reason}</div>
                </div>
              ))}
              {Object.entries(result.semantic ?? {}).map(([k, v]) => (
                <div key={k} className="sem"><h4>GEMMA — {k}</h4><p>{v}</p></div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
