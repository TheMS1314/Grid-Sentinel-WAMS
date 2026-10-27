import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, DragEvent, FormEvent, ReactNode } from 'react'
import {
  Activity, ArrowRight, BarChart3, Bell,
  Check, CheckCircle2, ChevronDown, ChevronRight, CircleAlert, CircleHelp,
  Clock3, CloudOff, Database, FileCheck2, FileJson2, FileUp, Fingerprint,
  Gauge, Layers3, LockKeyhole, Menu, MoreHorizontal, Play,
  Plus, RadioTower, RefreshCw, Search, ServerCog, Settings2, Shield,
  ShieldAlert, ShieldCheck, Sparkles, UploadCloud,
  Waves, X, Zap,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis,
} from 'recharts'
import Papa from 'papaparse'
import { api, clearPrivateAccessToken, formatTime, setPrivateAccessToken, shortDate } from './api'
import type { Analysis, ARPResearch, EvidenceScenario, Finding, FourLaneResearch, PriceContextResearch, MeasurementRecord, ModelInfo, Overview, ProtocolResearch, ProtocolSensitivity, ResearchEvidence, View } from './types'
import './login.css'

const EMPTY_OVERVIEW: Overview = {
  model_status: 'RESEARCH_ONLY', analyses: 0, observations: 0,
  review_rows: 0, abstention_rows: 0, last_analysis_at: null,
  daily_activity: [], recent_findings: [],
}

const nav: { view: View; icon: typeof Activity; label: string; description: string }[] = [
  { view: 'overview', icon: BarChart3, label: 'Overview', description: 'Research operations' },
  { view: 'analysis', icon: Waves, label: 'Analysis lab', description: 'Evaluate measurements' },
  { view: 'history', icon: Layers3, label: 'Analysis history', description: 'Previous assessments' },
  { view: 'evidence', icon: FileCheck2, label: 'Research evidence', description: 'Historical benchmark audit' },
  { view: 'system', icon: Settings2, label: 'System & model', description: 'Health and limitations' },
]

function displaySignal(value: string | null | undefined) {
  if (!value) return 'Unavailable measurement'
  const [device, field] = value.split('.')
  return `${device?.replaceAll('-AC-Meter', '').replaceAll('-Inverter', '') ?? ''} · ${field?.replace('sum_', '').toUpperCase() ?? ''} phase sum`
}

function Mark({ size = 34 }: { size?: number }) {
  return <div className="brand-mark" style={{ width: size, height: size }}>
    <Activity size={size * .57} strokeWidth={2.7} />
  </div>
}

function Pill({ children, variant = 'neutral', icon }: { children: ReactNode; variant?: 'success' | 'warning' | 'danger' | 'neutral'; icon?: ReactNode }) {
  return <span className={`pill pill-${variant}`}>{icon}{children}</span>
}

function IconBox({ children, color = 'teal' }: { children: ReactNode; color?: 'teal' | 'amber' | 'violet' | 'blue' }) {
  return <div className={`icon-box icon-box-${color}`}>{children}</div>
}

function MetricCard({ label, value, sub, icon, color }: { label: string; value: string | number; sub: string; icon: ReactNode; color: 'teal' | 'amber' | 'violet' | 'blue' }) {
  return <article className="metric-card">
    <div className="metric-card-top"><span>{label}</span><IconBox color={color}>{icon}</IconBox></div>
    <div className="metric-value">{typeof value === 'number' ? value.toLocaleString('en-IN') : value}</div>
    <div className="metric-sub"><span className="metric-sub-dot" />{sub}</div>
  </article>
}

function EmptyState({ icon, title, body, action }: { icon: ReactNode; title: string; body: string; action?: ReactNode }) {
  return <div className="empty-state">
    <div className="empty-icon">{icon}</div><h3>{title}</h3><p>{body}</p>{action}
  </div>
}

function FindingRow({ finding, onOpen }: { finding: Finding; onOpen?: (id: string) => void }) {
  const review = finding.kind === 'LOCAL_PHYSICS_REVIEW'
  return <tr>
    <td><div className="event-primary">{review ? 'Power identity mismatch' : 'Incomplete observation'}</div><div className="event-secondary">{displaySignal(finding.identity_name)}</div></td>
    <td><Pill variant={review ? 'warning' : 'neutral'} icon={review ? <CircleAlert size={12} /> : <CircleHelp size={12} />}>{review ? 'Review required' : 'Abstained'}</Pill></td>
    <td className="mono-cell">{finding.score == null ? '—' : finding.score.toFixed(1)}</td>
    <td className="time-cell">{formatTime(finding.timestamp)}</td>
    <td>{onOpen && finding.analysis_id && <button className="icon-button compact" aria-label="View analysis" onClick={() => onOpen(finding.analysis_id!)}><ChevronRight size={17} /></button>}</td>
  </tr>
}

function OverviewPage({ overview, analyses, offline, onNavigate, onOpen, onRefresh }: {
  overview: Overview; analyses: Analysis[]; offline: boolean; onNavigate: (v: View) => void;
  onOpen: (id: string) => void; onRefresh: () => void
}) {
  const chart = overview.daily_activity.map(d => ({ ...d, label: shortDate(d.date) }))
  return <>
    <div className="page-intro"><div><div className="intro-overline"><span className="pulse-dot" /> PRIVATE RESEARCH WORKSPACE</div>
      <h1>Grid intelligence, <span>made visible.</span></h1>
      <p>Explore meter integrity signals, review findings, and trace every assessment—with the evidence and limitations in view.</p>
    </div><button className="primary-button hero-button" onClick={() => onNavigate('analysis')}><Plus size={18} /> New analysis <ArrowRight size={17} /></button></div>

    <div className="metrics-grid">
      <MetricCard label="Total analyses" value={overview.analyses} sub="Recorded evaluations" icon={<Layers3 size={20} />} color="teal" />
      <MetricCard label="Observations assessed" value={overview.observations} sub="Measurement rows processed" icon={<Activity size={20} />} color="blue" />
      <MetricCard label="Review signals" value={overview.review_rows} sub="Not confirmed cyberattacks" icon={<ShieldAlert size={20} />} color="amber" />
      <MetricCard label="Abstained rows" value={overview.abstention_rows} sub="Missing or invalid input" icon={<RadioTower size={20} />} color="violet" />
    </div>
    <div className="overview-grid">
      <section className="panel chart-panel"><div className="panel-head">
        <div><div className="eyebrow">ACTIVITY</div><h3>Detection workspace</h3><p>Recorded analyses and review signals · last 14 days</p></div>
        <button className="icon-button" aria-label="Refresh activity" onClick={onRefresh}><RefreshCw size={17} /></button>
      </div>
        <div className="chart-legend"><span><i className="legend-dot teal" /> Observations</span><span><i className="legend-dot amber" /> Review signals</span></div>
        {overview.analyses === 0 ? <div className="chart-empty"><div className="chart-empty-line" /><p>Your analysis trends will appear here after the first run.</p></div> :
          <div className="activity-chart"><ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chart} margin={{ top: 12, right: 7, left: 2, bottom: 0 }}>
              <defs><linearGradient id="obGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#44dacb" stopOpacity={.3} /><stop offset="95%" stopColor="#44dacb" stopOpacity={0} /></linearGradient></defs>
              <CartesianGrid vertical={false} stroke="#273143" strokeDasharray="3 6" />
              <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: '#748094', fontSize: 11 }} interval="preserveStartEnd" dy={12} />
              <Tooltip contentStyle={{ background: '#131b2b', border: '1px solid #334057', borderRadius: 12, color: '#e7f3f6' }} itemStyle={{ color: '#dceff0' }} />
              <Area type="monotone" dataKey="observations" name="Observations" stroke="#42dbc9" strokeWidth={2.5} fill="url(#obGradient)" />
              <Area type="monotone" dataKey="reviews" name="Review signals" stroke="#f7b967" strokeWidth={2} fill="transparent" />
            </AreaChart>
          </ResponsiveContainer></div>}
      </section>

      <section className="panel model-panel"><div className="panel-head"><div><div className="eyebrow">MODEL STATUS</div><h3>Integrity engine</h3></div><Pill variant={offline ? 'danger' : 'success'}>{offline ? 'Offline' : 'API ready'}</Pill></div>
        <div className="engine-art"><div className="engine-circle outer" /><div className="engine-circle middle" /><div className="engine-circle inner"><ShieldCheck size={39} strokeWidth={1.5} /></div><div className="orbit-dot orbit-one" /><div className="orbit-dot orbit-two" /></div>
        <div className="engine-title">Three-phase consistency</div><div className="engine-sub">15 physics identity features · 3-row confirmation</div>
        <div className="engine-separator" />
        <div className="model-stat-row"><span>Deployment scope</span><strong>Research only</strong></div>
        <div className="model-stat-row"><span>Operational control</span><strong className="muted-good">Disabled</strong></div>
        <div className="model-stat-row"><span>Last evaluation</span><strong>{overview.last_analysis_at ? formatTime(overview.last_analysis_at) : 'Not yet run'}</strong></div>
        <button className="text-link full" onClick={() => onNavigate('system')}>Model details <ArrowRight size={16} /></button>
      </section>
    </div>

    <div className="lower-grid">
      <section className="panel recent-panel"><div className="panel-head"><div><div className="eyebrow">REVIEW QUEUE</div><h3>Recent findings</h3></div><button className="text-link" onClick={() => onNavigate('history')}>View history <ArrowRight size={16}/></button></div>
        {overview.recent_findings.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Signal</th><th>Classification</th><th>Score</th><th>Time</th><th /></tr></thead><tbody>
          {overview.recent_findings.slice(0,6).map(f => <FindingRow key={f.id} finding={f} onOpen={onOpen} />)}
        </tbody></table></div> : <EmptyState icon={<Bell size={25}/>} title="No findings yet" body="Anomalous or incomplete measurements will appear here when an analysis is run." action={<button className="secondary-button" onClick={() => onNavigate('analysis')}>Start an analysis <ArrowRight size={15}/></button>} />}
      </section>
      <section className="panel insight-panel"><div className="eyebrow">IMPORTANT CONTEXT</div><div className="insight-icon"><Shield size={24} /></div><h3>Review signals aren't attack verdicts.</h3><p>The detector checks meter identities for inconsistencies. It cannot authenticate data sources or detect every coordinated compromise.</p><div className="insight-divider" />
        <div className="insight-point"><CheckCircle2 size={15}/> Sustained physical mismatch checks</div>
        <div className="insight-point"><LockKeyhole size={15}/> No grid-control permissions</div>
        <div className="insight-point"><CircleAlert size={15}/> Independent field validation pending</div>
        <button className="text-link" onClick={() => onNavigate('system')}>Understand limitations <ArrowRight size={15}/></button>
      </section>
    </div>
    <section className="panel last-runs-panel"><div className="panel-head"><div><div className="eyebrow">RUN HISTORY</div><h3>Latest assessments</h3></div><button className="text-link" onClick={() => onNavigate('history')}>All analyses <ArrowRight size={15}/></button></div>
      {analyses.length ? <div className="mini-runs">{analyses.slice(0,3).map(a => <button key={a.id} onClick={() => onOpen(a.id)}><div className="run-symbol"><FileCheck2 size={19}/></div><span className="run-name"><strong>{a.source_name}</strong><small>{formatTime(a.created_at)} · {a.observation_count} samples</small></span><Pill variant={a.review_count ? 'warning' : 'success'}>{a.review_count ? `${a.review_count} review rows` : 'No confirmed mismatch'}</Pill><ChevronRight size={17}/></button>)}</div> : <p className="inline-empty">No assessments recorded. Upload a dataset to create your first run.</p>}
    </section>
  </>
}

const DEVICE_NAMES = ['BSS-Inverter-AC-Meter', 'Load-A-AC-Meter', 'Load-B-AC-Meter', 'PV-Inverter-AC-Meter', 'Substation-AC-Meter']
const FIELD_NAMES = ['p_sum3', 'q_sum3', 's_sum3', 'pln1', 'pln2', 'pln3', 'qln1', 'qln2', 'qln3', 'sln1', 'sln2', 'sln3']

function makeSyntheticDemo(): MeasurementRecord[] {
  const base = [-2500, 6500, 7200, -15000, -4000]
  const start = Date.now() - 24000
  return Array.from({ length: 24 }, (_, i) => {
    const values: Record<string, number> = {}
    DEVICE_NAMES.forEach((device, j) => {
      const p = base[j] + Math.sin(i / 6) * 100
      const q = p * .12
      const s = Math.hypot(p, q)
      const corrupt = i >= 13 && i <= 19 && j === 3
      const actualP = corrupt ? p * 1.25 : p
      const map: Record<string, number> = {
        p_sum3: actualP, q_sum3: q, s_sum3: s,
        pln1: p / 3, pln2: p / 3, pln3: p / 3,
        qln1: q / 3, qln2: q / 3, qln3: q / 3,
        sln1: s / 3, sln2: s / 3, sln3: s / 3,
      }
      FIELD_NAMES.forEach(field => { values[`${device}.${field}`] = map[field] })
    })
    return { timestamp: new Date(start + i * 1000).toISOString(), values }
  })
}

function parseMeasurementFile(file: File): Promise<MeasurementRecord[]> {
  return new Promise((resolve, reject) => {
    const read = new FileReader()
    read.onerror = () => reject(new Error('Could not read the selected file'))
    read.onload = () => {
      try {
        const contents = String(read.result)
        let raw: Record<string, unknown>[]
        if (file.name.toLowerCase().endsWith('.json')) {
          const parsed = JSON.parse(contents) as unknown
          const maybe = Array.isArray(parsed) ? parsed : (parsed as { records?: unknown; readings?: unknown }).records ?? (parsed as { readings?: unknown }).readings
          if (!Array.isArray(maybe)) throw new Error('JSON must contain an array of records or readings')
          raw = maybe as Record<string, unknown>[]
        } else {
          const parsed = Papa.parse<Record<string, unknown>>(contents, { header: true, dynamicTyping: true, skipEmptyLines: true })
          if (parsed.errors.length) throw new Error(parsed.errors[0].message)
          raw = parsed.data
        }
        if (raw.length < 1 || raw.length > 1000) throw new Error('Each upload must contain between 1 and 1,000 timestamped rows')
        const rows = raw.map((item, i): MeasurementRecord => {
          if (!item || typeof item !== 'object') throw new Error(`Row ${i + 1} is not a measurement record`)
          const stamp = item.timestamp
          if (typeof stamp !== 'string' || !/([zZ]|[+-]\d\d:\d\d)$/.test(stamp) || Number.isNaN(Date.parse(stamp))) {
            throw new Error(`Row ${i + 1} requires an ISO timestamp with an explicit timezone`)
          }
          const values = item.values && typeof item.values === 'object' ? item.values as Record<string, unknown> : item
          const converted: Record<string, number | null> = {}
          DEVICE_NAMES.forEach(d => FIELD_NAMES.forEach(f => {
            const key = `${d}.${f}`
            const v = values[key]
            if (v === '' || v == null) converted[key] = null
            else if (typeof v === 'number' && Number.isFinite(v)) converted[key] = v
            else if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) converted[key] = Number(v)
            else converted[key] = null
          }))
          return { timestamp: stamp, values: converted }
        })
        resolve(rows)
      } catch (error) { reject(error instanceof Error ? error : new Error('Unsupported measurement file')) }
    }
    read.readAsText(file)
  })
}

function AnalysisLab({ onComplete }: { onComplete: (a: Analysis) => void }) {
  const [fileName, setFileName] = useState('')
  const [records, setRecords] = useState<MeasurementRecord[]>([])
  const [busy, setBusy] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState('')
  const [synthetic, setSynthetic] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const choose = async (file?: File) => {
    if (!file) return
    setError(''); setRecords([])
    try {
      if (!/\.(csv|json)$/i.test(file.name)) throw new Error('Please upload a .csv or .json file')
      const next = await parseMeasurementFile(file)
      setRecords(next); setFileName(file.name); setSynthetic(false)
    } catch (err) { setError(err instanceof Error ? err.message : 'File could not be parsed') }
  }
  const handleDrop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); setDragging(false); void choose(event.dataTransfer.files[0]) }
  const run = async () => {
    setBusy(true); setError('')
    try { onComplete(await api.createAnalysis(fileName || 'Uploaded measurements', records)) }
    catch (err) { setError(err instanceof Error ? err.message : 'Analysis failed') }
    finally { setBusy(false) }
  }
  return <>
    <div className="view-header"><div className="eyebrow">INFERENCE WORKSPACE</div><h1>Analysis lab</h1><p>Run the frozen research detector against your measurements. Your source data is assessed locally; only findings and run metadata are retained.</p></div>
    <div className="lab-layout"><section className="panel upload-panel">
      <div className="step-line"><span className="step-number">01</span><div><h3>Import measurement data</h3><p>Upload timestamped meter records in CSV or JSON format.</p></div></div>
      <input ref={inputRef} type="file" accept=".csv,.json" hidden onChange={(e: ChangeEvent<HTMLInputElement>) => void choose(e.target.files?.[0])} />
      <div className={`upload-drop ${dragging ? 'dragging' : ''} ${records.length ? 'uploaded' : ''}`} onDragOver={e => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={handleDrop} onClick={() => inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') inputRef.current?.click() }}>
        {records.length ? <><div className="upload-glyph uploaded-icon"><FileCheck2 size={30}/></div><h3>{fileName}</h3><p>{records.length.toLocaleString()} records ready for evaluation</p><span className="upload-link">Choose another file</span></> : <><div className="upload-glyph"><UploadCloud size={31}/></div><h3>Drop your data here</h3><p>or <span className="upload-link">browse files</span> from your computer</p><small>CSV / JSON · Up to 1,000 rows per assessment</small></>}
      </div>
      <div className="demo-divider"><span>OR TRY A CONTROLLED EXAMPLE</span></div>
      <button className="demo-button" onClick={() => { setRecords(makeSyntheticDemo()); setFileName('Synthetic test signal'); setSynthetic(true); setError('') }}><Sparkles size={17}/> Load synthetic demo data <ArrowRight size={16}/></button>
      {synthetic && <div className="inline-note"><CircleAlert size={15}/> This is a manufactured signal for interface testing—not a real cyberattack or validation result.</div>}
    </section>
    <section className="panel analysis-config"><div className="step-line"><span className="step-number">02</span><div><h3>Review and evaluate</h3><p>Fixed model parameters · no test-time retraining</p></div></div>
      <div className="config-row"><div className="config-icon"><ShieldCheck size={19}/></div><div><strong>Meter consistency · v1</strong><p>15 algebraic identity features</p></div><Pill variant="success">Loaded</Pill></div>
      <div className="config-row"><div className="config-icon"><Clock3 size={19}/></div><div><strong>Temporal confirmation</strong><p>3 consecutive 1 Hz measurements</p></div><strong className="config-value">3 rows</strong></div>
      <div className="config-row"><div className="config-icon"><LockKeyhole size={19}/></div><div><strong>Decision policy</strong><p>Non-actionable review only</p></div><Pill variant="warning">Research</Pill></div>
      <div className="selection-summary"><span>Selected observations</span><strong>{records.length ? records.length.toLocaleString() : 'None'}</strong></div>
      {error && <div className="error-box"><CircleAlert size={17}/>{error}</div>}
      <button className="primary-button run-button" disabled={!records.length || busy} onClick={() => void run()}>{busy ? <RefreshCw size={18} className="spin" /> : <Play size={17} fill="currentColor" />}{busy ? 'Analyzing measurements…' : 'Run integrity analysis'}<ArrowRight size={17}/></button>
      <p className="run-disclaimer"><Shield size={14}/> No control commands, external transmission, or automatic attack attribution.</p>
    </section></div>
    <div className="lab-help"><FileJson2 size={20}/><div><strong>What does the input need?</strong><p>One timezone-aware <code>timestamp</code> and 12 power fields per meter for the five named devices. Missing fields cause the detector to abstain, not guess.</p></div><a href="#schema-note" onClick={e => e.preventDefault()}>Schema reference below <ChevronDown size={15}/></a></div>
    <section className="panel schema-panel" id="schema-note"><div className="panel-head"><div><div className="eyebrow">DATA CONTRACT</div><h3>Required meter groups</h3></div><Pill>5 devices · 60 inputs</Pill></div><div className="device-grid">{DEVICE_NAMES.map(name => <div key={name}><RadioTower size={16}/><span>{name.replaceAll('-AC-Meter', '')}</span><Check size={15}/></div>)}</div><p>For each meter: P/Q/S totals and three corresponding phase readings. Timestamps must include a timezone; input records must be strictly increasing.</p></section>
  </>
}

function HistoryPage({ analyses, onOpen, onNew }: { analyses: Analysis[]; onOpen: (id: string) => void; onNew: () => void }) {
  const [search, setSearch] = useState('')
  const filtered = analyses.filter(a => a.source_name.toLowerCase().includes(search.toLowerCase()) || a.id.includes(search))
  return <><div className="view-header view-header-split"><div><div className="eyebrow">AUDIT TRAIL</div><h1>Analysis history</h1><p>Browse saved research assessments and the exact review evidence they produced.</p></div><button className="primary-button" onClick={onNew}><Plus size={17}/> New analysis</button></div>
    <section className="panel history-panel"><div className="history-toolbar"><div className="search-box"><Search size={18}/><input value={search} placeholder="Search by file or run ID…" onChange={e => setSearch(e.target.value)}/></div><Pill>{filtered.length} runs</Pill></div>
      {filtered.length ? <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Source & run</th><th>Recorded</th><th>Observations</th><th>Reviews</th><th>Status</th><th/></tr></thead><tbody>{filtered.map(a => <tr key={a.id} onClick={() => onOpen(a.id)} className="clickable-row"><td><div className="event-primary">{a.source_name}</div><div className="event-secondary mono-cell">{a.id.slice(0,8)}…</div></td><td className="time-cell">{formatTime(a.created_at)}</td><td>{a.observation_count.toLocaleString()}</td><td>{a.review_count}</td><td><Pill variant={a.review_count ? 'warning' : 'success'}>{a.review_count ? 'Needs review' : 'No confirmed mismatch'}</Pill></td><td><ChevronRight size={17}/></td></tr>)}</tbody></table></div> : <EmptyState icon={<Layers3 size={27}/>} title="No matching analyses" body="Your saved assessments will appear here after you run the detector." action={<button className="secondary-button" onClick={onNew}>Analyze measurements <ArrowRight size={16}/></button>}/>}</section>
  </>
}

function SystemPage({ model, offline, onRefresh }: { model: ModelInfo | null; offline: boolean; onRefresh: () => void }) {
  return <><div className="view-header"><div className="eyebrow">SYSTEM TRANSPARENCY</div><h1>Model & infrastructure</h1><p>Inspect the exact inference model, deployment posture, and known scientific limitations.</p></div>
    <div className="system-cards"><article className="panel system-card"><div className="system-card-top"><IconBox color="teal"><ServerCog size={23}/></IconBox><Pill variant={offline ? 'danger' : 'success'}>{offline ? 'Disconnected' : 'Connected'}</Pill></div><h3>FastAPI service</h3><p>Private inference and analysis endpoints</p><div className="config-row thin"><span>Connection</span><strong>{offline ? 'Unavailable' : 'Responding'}</strong></div><div className="config-row thin"><span>Scope</span><strong>Private API</strong></div></article>
      <article className="panel system-card"><div className="system-card-top"><IconBox color="blue"><Database size={23}/></IconBox><Pill variant={offline ? 'danger' : 'success'}>{offline ? 'Unknown' : 'Connected'}</Pill></div><h3>PostgreSQL</h3><p>Analysis history & summarized findings</p><div className="config-row thin"><span>Stored</span><strong>Run metadata</strong></div><div className="config-row thin"><span>Raw measurements</span><strong>Not persisted</strong></div></article>
      <article className="panel system-card"><div className="system-card-top"><IconBox color="violet"><Fingerprint size={23}/></IconBox><Pill variant="warning">Research only</Pill></div><h3>Inference model</h3><p>Frozen three-phase integrity detector</p><div className="config-row thin"><span>Features</span><strong>{model?.features ?? '—'}</strong></div><div className="config-row thin"><span>Confirmation</span><strong>{model?.confirmation_rows ?? '—'} rows</strong></div></article></div>
    <div className="system-lower"><section className="panel architecture-panel"><div className="panel-head"><div><div className="eyebrow">DATA FLOW</div><h3>How an analysis works</h3></div><button className="icon-button" aria-label="Check service" onClick={onRefresh}><RefreshCw size={16}/></button></div>
      <div className="pipeline"><div><div className="pipeline-icon"><FileUp size={22}/></div><strong>Import</strong><small>CSV / JSON</small></div><ArrowRight size={19}/><div><div className="pipeline-icon"><Gauge size={22}/></div><strong>Validate</strong><small>Schema & time</small></div><ArrowRight size={19}/><div><div className="pipeline-icon"><Waves size={22}/></div><strong>Assess</strong><small>Frozen model</small></div><ArrowRight size={19}/><div><div className="pipeline-icon"><Database size={22}/></div><strong>Store</strong><small>Findings only</small></div></div>
      <div className="model-facts"><div><span>Model ID</span><code>{model?.model_id ?? 'Not loaded'}</code></div><div><span>Training examples</span><strong>{model?.training_rows ?? '—'}</strong></div><div><span>Calibration examples</span><strong>{model?.calibration_rows ?? '—'}</strong></div><div><span>Training fingerprint</span><code>{model?.source_sha256?.slice(0,20) ?? 'Unavailable'}…</code></div></div></section>
      <section className="panel limitations-panel"><div className="eyebrow">TRUST BOUNDARIES</div><h3>What the detector cannot prove</h3><p>Review these limitations before interpreting findings or sharing results.</p><div className="limitation-list">{(model?.limitations ?? ['Model data unavailable. Connect the private backend to inspect current limitations.']).map((item, i) => <div key={i}><CircleAlert size={16}/><span>{item}</span></div>)}</div><div className="warning-banner"><LockKeyhole size={19}/><div><strong>No operational authority</strong><p>This system never commands grid equipment or declares an authenticated intrusion.</p></div></div></section></div>
  </>
}

const SCENARIO_LABELS: Record<string, string> = {
  S0_benign_baseline: 'S0 · Clean holdout',
  S1_industroyer_pv: 'S1 · PV Modbus',
  S2_industroyer_bss: 'S2 · Battery Modbus',
  S3_arp_spoof_bss_meter_half_values: 'S3 · Battery MITM',
  S4_arp_spoof_loads_pv_two_phase: 'S4 · Loads/PV MITM',
  S5_arp_spoof_loads_pv_bss_two_phase: 'S5 · Multi-meter MITM',
  S6_mqtt_supply_chain_compromise: 'S6 · MQTT compromise',
}

function EvidencePage({ evidence, protocol, sensitivity, arp, fourLane, priceContext }: { evidence: ResearchEvidence | null; protocol: ProtocolResearch | null; sensitivity: ProtocolSensitivity | null; arp: ARPResearch | null; fourLane: FourLaneResearch | null; priceContext: PriceContextResearch | null }) {
  const scenarios = (evidence?.records ?? []).filter((item): item is EvidenceScenario =>
    'scenario' in item && item.scenario in SCENARIO_LABELS)
  const clean = scenarios.find(item => item.scenario === 'S0_benign_baseline')
  const mitm = scenarios.find(item => item.scenario === 'S4_arp_spoof_loads_pv_two_phase')
  const pct = (value?: number) => value == null ? '—' : `${(value * 100).toFixed(2)}%`
  return <>
    <div className="view-header"><div className="eyebrow">HISTORICAL RESEARCH · 26 OCT 2026</div><h1>Research evidence</h1><p>Replayed frozen-model outcomes on previously studied public records, with blind-validation boundaries and failures shown alongside the strong results.</p></div>
    <div className="evidence-alert"><CircleAlert size={21}/><div><strong>These are not live performance guarantees.</strong><p>The model architecture was selected after inspecting earlier Data4Cyber tests. Attack-activity labels do not prove each power reading was manipulated, and the short clean holdout cannot establish a prospective false-alarm rate.</p></div></div>
    <div className="metrics-grid">
      <MetricCard label="S4 exploratory row F1" value={pct(mitm?.row_f1)} sub="Previously observed MITM scenario" icon={<ShieldCheck size={20}/>} color="teal" />
      <MetricCard label="S0 clean false episodes" value={clean?.false_alarm_episodes ?? '—'} sub="In 360 seconds of held-out S0" icon={<CircleAlert size={20}/>} color="amber" />
      <MetricCard label="S4 unusable readings" value={mitm?.invalid_rows ?? '—'} sub="Abstained due to missing/invalid input" icon={<RadioTower size={20}/>} color="violet" />
      <MetricCard label="Blind independent MITM" value="Pending" sub="New independent campaign required" icon={<LockKeyhole size={20}/>} color="blue" />
    </div>
    {fourLane?.records?.length ? <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 36 · FOUR-LANE POSTHOC FUSION</div><h3>Complementary attack-family coverage — macro F1 {pct(fourLane.macro_f1)}</h3><p>Replayed the frozen meter head with five-second Modbus writer evidence, two-second ARP identity claims, and S0-calibrated price novelty. These are separately recorded research signals, not the deployed detector.</p></div><Pill variant="warning">Not independently validated</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>Meter F1</th><th>Modbus F1</th><th>ARP F1</th><th>Price F1</th><th>Four-lane F1</th><th>Benign FPR</th><th>False alert episodes</th></tr></thead><tbody>{fourLane.records.map(r => <tr key={r.scenario}><td><div className="event-primary">{SCENARIO_LABELS[r.scenario] ?? 'S1-alt · PV Modbus'}</div></td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.physics.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.modbus_source_hold5.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.arp_claim_hold2.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.price_domain.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.four_lane_or.f1)}</td><td>{pct(r.four_lane_or.clean_fpr)}</td><td>{r.clean_alert_episodes.episodes}</td></tr>)}</tbody></table></div>
      {Object.keys(fourLane.ablation ?? {}).length > 0 && <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Lane removed</th><th>Macro F1 without lane</th><th>Attack rows uniquely found by lane</th><th>Benign rows alerted only by lane</th></tr></thead><tbody>{Object.entries(fourLane.ablation).map(([name, row]) => <tr key={name}><td>{name.replaceAll('_', ' ')}</td><td>{pct(row.macro_f1_without_lane)}</td><td>{row.exclusive_attack_rows_across_S1_S6.toLocaleString()}</td><td>{row.exclusive_benign_alert_rows_across_S1_S6.toLocaleString()}</td></tr>)}</tbody></table></div>}
      {fourLane.records.some(r => r.false_alert_temporal_attribution) && <><div className="panel-head"><div><div className="eyebrow">PHASE 38 · FALSE-ALARM TIME CONTEXT</div><h3>How far are false alerts from labeled attack periods?</h3><p>Every false alert remains counted in the primary false-positive rate. Boundary proximity is descriptive, not a justification for suppressing an alarm or altering its label.</p></div><Pill variant="warning">Same campaigns</Pill></div>
        <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>All false-alert rows</th><th>Within 5s</th><th>5–30s away</th><th>Over 30s away</th><th>Far-from-attack clean alert rate</th></tr></thead><tbody>{fourLane.records.map(r => { const t = r.false_alert_temporal_attribution; return <tr key={r.scenario}><td>{SCENARIO_LABELS[r.scenario] ?? 'S1-alt · PV Modbus'}</td><td>{t?.false_alert_rows_total ?? '—'}</td><td>{t?.within_5_seconds ?? '—'}</td><td>{t?.between_5_and_30_seconds ?? '—'}</td><td>{t?.farther_than_30_seconds ?? '—'}</td><td>{pct(t?.far_clean_alert_rate ?? undefined)}</td></tr> })}</tbody></table></div></>}
      <p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> {fourLane.warning} Four-lane macro F1 is an exploratory *within-dataset* result, not independently measured site-level reliability. Ablation counts are from previously examined campaigns.</p>
    </section> : null}
    {priceContext && <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 45 · CONTEXT VS SECURITY</div><h3>Pricing anomalies are not authenticated attack evidence</h3><p>Two separate research review channels preserve price context while showing what happens if only meter, Modbus and ARP evidence counts toward security reviews.</p></div><Pill variant="warning">Post-hoc tradeoff</Pill></div>
      <div className="metrics-grid" style={{ padding: '0 24px 16px' }}>
        <MetricCard label="All-four-lane macro F1" value={pct(priceContext.full_or_macro_f1)} sub="Historical OR fusion" icon={<ShieldCheck size={20}/>} color="teal" />
        <MetricCard label="Security-only macro F1" value={pct(priceContext.security_only_macro_f1)} sub="Price shown as context only" icon={<ShieldAlert size={20}/>} color="amber" />
        <MetricCard label="Price-only attack rows" value={priceContext.price_exclusive_attack_rows_not_security_alerted} sub="Not security-alerted under separation" icon={<RadioTower size={20}/>} color="violet" />
        <MetricCard label="Price-only benign alerts" value={priceContext.price_exclusive_benign_alert_rows_not_security_alerted} sub="Removed from security alert stream" icon={<CircleAlert size={20}/>} color="blue" />
      </div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>Original F1</th><th>Security-only F1</th><th>Price-only attack rows</th><th>Price-only benign alerts</th></tr></thead><tbody>{priceContext.scenarios.map(r => <tr key={r.scenario}><td>{SCENARIO_LABELS[r.scenario] ?? r.scenario}</td><td>{pct(r.full_or_f1)}</td><td>{pct(r.security_only_f1)}</td><td>{r.price_only_attack_review_rows.toLocaleString()}</td><td>{r.price_only_benign_review_rows}</td></tr>)}</tbody></table></div>
      <div className="panel-head"><div><div className="eyebrow">PHASE 44 · SYNTHETIC BENIGN TARIFF CHANGES</div><h3>Frozen price-rule false reviews</h3><p>Actual S0 benign prices with an artificial constant offset. These are not additional attacks or observed real tariffs.</p></div><Pill variant="warning">Price lane only</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Simulated price offset</th><th>Benign false reviews</th><th>False-review fraction</th></tr></thead><tbody>{priceContext.benign_price_offset_stress.map(r => <tr key={r.additive_shift_eur_per_kwh}><td>{r.additive_shift_eur_per_kwh >= 0 ? '+' : '−'}€{Math.abs(r.additive_shift_eur_per_kwh).toFixed(2)}/kWh</td><td>{r.false_review_seconds}/{r.observed_benign_seconds}</td><td>{pct(r.benign_false_review_fraction)}</td></tr>)}</tbody></table></div>
      <p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> {priceContext.warning} Security-only misses most S6 labelled activity; price context must remain visible pending authenticated tariff provenance.</p>
    </section>}
    <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">FROZEN REPLAY · DATA4CYBER V3</div><h3>Scenario-by-scenario outcomes</h3><p>Exactly the model served by this application; threshold and model parameters unchanged.</p></div><Pill variant="warning">Exploratory</Pill></div>
      {scenarios.length ? <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>F1 (rows)</th><th>Recall (rows)</th><th>Clean FPR (rows)</th><th>Detected activity episodes</th><th>False episodes</th></tr></thead><tbody>
        {scenarios.map(item => <tr key={item.scenario}><td><div className="event-primary">{SCENARIO_LABELS[item.scenario]}</div></td><td>{item.scenario.startsWith('S0_') ? 'N/A' : pct(item.row_f1)}</td><td>{item.scenario.startsWith('S0_') ? 'N/A' : pct(item.row_recall)}</td><td>{pct(item.clean_row_fpr)}</td><td>{item.attack_episodes ? `${item.detected_attack_episodes ?? 0} / ${item.attack_episodes}` : 'N/A'}</td><td>{item.false_alarm_episodes ?? '—'}</td></tr>)}
      </tbody></table></div> : <EmptyState icon={<Database size={25}/>} title="Evidence bundle unavailable" body="Connect to the upgraded backend to load its embedded, frozen research benchmark." />}
    </section>
    <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 24 · PASSIVE MODBUS COMMAND SOURCE</div><h3>A complementary detection lane</h3><p>Historical comparison of frozen physics scoring and source-role discrepancies in the public packet captures. No automatic network response.</p></div><Pill variant="warning">IP not authenticated</Pill></div>
      {protocol?.records?.length ? <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>Physics F1</th><th>Modbus source F1</th><th>Combined OR F1</th><th>Unexpected writes</th><th>Source-lane clean FPR</th></tr></thead><tbody>
        {protocol.records.filter(r => ['S0_benign_baseline','S1_industroyer_pv','S2_industroyer_bss','S1_industroyer_pv_alt'].includes(r.scenario)).map(r => <tr key={r.scenario}><td><div className="event-primary">{r.scenario === 'S1_industroyer_pv_alt' ? 'S1-alt · Reserved PV Modbus' : (SCENARIO_LABELS[r.scenario] ?? r.scenario)}</div></td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.physics.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.unexpected_modbus_writer.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.two_lane_or.f1)}</td><td>{r.unexpected_write_count}</td><td>{pct(r.unexpected_modbus_writer.clean_fpr)}</td></tr>)}
      </tbody></table></div> : <div className="inline-empty">Additional protocol evidence requires the upgraded backend.</div>}
      <p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> The source address can be spoofed; role mapping is not cryptographic provenance. Blind new-site validation is still pending.</p>
    </section>
    {sensitivity && <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">EXPLORATORY TEMPORAL SENSITIVITY · NOT DEPLOYED</div><h3>Five-second event persistence</h3><p>Alternative policy applied after examining these campaign families, shown only to expose the false-alarm tradeoff.</p></div><Pill variant="warning">Not validated</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>Activity F1</th><th>Activity recall</th><th>Benign-row alert rate</th></tr></thead><tbody>{sensitivity.records.filter(r => r.tp > 0).map(r => {
        const f1 = 2*r.tp / Math.max(1,2*r.tp+r.fp+r.fn)
        const recall = r.tp / Math.max(1,r.tp+r.fn)
        return <tr key={r.scenario}><td>{r.scenario.includes('_alt') ? 'S1-alt · PV Modbus' : (SCENARIO_LABELS[r.scenario] ?? r.scenario)}</td><td>{pct(f1)}</td><td>{pct(recall)}</td><td>{pct(r.clean_row_fpr)}</td></tr>
      })}</tbody></table></div><p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> {sensitivity.warning}</p>
    </section>}
    {arp?.records?.length ? <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 25 · ARP IDENTITY CLAIMS</div><h3>Coordinated MITM: a complementary network signal</h3><p>Published S0 IP/MAC inventory compared with recorded ARP claims. These are spoofable source claims, not verified device identities.</p></div><Pill variant="warning">Historical</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>Physics F1</th><th>ARP F1</th><th>OR F1</th><th>OR clean FPR</th><th>5-s OR F1</th></tr></thead><tbody>{arp.records.map(r => {
        const held=arp.hold5_sensitivity.find(x => x.scenario===r.scenario)
        return <tr key={r.scenario}><td>{SCENARIO_LABELS[r.scenario] ?? r.scenario}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.physics.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.arp_source_consistency.f1)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.two_lane_or.f1)}</td><td>{pct(r.two_lane_or.clean_fpr)}</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(held?.two_lane_or.f1)}</td></tr>
      })}</tbody></table></div>
      <p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> {arp.warning} A five-second sensitivity improves apparent row coverage but increases false alerts.</p>
    </section> : null}
    {arp?.policy_sweep?.length ? <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 26 · POSTHOC POLICY SWEEP</div><h3>ARP persistence versus false alarms</h3><p>Comparing 0–5 seconds of historical alert persistence, including benign-row alerts. Two seconds performs better than five on S5 here; neither is approved for deployment.</p></div><Pill variant="warning">Not validated</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Scenario</th><th>Persistence</th><th>Combined F1</th><th>Benign alert rate</th><th>False alert seconds</th><th>Clean alert episodes</th><th>S5 phase 2 coverage</th></tr></thead><tbody>{arp.policy_sweep.filter(r => [0,2,5].includes(r.arp_hold_seconds)).map(r => {
        const phase=r.per_phase['s5_mitm_phase_2']
        return <tr key={`${r.scenario}-${r.arp_hold_seconds}`}><td>{SCENARIO_LABELS[r.scenario] ?? r.scenario}</td><td>{r.arp_hold_seconds} s</td><td>{r.scenario.startsWith('S0_') ? 'N/A' : pct(r.combined.f1)}</td><td>{pct(r.combined.clean_fpr)}</td><td>{r.combined.fp}</td><td>{r.clean_alert_burden.episodes}</td><td>{phase ? `${phase.or_detected_seconds}/${phase.labeled_seconds}` : '—'}</td></tr>
      })}</tbody></table></div><p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> All policy variants use examined campaigns. S0 showed no ARP identity mismatches; benign samples within attack runs are not equivalent to independent clean-network validation.</p>
    </section> : null}
    {arp?.negative_controls?.length ? <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 27 · NON-ARP NEGATIVE CONTROLS</div><h3>Cross-family ARP false-alert audit</h3><p>Captured ARP traffic from S0, S1, S1-alt, S2, and S6 tests whether the MITM-specific evidence fires in unrelated attack campaigns. These captures share the same research environment.</p></div><Pill variant="warning">Within dataset</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Control scenario</th><th>Observed ARP packets</th><th>IP/MAC mismatches</th><th>Clean seconds</th><th>2-s ARP alerts</th><th>Clean ARP alert rate</th></tr></thead><tbody>{arp.negative_controls.filter(r => r.arp_hold_seconds===2).map(r => <tr key={r.scenario}><td>{r.scenario.includes('_alt') ? 'S1-alt · PV Modbus' : (SCENARIO_LABELS[r.scenario] ?? r.scenario)}</td><td>{r.arp_packets_observed.toLocaleString()}</td><td>{r.known_ip_mac_mismatch_packets}</td><td>{r.clean_seconds.toLocaleString()}</td><td>{r.arp_alert_seconds_total}</td><td>{pct(r.clean_row_alert_rate)}</td></tr>)}</tbody></table></div>
      <p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> Zero observed mismatches across these controls does not establish a zero real-world false-positive rate; inventory changes and unseen networks are untested.</p>
    </section> : null}
    {arp?.uncertainty ? <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 28 · ZERO-ALERT UNCERTAINTY</div><h3>Why zero observed alerts is not a zero-risk guarantee</h3><p>Exact one-sided 95% formulas under different hypothetical independent trial units. Shared topology, correlated traffic and post-hoc design violate the assumptions needed for field guarantees.</p></div><Pill variant="warning">Assumptions not met</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>Hypothetical independent unit</th><th>Zero-event observations</th><th>Conditional 95% upper probability</th></tr></thead><tbody>
        <tr><td>One clean second</td><td>{arp.uncertainty.observed_clean_seconds.toLocaleString()}</td><td>{pct(arp.uncertainty.hypothetical_iid_per_second_upper_rate)}</td></tr>
        <tr><td>One ARP packet</td><td>{arp.uncertainty.observed_arp_packets.toLocaleString()}</td><td>{pct(arp.uncertainty.hypothetical_iid_per_packet_upper_mismatch_rate)}</td></tr>
        <tr><td>One entire scenario</td><td>{arp.uncertainty.observed_scenarios}</td><td>{pct(arp.uncertainty.hypothetical_independent_scenario_upper_event_probability)}</td></tr>
      </tbody></table></div><p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> These figures are mathematical assumption sensitivity, not confidence intervals validated for real sites. Prospective multi-site benign measurements are still required.</p>
    </section> : null}
    {arp?.identity_ambiguity ? <section className="panel evidence-panel"><div className="panel-head"><div><div className="eyebrow">PHASE 32 · SYNTHETIC IDENTIFIABILITY TEST</div><h3>Maintenance or MITM? ARP claims alone cannot tell</h3><p>The same observed IP/MAC-change announcements are replayed under two different hidden realities: authorized NIC replacement or attacker impersonation. A deterministic ARP-only rule must return the same alerts.</p></div><Pill variant="warning">Synthetic only</Pill></div>
      <div className="table-scroll"><table className="data-table history-table"><thead><tr><th>ARP persistence</th><th>Benign-maintenance false alert seconds</th><th>Spoofing attack detected seconds</th><th>Observed claims identical?</th></tr></thead><tbody>{arp.identity_ambiguity.records.map(r => <tr key={r.hold_seconds}><td>{r.hold_seconds} s</td><td>{r.synthetic_maintenance_false_alert_seconds}</td><td>{r.synthetic_spoof_attack_detected_seconds}/{r.synthetic_attack_labeled_seconds}</td><td>{r.identical_arp_observations ? 'Yes' : 'No'}</td></tr>)}</tbody></table></div>
      <p className="run-disclaimer" style={{ padding: '0 24px 20px' }}><CircleAlert size={14}/> {arp.identity_ambiguity.requirement} These are generated examples, not additional field-dataset measurements.</p>
    </section> : null}
    <div className="evidence-context">
      <section className="panel insight-panel"><div className="eyebrow">WHAT WORKS</div><h3>Targeted phase/total mismatch review</h3><p>On the main S4 MITM manipulation interval, the first review appeared four seconds after labeled onset. The earlier, undetected 10-second episode is specifically reconnaissance, outside this physics-only detector’s scope.</p></section>
      <section className="panel insight-panel"><div className="eyebrow">WHAT DOES NOT</div><h3>Coherent changes can bypass it</h3><p>Modbus and MQTT row-level recall remains poor. S5 MITM phase 2 fell to just 16.84% recall (98/582 labeled rows). A controlled synthetic test changing both total power and phases produced no alarms. An independent provenance-aware lane remains necessary.</p></section>
    </div>
    <p className="run-disclaimer"><Shield size={14}/> Source data and all scenario-level metrics are encoded in the reproducible Phase 22 benchmark included with this delivery.</p>
  </>
}

function AnalysisDrawer({ analysis, onClose }: { analysis: Analysis | null; onClose: () => void }) {
  if (!analysis) return null
  return <div className="drawer-scrim" onClick={onClose}><aside className="drawer" onClick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Analysis details"><div className="drawer-head"><div><div className="eyebrow">RUN DETAILS</div><h2>Analysis report</h2></div><button className="icon-button" aria-label="Close report" onClick={onClose}><X size={21}/></button></div><div className="drawer-body"><Pill variant="warning"><Shield size={13}/> Research assessment</Pill><h3 className="drawer-source">{analysis.source_name}</h3><p className="drawer-date">{formatTime(analysis.created_at)} · Run {analysis.id.slice(0,8)}</p><div className="drawer-metrics"><div><strong>{analysis.observation_count}</strong><span>Rows evaluated</span></div><div><strong>{analysis.review_count}</strong><span>Review rows</span></div><div><strong>{analysis.abstention_count}</strong><span>Abstentions</span></div></div><div className="drawer-section-title">Recorded findings</div>{analysis.findings?.length ? <div className="finding-stack">{analysis.findings.map(f => <div className="finding-card" key={f.id}><div className="finding-card-header"><Pill variant={f.kind === 'ABSTAIN' ? 'neutral' : 'warning'}>{f.kind === 'ABSTAIN' ? 'Abstained' : 'Review signal'}</Pill><small>{formatTime(f.timestamp)}</small></div><strong>{displaySignal(f.identity_name)}</strong><p>{f.reason}</p>{f.score != null && <span className="finding-score">Normalized score {f.score.toFixed(2)}</span>}</div>)}</div> : <EmptyState icon={<ShieldCheck size={26}/>} title="No stored review signals" body="This run produced no confirmed local mismatches or abstentions."/>}</div><div className="drawer-footer"><div><CircleHelp size={17}/> A review does not establish a cyberattack.</div><button className="secondary-button" onClick={onClose}>Close report</button></div></aside></div>
}

export default function App() {
  const [authorized, setAuthorized] = useState(false)
  const [loginToken, setLoginToken] = useState('')
  const [loginError, setLoginError] = useState('')
  const [loggingIn, setLoggingIn] = useState(false)
  const [view, setView] = useState<View>('overview')
  const [overview, setOverview] = useState<Overview>(EMPTY_OVERVIEW)
  const [analyses, setAnalyses] = useState<Analysis[]>([])
  const [model, setModel] = useState<ModelInfo | null>(null)
  const [evidence, setEvidence] = useState<ResearchEvidence | null>(null)
  const [protocol, setProtocol] = useState<ProtocolResearch | null>(null)
  const [sensitivity, setSensitivity] = useState<ProtocolSensitivity | null>(null)
  const [arp, setArp] = useState<ARPResearch | null>(null)
  const [fourLane, setFourLane] = useState<FourLaneResearch | null>(null)
  const [priceContext, setPriceContext] = useState<PriceContextResearch | null>(null)
  const [offline, setOffline] = useState(true)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Analysis | null>(null)
  const [toast, setToast] = useState('')
  const [mobileNav, setMobileNav] = useState(false)

  const refresh = useCallback(async () => {
    const [ready, ov, history, info, benchmark, traffic, temporal, arpEvidence, fusionEvidence, priceEvidence] = await Promise.allSettled([
      api.readiness(), api.overview(), api.analyses(), api.model(), api.researchEvidence(), api.protocolEvidence(), api.protocolSensitivity(), api.arpResearch(), api.fourLaneResearch(), api.priceContextResearch(),
    ])
    setOffline(ready.status !== 'fulfilled')
    if (ov.status === 'fulfilled') setOverview(ov.value)
    if (history.status === 'fulfilled') setAnalyses(history.value)
    if (info.status === 'fulfilled') setModel(info.value)
    if (benchmark.status === 'fulfilled') setEvidence(benchmark.value)
    if (traffic.status === 'fulfilled') setProtocol(traffic.value)
    if (temporal.status === 'fulfilled') setSensitivity(temporal.value)
    if (arpEvidence.status === 'fulfilled') setArp(arpEvidence.value)
    if (fusionEvidence.status === 'fulfilled') setFourLane(fusionEvidence.value)
    if (priceEvidence.status === 'fulfilled') setPriceContext(priceEvidence.value)
    setLoading(false)
  }, [])
  useEffect(() => { if (authorized) void refresh() }, [authorized, refresh])
  useEffect(() => { if (toast) { const timer = window.setTimeout(() => setToast(''), 5500); return () => window.clearTimeout(timer) } }, [toast])
  const activeNav = useMemo(() => nav.find(item => item.view === view), [view])
  const navigate = (v: View) => { setView(v); setMobileNav(false); window.scrollTo({ top: 0, behavior: 'smooth' }) }
  const open = async (id: string) => {
    try { setSelected(await api.analysis(id)) }
    catch (err) { setToast(err instanceof Error ? err.message : 'Could not open analysis') }
  }
  const complete = (analysis: Analysis) => {
    setToast(`Analysis complete · ${analysis.review_count} review rows · ${analysis.abstention_count} abstentions`)
    void refresh(); navigate('history');void open(analysis.id)
  }
  const login = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!loginToken.trim()) return
    setLoggingIn(true)
    setLoginError('')
    setPrivateAccessToken(loginToken.trim())
    try {
      await api.model() // Authenticated API endpoint; read-only credential check.
      setAuthorized(true)
      setLoginToken('')
    } catch (error) {
      clearPrivateAccessToken()
      setLoginError(error instanceof Error ? error.message : 'Could not verify private access')
    } finally { setLoggingIn(false) }
  }
  const logout = () => {
    clearPrivateAccessToken()
    setAuthorized(false)
    setOffline(true)
    setSelected(null)
    setAnalyses([])
    setOverview(EMPTY_OVERVIEW)
  }
  if (!authorized) return <div className="login-screen"><form className="login-panel" onSubmit={e => void login(e)}>
    <Mark size={46}/><div className="eyebrow">PRIVATE RESEARCH WORKSPACE</div>
    <h1>Unlock Grid Sentinel</h1><p>Enter the private access token configured on your own Docker host. It stays in this browser tab's memory and is cleared when you reload or sign out.</p>
    <label htmlFor="private-token">Private access token</label>
    <input id="private-token" type="password" autoComplete="off" spellCheck={false} value={loginToken}
      onChange={e => setLoginToken(e.target.value)} placeholder="Token from your local .env" required minLength={32}/>
    {loginError && <div className="login-error" role="alert">{loginError}</div>}
    <button className="primary-button" type="submit" disabled={loggingIn || loginToken.trim().length < 32}>
      <LockKeyhole size={17}/>{loggingIn ? 'Verifying...' : 'Enter private workspace'}</button>
    <small>Research-only system · Keep bound to localhost · No operational grid control</small>
  </form></div>
  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}><div className="sidebar-top"><Mark/><div className="brand-text">GRID<span>SENTINEL</span><small>CYBER-PHYSICAL RESEARCH</small></div><button className="mobile-close icon-button" onClick={() => setMobileNav(false)}><X size={19}/></button></div>
      <div className="workspace-selector"><div className="workspace-avatar"><Zap size={16}/></div><span><strong>Research workspace</strong><small>Private · Local environment</small></span><ChevronDown size={15}/></div>
      <div className="nav-label">WORKSPACE</div><nav className="sidebar-nav">{nav.map(({ view: target, icon: Icon, label }) => <button key={target} className={`nav-item ${view === target ? 'active' : ''}`} onClick={() => navigate(target)}><Icon size={19}/><span>{label}</span>{view === target && <span className="nav-indicator"/>}</button>)}</nav>
      <div className="sidebar-spacer"/><div className="sidebar-guard"><div className="guard-orb"><ShieldCheck size={19}/></div><div><strong>Protected by design</strong><p>Private research mode.<br/>No automated grid control.</p></div><div className="guard-status"><span className="status-dot"/> SAFE OPERATING SCOPE</div></div>
      <div className="sidebar-foot"><div className="foot-avatar">GS</div><div><strong>Grid Sentinel</strong><span>Research environment · v1.0</span></div><MoreHorizontal size={19}/></div>
    </aside>
    {mobileNav && <div className="mobile-scrim" onClick={() => setMobileNav(false)}/>}
    <main className="main-content"><header className="topbar"><div className="topbar-left"><button className="mobile-menu icon-button" onClick={() => setMobileNav(true)}><Menu size={21}/></button><div className="breadcrumb">Workspace <ChevronRight size={14}/> <strong>{activeNav?.label}</strong></div></div><div className="topbar-right"><span className={`connection ${offline ? 'connection-offline' : ''}`}><span className="connection-dot"/>{offline ? 'Backend offline' : 'Private API connected'}</span><div className="topbar-divider"/><button className="icon-button" aria-label="Refresh dashboard" onClick={() => void refresh()}><RefreshCw size={17}/></button><button className="icon-button" aria-label="Sign out" title="Sign out" onClick={logout}><LockKeyhole size={17}/></button><div className="header-avatar">GS</div></div></header>
      <div className="main-scroll"><div className="content-container">
        {offline && !loading && <div className="offline-banner"><CloudOff size={18}/><div><strong>Backend connection unavailable</strong><span>The dashboard can still be explored. Start FastAPI and PostgreSQL to view saved results or run analyses.</span></div><button onClick={() => void refresh()}>Retry <RefreshCw size={14}/></button></div>}
        {view === 'overview' && <OverviewPage overview={overview} analyses={analyses} offline={offline} onNavigate={navigate} onOpen={id => void open(id)} onRefresh={() => void refresh()}/>}
        {view === 'analysis' && <AnalysisLab onComplete={complete}/>}
        {view === 'history' && <HistoryPage analyses={analyses} onOpen={id => void open(id)} onNew={() => navigate('analysis')}/>}
        {view === 'evidence' && <EvidencePage evidence={evidence} protocol={protocol} sensitivity={sensitivity} arp={arp} fourLane={fourLane} priceContext={priceContext}/>} 
        {view === 'system' && <SystemPage model={model} offline={offline} onRefresh={() => void refresh()}/>}
        <footer className="page-footer"><span>© 2026 Grid Sentinel · Private research operations</span><span><Shield size={13}/> Detector signals are not verified intrusion claims</span></footer>
      </div></div>
    </main>
    <AnalysisDrawer analysis={selected} onClose={() => setSelected(null)}/>
    {toast && <div className="toast"><CheckCircle2 size={19}/><span>{toast}</span><button onClick={() => setToast('')}><X size={16}/></button></div>}
  </div>
}
