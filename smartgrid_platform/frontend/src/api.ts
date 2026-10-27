import type { Analysis, MeasurementRecord, ModelInfo, Overview, Readiness, ResearchEvidence, ProtocolResearch, ProtocolSensitivity, ARPResearch, FourLaneResearch, PriceContextResearch } from './types'

// Credentials exist only in this browser tab's JS memory, never localStorage,
// bundle source, URL parameters, database, or a cookie.
let privateAccessToken = ''
export const setPrivateAccessToken = (token: string) => { privateAccessToken = token }
export const clearPrivateAccessToken = () => { privateAccessToken = '' }

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json',
        ...(privateAccessToken ? { Authorization: `Bearer ${privateAccessToken}` } : {}),
        ...(options?.headers || {}) },
    })
  } catch {
    throw new Error('Cannot reach the private API. Check that the backend and database are running.')
  }
  if (!response.ok) {
    if (response.status === 401) throw new Error('Invalid private access token')
    const body = await response.json().catch(() => ({})) as { detail?: string | object }
    const details = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail || '')
    throw new Error(details || `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export const api = {
  overview: () => request<Overview>('/overview'),
  analyses: () => request<Analysis[]>('/analyses?limit=50'),
  analysis: (id: string) => request<Analysis>(`/analyses/${encodeURIComponent(id)}`),
  model: () => request<ModelInfo>('/model'),
  researchEvidence: () => request<ResearchEvidence>('/research-evidence'),
  protocolEvidence: () => request<ProtocolResearch>('/protocol-research'),
  protocolSensitivity: () => request<ProtocolSensitivity>('/protocol-sensitivity'),
  arpResearch: () => request<ARPResearch>('/arp-research'),
  fourLaneResearch: () => request<FourLaneResearch>('/four-lane-research'),
  priceContextResearch: () => request<PriceContextResearch>('/price-context-research'),
  readiness: () => request<Readiness>('/ready'),
  createAnalysis: (source_name: string, records: MeasurementRecord[]) =>
    request<Analysis>('/analyses', {
      method: 'POST',
      body: JSON.stringify({ source_name, records }),
    }),
}

export const formatTime = (value?: string | null) =>
  value ? new Intl.DateTimeFormat('en-IN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'

export const shortDate = (value: string) =>
  new Intl.DateTimeFormat('en-IN', { day: '2-digit', month: 'short' }).format(new Date(value + 'T12:00:00Z'))
