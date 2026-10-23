import React from 'react'

export function Tier({ tier }) {
  return <span className={`badge tier-${tier}`}>{tier}</span>
}

// small "Auto" / "Manual" marker for how an incident was handled
export function Mode({ mode }) {
  if (!mode) return <span className="muted">-</span>
  return <span className={`modetag ${mode === 'auto' ? 'auto' : ''}`}>{mode === 'auto' ? 'Auto' : 'Manual'}</span>
}

export const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : '-')

// backend escapes some characters (&#x27; etc.) for safety, show them normally
export const dec = (t) => { const e = document.createElement('textarea'); e.innerHTML = t; return e.value }
