import React, { useMemo } from 'react'

const COLORS = { ip: '#c62828', user: '#1565c0', ua: '#6a1b9a', honeytoken: '#e65100', alert: '#757575', target: '#2e7d32', url: '#ad1457', session: '#00838f' }

// very simple layout: start on a circle, then a few rounds of "push apart / pull together"
function layout(nodes, edges, w, h) {
  const pos = {}
  nodes.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(nodes.length, 1)
    pos[n.id] = { x: w / 2 + Math.cos(a) * (w / 3), y: h / 2 + Math.sin(a) * (h / 3) }
  })
  for (let it = 0; it < 80; it++) {
    for (const a of nodes) for (const b of nodes) {
      if (a.id >= b.id) continue
      const dx = pos[a.id].x - pos[b.id].x, dy = pos[a.id].y - pos[b.id].y
      const d = Math.max(Math.hypot(dx, dy), 1)
      const f = 2200 / (d * d)
      pos[a.id].x += (dx / d) * f; pos[a.id].y += (dy / d) * f
      pos[b.id].x -= (dx / d) * f; pos[b.id].y -= (dy / d) * f
    }
    for (const e of edges) {
      const p = pos[e.source], q = pos[e.target]
      if (!p || !q) continue
      const dx = q.x - p.x, dy = q.y - p.y
      const d = Math.max(Math.hypot(dx, dy), 1)
      const f = (d - 90) * 0.02
      p.x += (dx / d) * f; p.y += (dy / d) * f
      q.x -= (dx / d) * f; q.y -= (dy / d) * f
    }
    for (const n of nodes) {
      pos[n.id].x = Math.min(w - 30, Math.max(30, pos[n.id].x))
      pos[n.id].y = Math.min(h - 20, Math.max(20, pos[n.id].y))
    }
  }
  return pos
}

export default function GraphView({ nodes = [], edges = [], height = 380 }) {
  const w = 800
  const pos = useMemo(() => layout(nodes, edges, w, height), [nodes, edges, height])
  if (!nodes.length) return <p className="muted">Nothing to draw yet.</p>
  const types = [...new Set(nodes.map((n) => n.type))]
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${height}`} className="w-full border border-gray-300 bg-white" style={{ maxHeight: height }}>
        {edges.map((e, i) => pos[e.source] && pos[e.target] && (
          <line key={i} x1={pos[e.source].x} y1={pos[e.source].y} x2={pos[e.target].x} y2={pos[e.target].y} stroke="#aaa" />
        ))}
        {nodes.map((n) => (
          <g key={n.id}>
            <circle cx={pos[n.id].x} cy={pos[n.id].y} r={n.type === 'alert' ? 5 : 9} fill={COLORS[n.type] || '#555'} />
            {n.type !== 'alert' && (
              <text x={pos[n.id].x + 11} y={pos[n.id].y + 4} fontSize="11" fill="#222">
                {String(n.label).slice(0, 24)}
              </text>
            )}
            <title>{n.label}</title>
          </g>
        ))}
      </svg>
      <div className="text-xs mt-1">
        {types.map((t) => (
          <span key={t} className="mr-3"><span style={{ color: COLORS[t] }}>●</span> {t}</span>
        ))}
      </div>
    </div>
  )
}
