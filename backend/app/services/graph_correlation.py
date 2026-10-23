"""
NetworkX secondary correlation (workflow step 9.5)
Owner: Nidhi

The primary correlator (correlation.py) groups alerts by "same IP or same user inside 30 minutes".
That misses an attacker who rotates IPs and comes back later. This job runs periodically
(not per event) over the alerts of the last GRAPH_LOOKBACK_HOURS and:

  1. builds a graph whose nodes are IPs, users, user agents, honeytokens and sessions,
     with an edge whenever two of them were "seen together" in the same alert
  2. takes the connected components - everything in one component is one actor/campaign
  3. if a component spans more than one incident, merges those incidents into one
     (correlation_method = "networkx_batch") and records the multi-hop path, e.g.
        IP 198.51.100.45 -> UA sqlmap -> IP 203.0.113.88 -> honeytoken /adm...eys
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

import networkx as nx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import AlertModel, IncidentModel
from app.schemas.alert import StandardAlert
from app.services.correlation import refresh_incident, maybe_auto_respond

COMMON_UA_LIMIT = 4   # a user agent used by more IPs than this is too generic to link on


def _to_schema(a: AlertModel) -> StandardAlert:
    return StandardAlert(alert_id=a.id, event_id=a.event_id, detector=a.detector, category=a.category,
                         severity=a.severity, confidence=a.confidence, source_ip=a.source_ip, user_id=a.user_id,
                         target=a.target, timestamp=a.timestamp, title=a.title, evidence=a.evidence or {},
                         recommended_action=a.recommended_action, incident_id=a.incident_id)


def _entities(a: AlertModel) -> List[str]:
    ev = a.evidence or {}
    ents = []
    if a.source_ip:
        ents.append(f"ip:{a.source_ip}")
    if a.user_id:
        ents.append(f"user:{a.user_id}")
    if ev.get("user_agent"):
        ents.append(f"ua:{str(ev['user_agent'])[:60]}")
    if ev.get("masked_honeytoken"):
        ents.append(f"honeytoken:{ev['masked_honeytoken']}")
    if ev.get("session_id"):
        ents.append(f"session:{ev['session_id']}")
    for ip in ev.get("failing_ips", []) or []:
        ents.append(f"ip:{ip}")
    return ents


def build_graph(alerts: List[AlertModel]) -> nx.Graph:
    G = nx.Graph()
    ua_ips: Dict[str, set] = {}
    for a in alerts:
        for e in _entities(a):
            if e.startswith("ua:") and a.source_ip:
                ua_ips.setdefault(e, set()).add(a.source_ip)
    generic = {u for u, ips in ua_ips.items() if len(ips) > COMMON_UA_LIMIT}

    for a in alerts:
        ents = [e for e in _entities(a) if e not in generic]
        for e in ents:
            if e not in G:
                G.add_node(e, kind=e.split(":", 1)[0], label=e.split(":", 1)[1])
        # "seen together" edges between every pair in the same alert
        for i in range(len(ents)):
            for j in range(i + 1, len(ents)):
                u, v = ents[i], ents[j]
                if G.has_edge(u, v):
                    G[u][v]["weight"] += 1
                else:
                    G.add_edge(u, v, weight=1, incidents=set())
                G[u][v].setdefault("incidents", set()).add(a.incident_id)
    return G


def _path_text(G: nx.Graph, comp: set) -> str:
    """Longest simple-ish hop chain from an IP to a honeytoken (or between two IPs)."""
    ips = [n for n in comp if n.startswith("ip:")]
    tokens = [n for n in comp if n.startswith("honeytoken:")]
    best = []
    targets = tokens or ips
    for s in ips:
        for t in targets:
            if s == t:
                continue
            try:
                path = nx.shortest_path(G, s, t)
            except nx.NetworkXNoPath:
                continue
            if len(path) > len(best):
                best = path
    if not best:
        return ""
    names = {"ip": "IP", "user": "user", "ua": "UA", "honeytoken": "honeytoken", "session": "session"}
    return " -> ".join(f"{names.get(n.split(':')[0], n.split(':')[0])} {G.nodes[n]['label']}" for n in best)


def run_graph_correlation(db: Session, lookback_hours: int = None, merge: bool = True) -> Dict[str, Any]:
    lookback_hours = lookback_hours or settings.GRAPH_LOOKBACK_HOURS
    # "recent" = incidents that received evidence in the last N hours (wall clock, i.e. when the
    # system saw it, so logs with old timestamps still count when they were uploaded just now)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    recent_ids = [i.id for i in db.query(IncidentModel).filter(IncidentModel.status.in_(["open", "escalated"])).all()
                  if (i.last_evidence_at or i.last_seen).replace(tzinfo=timezone.utc) >= cutoff]
    if not recent_ids:
        return {"components": [], "merged": 0, "nodes": [], "edges": [], "lookback_hours": lookback_hours}
    alerts = db.query(AlertModel).filter(AlertModel.incident_id.in_(recent_ids)).all()
    G = build_graph(alerts)

    comp_info, merged = [], 0
    for idx, comp in enumerate(nx.connected_components(G), 1):
        comp = set(comp)
        comp_alerts = [a for a in alerts if any(e in comp for e in _entities(a))]
        inc_ids = sorted({a.incident_id for a in comp_alerts if a.incident_id})
        ips = sorted(n.split(":", 1)[1] for n in comp if n.startswith("ip:"))
        path = _path_text(G, comp)
        info = {
            "component": idx,
            "ips": ips,
            "users": sorted(n.split(":", 1)[1] for n in comp if n.startswith("user:")),
            "incident_ids": inc_ids,
            "multi_hop_path": path,
            "ip_rotation": len(ips) > 1,
            "merged": False,
        }
        if merge and len(inc_ids) > 1:
            primary_id = _merge_incidents(db, inc_ids, path)
            if primary_id:
                info["merged"] = True
                merged += 1
                info["incident_ids"] = [primary_id]
        comp_info.append(info)

    # graph json for the dashboard (separate from the per-incident graph)
    nodes = [{"id": n, "label": d["label"], "type": d["kind"]} for n, d in G.nodes(data=True)]
    edges = [{"source": u, "target": v, "weight": d.get("weight", 1)} for u, v, d in G.edges(data=True)]
    return {"components": comp_info, "merged": merged, "nodes": nodes, "edges": edges,
            "generated_at": datetime.now(timezone.utc).isoformat(), "lookback_hours": lookback_hours}


def _merge_incidents(db: Session, inc_ids: List[str], path: str):
    """Merges the incidents and returns the id of the one that survives (or None)."""
    incs = db.query(IncidentModel).filter(IncidentModel.id.in_(inc_ids)).all()
    incs = [i for i in incs if i.status in ("open", "escalated")]
    if len(incs) < 2:
        return None
    incs.sort(key=lambda i: i.first_seen)
    primary, others = incs[0], incs[1:]

    ents = {k: set(v) for k, v in (primary.related_entities or {}).items()}
    timeline = list(primary.timeline or [])
    for o in others:
        for k, v in (o.related_entities or {}).items():
            ents.setdefault(k, set()).update(v)
        timeline += list(o.timeline or [])
        db.query(AlertModel).filter(AlertModel.incident_id == o.id).update({"incident_id": primary.id})
        primary.first_seen = min(primary.first_seen, o.first_seen)
        primary.last_seen = max(primary.last_seen, o.last_seen)
    db.flush()
    for o in others:
        db.delete(o)

    primary.related_entities = {k: sorted(v) for k, v in ents.items()}
    timeline.sort(key=lambda x: x["timestamp"])
    timeline.append({"timestamp": datetime.now(timezone.utc).isoformat(), "event_id": None, "alert_id": None,
                     "detector": "networkx", "severity": "info",
                     "title": "Incidents merged by NetworkX batch correlation",
                     "reason": path or "shared entities in one graph component"})
    primary.timeline = timeline
    primary.correlation_method = "networkx_batch"
    if not primary.title.startswith("Multi-hop campaign"):
        primary.title = f"Multi-hop campaign: {primary.title}"
    primary.summary = "Several incidents were joined by the NetworkX batch job. " + (f"Path: {path}" if path else "")

    all_alerts = [_to_schema(a) for a in db.query(AlertModel).filter(AlertModel.incident_id == primary.id).all()]
    refresh_incident(db, primary, all_alerts)
    db.commit()
    maybe_auto_respond(db, primary)
    return primary.id
