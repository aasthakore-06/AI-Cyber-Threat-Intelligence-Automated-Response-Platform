"""
Plain-language incident narrative (workflow step 10.7)

No ML here: the alerts of an incident are sorted by time and filled into sentence
templates, e.g.
  "At 10:00:35 IP 198.51.100.45 made 15 failed logins in 120s (11 usernames tried),
   then at 10:01:50 ... "
build_explanations() gives the rule-tracing lines (why each alert fired) that the
incident page shows under "Why was this flagged?".
"""
import html
from typing import List, Any
from app.schemas.alert import StandardAlert


def _val(x):
    return x.value if hasattr(x, "value") else str(x)


def _subject(a: StandardAlert) -> str:
    if a.source_ip:
        return f"IP {a.source_ip}"
    if a.user_id:
        return f"user '{a.user_id}'"
    return "an unknown source"


def _clause(a: StandardAlert) -> str:
    ev = a.evidence or {}
    det = _val(a.detector)
    rule = ev.get("rule_matched")
    who = _subject(a)

    if det == "login":
        if rule == "BRUTE_FORCE_WINDOW":
            return (f"{who} made {ev.get('peak_failed_in_window')} failed logins in "
                    f"{ev.get('window_seconds')}s ({ev.get('unique_usernames_tried')} different username(s) tried)")
        if rule == "FAILURES_THEN_SUCCESS":
            return f"{who} logged in as '{a.user_id}' after {ev.get('failed_before_success')} failed attempts"
        if rule == "HIGH_FAILED_SUCCESS_RATIO":
            return (f"account '{a.user_id}' had {ev.get('failed')} failed against "
                    f"{ev.get('successful')} successful logins in {ev.get('window_days')} days")
        if rule == "ISOLATION_FOREST_OUTLIER":
            reasons = "; ".join(ev.get("reasons", [])[:2])
            return f"a login for '{a.user_id}' from {a.source_ip} looked abnormal ({reasons})"
    if det == "port_scan":
        return f"{who} probed {ev.get('distinct_ports_count')} different ports"
    if det == "web_attack":
        kind = str(ev.get("attack_type", "attack")).replace("_", " ").lower()
        return f"{who} sent a {kind} request to {html.unescape(str(ev.get('request_uri', a.target)))}"
    if det == "honeytoken":
        return f"{who} touched the honeytoken {ev.get('masked_honeytoken', '')}"
    if det == "phishing":
        return f"{who} was linked to the phishing URL {a.target}".replace("an unknown source was", "a user was")
    return f"{who}: {a.title}"


def generate_incident_narrative(incident: Any, alerts: List[StandardAlert]) -> str:
    if not alerts:
        return "No alerts are linked to this incident yet."

    alerts = sorted(alerts, key=lambda a: a.timestamp)
    parts = []
    i = 0
    while i < len(alerts):
        a = alerts[i]
        # several web-attack alerts in a row from the same IP are told as one step
        j = i
        while j + 1 < len(alerts) and _val(alerts[j + 1].detector) == "web_attack" == _val(a.detector) \
                and alerts[j + 1].source_ip == a.source_ip:
            j += 1
        if j > i:
            kinds = {}
            for x in alerts[i:j + 1]:
                k = str((x.evidence or {}).get("attack_type", "attack")).replace("_", " ").lower()
                kinds[k] = kinds.get(k, 0) + 1
            kind_txt = ", ".join(f"{k} x{n}" for k, n in kinds.items())
            parts.append(f"between {a.timestamp.strftime('%H:%M:%S')} and {alerts[j].timestamp.strftime('%H:%M:%S')} "
                         f"{_subject(a)} sent {j - i + 1} malicious web requests ({kind_txt})")
        else:
            parts.append(f"at {a.timestamp.strftime('%H:%M:%S')} {_clause(a)}")
        i = j + 1

    first, last = alerts[0].timestamp, alerts[-1].timestamp
    date = first.strftime("%d %b %Y")
    modules = sorted({_val(a.detector).replace("_", " ") for a in alerts})

    text = (f"On {date} the system raised {len(alerts)} alert(s) from {len(modules)} module(s) "
            f"({', '.join(modules)}) that belong together. What happened, in order: "
            + ", then ".join(parts) + ".")

    ents = (getattr(incident, "related_entities", None) or {})
    ips = ents.get("ips", [])
    if len(ips) > 1:
        text += (f" The activity came from {len(ips)} different IPs ({', '.join(ips)}) but they are linked "
                 "through a shared user, user agent or decoy, which points to the same attacker changing address.")
    if any(_val(a.detector) == "honeytoken" for a in alerts):
        text += " A honeytoken was touched, so this is treated as confirmed hostile activity."

    score = getattr(incident, "risk_score", None)
    tier = getattr(incident, "risk_tier", None)
    if score is not None and tier:
        text += f" Current risk score: {score:.0f}/100 ({tier})."
    return text


def build_explanations(alerts: List[StandardAlert]) -> List[str]:
    """Rule-tracing text: which condition made each alert fire."""
    lines = []
    for a in sorted(alerts, key=lambda x: x.timestamp):
        ev = a.evidence or {}
        det = _val(a.detector)
        rule = ev.get("rule_matched")
        if rule == "BRUTE_FORCE_WINDOW":
            lines.append(f"[login] more than {ev['threshold']} failed logins inside {ev['window_seconds']}s "
                         f"(peak {ev['peak_failed_in_window']}) -> brute-force rule")
        elif rule == "FAILURES_THEN_SUCCESS":
            lines.append(f"[login] {ev['failed_before_success']} failures in the 10 minutes before a successful login -> takeover rule")
        elif rule == "HIGH_FAILED_SUCCESS_RATIO":
            lines.append(f"[login] failed:successful ratio {ev['ratio']} is above {ev['ratio_threshold']} over {ev['window_days']} days")
        elif rule == "ISOLATION_FOREST_OUTLIER":
            lines.append(f"[login] Isolation Forest anomaly score {ev['anomaly_score']} >= {ev['threshold']} ({'; '.join(ev.get('reasons', []))})")
        elif rule == "DISTINCT_PORTS_THRESHOLD_EXCEEDED":
            lines.append(f"[port_scan] {ev['distinct_ports_count']} distinct ports in {ev['window_seconds']}s, threshold is {ev['threshold']}")
        elif det == "web_attack":
            lines.append(f"[web_attack] request matched the {ev.get('attack_type')} signature: {html.unescape(str(ev.get('matched_snippet')))}")
        elif det == "honeytoken":
            lines.append("[honeytoken] a decoy resource was accessed, decoys are never used legitimately -> fixed high severity")
        elif det == "phishing":
            lines.append(f"[phishing] Random Forest + URL rules classified the URL as phishing (confidence {a.confidence:.2f})")
        else:
            lines.append(f"[{det}] {a.title}")
    return lines
