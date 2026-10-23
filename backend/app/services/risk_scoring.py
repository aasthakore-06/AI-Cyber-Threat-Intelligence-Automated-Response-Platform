"""
Risk Scoring Service (workflow step 10)
Owner: Aastha

Step 1 - normalise every alert to 0-100
    rule-based modules : fixed severity map   low=30  medium=60  high=90  critical=95
    ML modules         : confidence x 100     (phishing Random Forest, login Isolation Forest)
    honeytoken         : fixed 90+ (decoys have no false positives)
Step 2 - one score per module = best alert of that module + 3 per extra alert (max +10)
Step 3 - weighted combination across modules
              incident = 0.6 x (highest module score) + 0.4 x (average module score)
Step 4 - small bonuses: 2 modules agree +8, 3 or more +15, recon followed by
         exploitation / credential attack +10
Step 5 - honeytoken present -> score is at least 90.  Cap at 100.

Tiers (same as the synopsis):  0-30 Safe | 31-70 Suspicious | 71-100 Malicious
Everything is deterministic and the breakdown list explains every number.
"""
from typing import List, Dict, Any, Tuple
from app.schemas.alert import StandardAlert, AlertSeverity, AlertCategory, AlertDetector
from app.schemas.incident import RiskTier

SEVERITY_SCORE = {
    AlertSeverity.LOW: 30.0,
    AlertSeverity.MEDIUM: 60.0,
    AlertSeverity.HIGH: 90.0,
    AlertSeverity.CRITICAL: 95.0,
}
HONEYTOKEN_MIN_SCORE = 90.0
W_MAX, W_AVG = 0.6, 0.4


def tier_for(score: float) -> RiskTier:
    if score >= 71:
        return RiskTier.MALICIOUS
    if score >= 31:
        return RiskTier.SUSPICIOUS
    return RiskTier.SAFE


def _det(alert) -> str:
    return alert.detector.value if hasattr(alert.detector, "value") else str(alert.detector)


def _is_ml(alert) -> bool:
    return _det(alert) == "phishing" or (alert.evidence or {}).get("rule_matched") == "ISOLATION_FOREST_OUTLIER"


def alert_score(alert: StandardAlert) -> Tuple[float, str]:
    """Normalised 0-100 score of one alert and how it was derived."""
    if _det(alert) == "honeytoken":
        return max(HONEYTOKEN_MIN_SCORE, round(alert.confidence * 100, 1)), "honeytoken, fixed high confidence"
    if _is_ml(alert):
        return round(alert.confidence * 100, 1), f"ML confidence {alert.confidence:.2f} x 100"
    sev = alert.severity if isinstance(alert.severity, AlertSeverity) else AlertSeverity(alert.severity)
    return SEVERITY_SCORE[sev], f"rule severity '{sev.value}'"


def calculate_risk_score(alerts: List[StandardAlert]) -> Tuple[float, RiskTier, List[Dict[str, Any]]]:
    if not alerts:
        return 0.0, RiskTier.SAFE, [{"category": "Info", "reason": "No alerts linked to this incident", "points": 0.0}]

    breakdown: List[Dict[str, Any]] = []

    # step 1 + 2: one score per module
    by_module: Dict[str, List[Tuple[float, str, StandardAlert]]] = {}
    for a in alerts:
        s, how = alert_score(a)
        by_module.setdefault(_det(a), []).append((s, how, a))

    module_scores: Dict[str, float] = {}
    for mod, items in by_module.items():
        items.sort(key=lambda t: -t[0])
        best, how, top = items[0]
        extra = min(10.0, 3.0 * (len(items) - 1))
        module_scores[mod] = min(100.0, best + extra)
        note = f" (+{extra:.0f} for {len(items) - 1} more alert(s))" if extra else ""
        breakdown.append({"category": "Module score", "points": round(module_scores[mod], 1),
                          "reason": f"{mod}: {best:.0f} from {how}{note}"})

    # step 3: weighted combination
    top_score = max(module_scores.values())
    avg_score = sum(module_scores.values()) / len(module_scores)
    score = W_MAX * top_score + W_AVG * avg_score
    breakdown.append({"category": "Weighted combination", "points": round(score, 1),
                      "reason": f"{W_MAX} x highest module ({top_score:.0f}) + {W_AVG} x average of modules ({avg_score:.0f})"})

    # step 4: bonuses
    n_mod = len(module_scores)
    if n_mod >= 3:
        score += 15
        breakdown.append({"category": "Corroboration", "points": 15.0, "reason": f"{n_mod} different modules agree"})
    elif n_mod == 2:
        score += 8
        breakdown.append({"category": "Corroboration", "points": 8.0, "reason": "2 different modules agree"})

    cats = {a.category.value if hasattr(a.category, "value") else str(a.category) for a in alerts}
    if "reconnaissance" in cats and ({"credential_access", "web_exploitation"} & cats):
        score += 10
        breakdown.append({"category": "Attack progression", "points": 10.0,
                          "reason": "reconnaissance followed by exploitation / credential attack"})

    # step 5: honeytoken floor
    if "honeytoken" in module_scores and score < HONEYTOKEN_MIN_SCORE:
        breakdown.append({"category": "Honeytoken floor", "points": round(HONEYTOKEN_MIN_SCORE - score, 1),
                          "reason": "a decoy was touched, nobody has a legitimate reason to do that, so at least 90"})
        score = HONEYTOKEN_MIN_SCORE

    final = round(max(0.0, min(100.0, score)), 1)
    return final, tier_for(final), breakdown
