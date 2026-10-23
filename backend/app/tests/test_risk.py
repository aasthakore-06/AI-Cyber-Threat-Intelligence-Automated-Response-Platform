from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.incident import RiskTier
from app.services.risk_scoring import calculate_risk_score, tier_for
from app.services.risk_decay import decay_score


def _alert(det, cat, sev, conf):
    return StandardAlert(event_id="e", detector=det, category=cat, severity=sev, confidence=conf,
                         title="t", recommended_action="x")


def test_tier_boundaries():
    assert tier_for(30) == RiskTier.SAFE
    assert tier_for(31) == RiskTier.SUSPICIOUS
    assert tier_for(70) == RiskTier.SUSPICIOUS
    assert tier_for(71) == RiskTier.MALICIOUS


def test_score_bounds_and_empty():
    s, t, _ = calculate_risk_score([])
    assert s == 0 and t == RiskTier.SAFE
    a = _alert(AlertDetector.LOGIN, AlertCategory.CREDENTIAL_ACCESS, AlertSeverity.MEDIUM, 0.9)
    s, t, _ = calculate_risk_score([a])
    assert s == 60 and t == RiskTier.SUSPICIOUS          # rule based: medium = 60


def test_two_modules_score_higher_than_one():
    login = _alert(AlertDetector.LOGIN, AlertCategory.CREDENTIAL_ACCESS, AlertSeverity.MEDIUM, 0.9)
    scan = _alert(AlertDetector.PORT_SCAN, AlertCategory.RECONNAISSANCE, AlertSeverity.MEDIUM, 0.8)
    one, _, _ = calculate_risk_score([login])
    two, _, _ = calculate_risk_score([login, scan])
    assert two > one and two <= 100


def test_honeytoken_forces_at_least_90():
    ht = _alert(AlertDetector.HONEYTOKEN, AlertCategory.DECEPTION, AlertSeverity.CRITICAL, 0.5)
    s, t, breakdown = calculate_risk_score([ht])
    assert s >= 90 and t == RiskTier.MALICIOUS
    # mixed with a weak signal the weighted average would pull it under 90, the floor stops that
    weak = _alert(AlertDetector.WEB_ATTACK, AlertCategory.WEB_EXPLOITATION, AlertSeverity.LOW, 0.5)
    s2, t2, breakdown = calculate_risk_score([ht, weak])
    assert s2 >= 90 and any(b["category"] == "Honeytoken floor" for b in breakdown)


def test_decay_ten_percent_every_six_hours_with_floor():
    assert decay_score(80, 5)["score"] == 80                  # not a full 6h step yet
    assert decay_score(80, 6)["score"] == 72                  # -10%
    assert decay_score(80, 12)["score"] == 64.8               # -10% twice
    far = decay_score(80, 24 * 30)
    assert far["score"] == 40 and far["floor_hit"]            # never below 50% of base
    assert decay_score(95, 24 * 30, has_honeytoken=True)["score"] == 60  # honeytoken floor
