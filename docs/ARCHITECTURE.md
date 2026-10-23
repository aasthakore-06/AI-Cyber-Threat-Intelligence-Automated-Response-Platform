# Architecture

```
auth.log / access.log / network.csv / urls.txt --upload--> parsers --> events
honeytoken webhook / decoy route ---------------------------------------^
   v
5 detectors (login batch | phishing | port scan | web attack | honeytoken) --> alerts
   v
primary correlation (same IP/user, 30 min) --> incident <-- NetworkX batch job merges incidents
   v
risk score 0-100 -> tier -> narrative + explanation;  decay job lowers idle incidents
   v
auto_response_enabled and score >= 71 ?  yes: perform_response(mode=auto)
                                         no : waits for admin -> perform_response(mode=manual)
   v
React dashboard (REST + websocket live feed)
```

## Risk score
1. alert -> 0-100: rule modules low/medium/high = 30/60/90; ML modules (phishing RF, login Isolation Forest) = confidence x 100; honeytoken >= 90
2. module score = best alert + 3 per extra alert (max +10)
3. incident = 0.6 x highest module + 0.4 x average of modules
4. bonuses: 2 modules +8, 3+ modules +15, recon then exploitation/credential attack +10
5. honeytoken present -> at least 90; cap 100

## Decay
`score = max(base x 0.9^(idle_hours // 6), floor)`, floor = 50% of base (honeytoken incidents 60).
Idle time counts from when the last alert was added (wall clock), not the log timestamp. New evidence resets to the base score.

## Tables
events, alerts, incidents (+base_risk_score, last_evidence_at, decay_history, response_mode, correlation_method),
feedback (+feature_snapshot), response_actions, blocklist, settings, users, honeytokens, uploads.
