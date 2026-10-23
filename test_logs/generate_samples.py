"""
Makes the test log files in this folder (auth.log, access.log, network.csv, urls.txt).
Run:  python generate_samples.py
The story in the files (all dates are 13-14 Oct 2026):
  - one week of normal logins for alice / bob / carol / dave
  - 14 Oct 09:50  198.51.100.45 port-scans 10.0.0.50
  - 14 Oct 09:55  same IP fires SQLi / XSS / traversal at the web app (user agent sqlmap)
  - 14 Oct 10:00  same IP brute-forces ssh, then gets into 'admin'
  - 14 Oct 10:20  203.0.113.9 keeps going against 'admin'  (IP rotation)
  - 14 Oct 11:10  203.0.113.88 comes back with the same sqlmap user agent and touches the decoy /admin/backup-keys
  - 'dbadmin' gets hammered slowly over several days (failed/success ratio)
  - bob logs in at 03:12 from an IP nobody has seen (anomaly)
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(11)
here = Path(__file__).parent
HOST = "web01"


def sys_ts(t):  # syslog style
    return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if t.day < 10 else t.strftime("%b %d %H:%M:%S")


def line(t, msg, pid=None):
    pid = pid or random.randint(1000, 9999)
    return t, f"{sys_ts(t)} {HOST} sshd[{pid}]: {msg}"


auth = []
users = {"alice": "10.0.0.11", "bob": "10.0.0.12", "carol": "10.0.0.13", "dave": "10.0.0.14"}

# ---- normal week (7-13 Oct) --------------------------------------------------
for d in range(7, 14):
    day = datetime(2026, 10, d)
    if day.weekday() >= 5:
        continue
    for u, ip in users.items():
        t = day + timedelta(hours=random.choice([8, 9, 9, 10]), minutes=random.randint(0, 50))
        if random.random() < 0.15:  # fat-fingered password once in a while
            auth.append(line(t - timedelta(seconds=20), f"Failed password for {u} from {ip} port {random.randint(40000,60000)} ssh2"))
        auth.append(line(t, f"Accepted password for {u} from {ip} port {random.randint(40000,60000)} ssh2"))
        if random.random() < 0.5:
            t2 = day + timedelta(hours=14, minutes=random.randint(0, 59))
            auth.append(line(t2, f"Accepted publickey for {u} from {ip} port {random.randint(40000,60000)} ssh2"))
    auth.append((day + timedelta(hours=12), f"{sys_ts(day + timedelta(hours=12))} {HOST} CRON[2211]: pam_unix(cron:session): session opened for user root"))

# ---- bob at 3am from a strange IP (13 Oct) -----------------------------------
auth.append(line(datetime(2026, 10, 13, 3, 12, 40), "Accepted password for bob from 203.0.113.77 port 51022 ssh2"))

# ---- slow attack on dbadmin: 14 failures over a week, 2 real logins -----------
for i, ip in enumerate(["192.0.2.14", "192.0.2.55", "192.0.2.14", "192.0.2.77"] * 4):
    t = datetime(2026, 10, 7, 2, 0) + timedelta(hours=random.randint(8, 12) * (i + 1) * 0.7)
    if t.day <= 14:
        auth.append(line(t, f"Failed password for dbadmin from {ip} port {random.randint(30000,60000)} ssh2"))
auth.append(line(datetime(2026, 10, 9, 10, 5), "Accepted password for dbadmin from 10.0.0.20 port 44000 ssh2"))
auth.append(line(datetime(2026, 10, 12, 10, 2), "Accepted password for dbadmin from 10.0.0.20 port 44001 ssh2"))

# ---- 14 Oct 10:00 brute force from 198.51.100.45 -----------------------------
t0 = datetime(2026, 10, 14, 10, 0, 5)
tried = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "admin", "root", "guest", "admin", "user", "admin", "root", "deploy", "admin"]
for i, u in enumerate(tried):
    t = t0 + timedelta(seconds=i * 6)
    inv = "invalid user " if u in ("test", "oracle", "guest", "user", "deploy") else ""
    auth.append(line(t, f"Failed password for {inv}{u} from 198.51.100.45 port {41000+i} ssh2"))
auth.append(line(t0 + timedelta(seconds=105), "Accepted password for admin from 198.51.100.45 port 41020 ssh2"))

# ---- 14 Oct 10:20 same account, new IP ---------------------------------------
t1 = datetime(2026, 10, 14, 10, 20, 0)
for i in range(7):
    auth.append(line(t1 + timedelta(seconds=i * 8), f"Failed password for admin from 203.0.113.9 port {52000+i} ssh2"))
auth.append(line(t1 + timedelta(seconds=70), "Accepted password for admin from 203.0.113.9 port 52010 ssh2"))

auth.sort(key=lambda x: x[0])
(here / "auth.log").write_text("\n".join(l for _, l in auth) + "\n")

# ---- network.csv --------------------------------------------------------------
rows = ["timestamp,src_ip,dst_ip,dst_port,protocol"]
for i in range(30):
    t = datetime(2026, 10, 14, 9, 30) + timedelta(minutes=i)
    rows.append(f"{t.isoformat()}Z,10.0.0.{11 + i % 4},10.0.0.50,{random.choice([80, 443, 443, 22])},TCP")
scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
for i, p in enumerate(scan_ports):
    t = datetime(2026, 10, 14, 9, 50, 0) + timedelta(seconds=i * 2)
    rows.append(f"{t.isoformat()}Z,198.51.100.45,10.0.0.50,{p},TCP")
(here / "network.csv").write_text("\n".join(rows) + "\n")

# ---- access.log ---------------------------------------------------------------
UA_OK = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36"
UA_BAD = "sqlmap/1.7.2#stable (https://sqlmap.org)"
web = []


def w(t, ip, req, status, ua=UA_OK, size=512):
    web.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{req} HTTP/1.1" {status} {size} "-" "{ua}"'))


for i in range(40):
    t = datetime(2026, 10, 14, 9, 0) + timedelta(minutes=i * 2)
    w(t, f"10.0.0.{11 + i % 4}", random.choice(["GET /", "GET /products?id=%d" % random.randint(1, 50), "GET /about", "POST /login"]), 200)
sqli = [
    "GET /products?id=1'%20OR%201=1--",
    "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "GET /search?q=<script>alert(1)</script>",
    "GET /download?file=../../../../etc/passwd",
    "GET /products?id=5;%20DROP%20TABLE%20users--",
]
for i, r in enumerate(sqli):
    w(datetime(2026, 10, 14, 9, 55, 10) + timedelta(seconds=i * 9), "198.51.100.45", r, 403, UA_BAD)
# the rotated IP comes back later with the same tool
w(datetime(2026, 10, 14, 11, 10, 3), "203.0.113.88", "GET /products?id=1'%20OR%20'1'='1", 403, UA_BAD)
w(datetime(2026, 10, 14, 11, 10, 20), "203.0.113.88", "GET /products?id=2%20UNION%20SELECT%20NULL,NULL--", 403, UA_BAD)
w(datetime(2026, 10, 14, 11, 15, 41), "203.0.113.88", "GET /admin/backup-keys", 200, UA_BAD)
web.sort(key=lambda x: x[0])
(here / "access.log").write_text("\n".join(l for _, l in web) + "\n")

# ---- urls.txt -----------------------------------------------------------------
(here / "urls.txt").write_text("""# links people reported / mail gateway copies
https://www.google.com/search?q=python
https://github.com/pallets/flask
https://www.wikipedia.org/
http://192.168.1.105/login/bank-verify.php
http://secure-paypal-login.account-verify.example.tk/signin?user=update
http://amaz0n-support.com-login.xyz/verify/account/password
https://docs.python.org/3/
""")
print("sample files written to", here)
