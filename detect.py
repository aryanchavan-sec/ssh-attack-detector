import re, sys, json
from collections import defaultdict

pattern = re.compile(r"Failed password for (?:invalid user )?(.*?) from (\d+\.\d+\.\d+\.\d+)")
attempts = defaultdict(int)
users = defaultdict(set)

with open(sys.argv[1], errors="ignore") as f:
    for line in f:
        m = pattern.search(line)
        if m:
            user, ip = m.groups()
            attempts[ip] += 1
            users[ip].add(user)

THRESHOLD = 7   # change this and see what happens
alerts = []
for ip, count in sorted(attempts.items(), key=lambda x: -x[1]):
    if count >= THRESHOLD:
        alerts.append({"ip": ip, "failed_logins": count,
                       "usernames_tried": len(users[ip]),
                       "mitre_technique": "T1110 Brute Force"})

json.dump(alerts, open("alerts.json", "w"), indent=2)
print(f"{len(alerts)} alerts saved to alerts.json")
