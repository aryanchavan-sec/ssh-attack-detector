# SSH Attack Detector

A small Python tool that finds people guessing passwords on an SSH server. It reads a server log, flags IP addresses with too many failed logins, and saves the alerts to a file. I then used an AI assistant to explain each alert, and I checked the AI's answers against the raw log.

## What it does

1. Reads an SSH log file line by line.
2. Counts "Failed password" lines for each IP address.
3. Flags any IP with **7 or more** failed logins.
4. Saves the alerts to `alerts.json`. Each alert has the IP, the number of failed logins, how many different usernames were tried, and the MITRE ATT&CK technique (T1110 Brute Force).

## The data

I used the OpenSSH sample from Loghub: a real SSH server log of about 2,000 lines. It has 520 failed password lines and only 1 successful login.

Source: https://github.com/logpai/loghub

Loghub is free for research and study. If you use it, please cite: Zhu et al., "Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics", ISSRE 2023.

## How to run it

Tested on a MacBook with Python 3.9.

```
python3 -m venv venv
source venv/bin/activate
python3 detect.py OpenSSH_2k.log
```

You should see: `7 alerts saved to alerts.json`

## Results

| IP | Failed logins | Usernames tried | Time span |
|---|---|---|---|
| 183.62.140.253 | 286 | 10 | about 10 minutes |
| 187.141.143.180 | 80 | 28 | about 7 minutes |
| 103.99.0.122 | 46 | 19 | almost 2 hours |
| 112.95.230.3 | 26 | 3 | about 1 minute |
| 5.188.10.180 | 18 | 6 | about 2 minutes |
| 185.190.58.151 | 17 | 3 | about 6 minutes |
| 123.235.32.19 | 7 | 1 | about 2 minutes |

The only successful login in the file came from 119.137.62.142. That IP is not on the alert list, so none of the 7 flagged IPs got in.

## Why I chose a limit of 7

A low limit catches more attackers but also flags people who just mistyped their password. A high limit gives fewer false alarms but misses small attacks. I chose 7. A limit of 5 added three small cases that could be typos. A limit of 20 left out several real attackers. 7 keeps the clear attacks and drops the most likely typos.

## AI summaries, and how I checked them

I gave `alerts.json` to an AI assistant (Claude) and asked for a short explanation and a severity (low, medium, or high) for each alert. The AI only saw the numbers in the alerts. It did not see how fast the attempts happened. So I checked each alert against the raw log, using the first and last time each IP appeared.

| IP | AI severity | My severity | What I found |
|---|---|---|---|
| 183.62.140.253 | High | High | 286 tries in about 10 minutes is a program |
| 187.141.143.180 | High | High | 80 tries on 28 usernames in about 7 minutes |
| 103.99.0.122 | High | High | Slow, almost 2 hours. The AI did not mention this. |
| 112.95.230.3 | Medium | High | 26 tries in about 1 minute is too fast for a person |
| 5.188.10.180 | Medium | High | 18 tries in about 2 minutes is also automated |
| 185.190.58.151 | Medium | Medium | Steady, about 17 tries in 6 minutes |
| 123.235.32.19 | Low | Medium | 7 tries in about 2 minutes is fast for a typo |

**What I learned:** the AI was good at the basics but missed speed. Many tries in a short time points to an automated attack, so severity should go up. Checking the AI against the raw log changed 3 of the 7 severities.

## A bug I found

When I checked the counts by hand, the detector said 17 failed logins for 5.188.10.180 but the log had 18. One log line had a username with an extra space (`invalid user  0101`), and my first pattern skipped it. I changed the username part of the pattern from `(\S+)` to `(.*?)`. Now the detector counts all 520 failed logins.

## Limits of this project

- It only works on a small sample file.
- It counts total failures. It does not look at time, so it cannot tell fast attacks from slow ones.
- It cannot tell if an attacker got in. I checked that by hand with `grep "Accepted"`.
- The AI summaries are not automatic yet. I pasted the alerts into an AI chat.

## What I would improve

- Alert on failures in a time window, for example 7 failures in 5 minutes.
- Check automatically if a flagged IP also has a successful login.
- Add a replay mode that reads the log slowly, as if the attack were happening live.
- Run the AI summaries automatically with a local model, and add the time span to what the AI sees.
