# Project — Purple Team: Attack Simulation & Incident Response

## Objective
Simulate a realistic adversary compromise (initial access, discovery, credential dumping)
from the attacker's perspective, then switch to the defender's role - detecting, analysing,
and documenting the intrusion as a blue team SOC analyst. The primary deliverable is a
professional incident report backed by Splunk/Sysmon evidence and customdetection rules.

## Environment
| Role | OS |
| --- | --- |
| Attacker | Kali Linux |
| Target | Windows 11 + Sysmon (SOC-WIN11-SPLUNK-01) |
| SIEM | Splunk (Ubuntu 26.04 LTS) |

## Tools Used

- **Offensive (simulation):** Sliver C2, Mimikatz
- **Defensive:** Splunk, Sysmon

## Phases Executed
| Phase | Technique | ATT&CK ID |
| --- | --- | --- |
| Initial Access | User Execution: Malicious File | T1204.002 |
| Command & Control | Sliver HTTPS beacon | T1071.001 |
| Discovery | System Info / Account Discovery | T1082, T1087 |
| Credential Access | SAM dump via token::elevate | T1003.002 |
| Credential Access | LSA Secrets (plaintext password recovered) | T1552.004|

> Lateral movement and persistence phases were deliberately out of scope
> for this project to maintain a blue team focus.

## Key Findings
- **Critical:** Plaintext auto-logon password stored in LSA Secrets (T1552.004)
- **High:** Administrator and vboxuser share identical NTLM hashes - credential reuse
- **High:** LSASS PPL enforced at UEFI level (0x2) - blocked Mimikatz LSASS access
- **Medium:** 1 detection gap identified and closed with custom Splunk SPL query

## Key Outputs
- [Incident Report (PDF)](report/incident_report.pdf)
- [Attack Timeline (CSV)](evidence/attack_timeline.csv)
- [ATT&CK Navigator Layer](attck-navigator/project2_coverage.json) 
