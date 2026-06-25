# CodeAlpha_SecureCodeReview

**CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review**

A secure code review of the FastAPI backend from my own PFE/PFA project — an Edge-to-Cloud intelligent residential surveillance system (Raspberry Pi 5 + Hailo-8 NPU, YOLO11n, Supabase, Next.js dashboard).

Source project: https://github.com/othmane1244/Phase-4

## Contents

```
SECURITY_REVIEW.md      → full audit report: methodology, findings, remediation
bandit_report.txt       → raw output of the Bandit static analyzer
reviewed-code/          → snapshot of the 4 audited files (main.py, database.py, models.py, services.py)
remediation/
  security.py                  → new API-key auth dependency module
  main_patched_excerpt.py      → patched route excerpts (auth + CORS + debug-route gating)
  models_patched_excerpt.py    → patched Pydantic model (bounded payload size)
```

## Methodology

1. **Automated static analysis** with [Bandit](https://bandit.readthedocs.io/) — found 0 issues, since the real risks here are architectural rather than syntactic.
2. **Manual review** focused on authentication/authorization, CORS, input validation, rate limiting, logging/privacy, and error handling — appropriate given this API ingests data from edge devices and serves a security-critical real-time dashboard.

## Key findings

| Severity | Finding |
|---|---|
| 🔴 High | No authentication on any endpoint |
| 🔴 High | Unauthenticated endpoint that deletes alert data |
| 🟠 Medium | Permissive CORS (`*` + credentials) |
| 🟠 Medium | No rate limiting / unbounded request payload |
| 🟠 Medium | Verbose per-detection logging (privacy / CNDP compliance risk) |
| 🟡 Low | Overly broad exception handling |
| 🟡 Low | Debug routes not separated from production routes |

Full details, CWE references, and remediation code in [`SECURITY_REVIEW.md`](./SECURITY_REVIEW.md).

## Why this project

Auditing real production-bound code (rather than a toy vulnerable app) makes the review concrete: every finding here maps to an actual deployment decision for a Raspberry Pi 5 surveillance system, including the project's own Privacy by Design / loi 09-08 (CNDP) compliance constraints.

## Author

Othmane — IACS Engineering Student, ENSA Béni Mellal (USMS)
CodeAlpha Cybersecurity Internship
