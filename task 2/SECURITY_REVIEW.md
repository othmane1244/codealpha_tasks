# Secure Code Review — Surveillance API (FastAPI Backend)

**CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review**

**Application audited:** `Phase-4` — Edge-to-Cloud Intelligent Residential Surveillance System
**Layer reviewed:** FastAPI backend (`main.py`, `database.py`, `models.py`, `services.py`)
**Language:** Python 3.12 / FastAPI 0.115.5
**Source:** https://github.com/othmane1244/Phase-4
**Reviewer:** Othmane
**Date:** June 2026

---

## 1. Scope

This review covers the four core files that make up the API layer of the surveillance system:

| File | Role |
|---|---|
| `main.py` | FastAPI routes (REST + WebSocket), CORS config, app lifecycle |
| `database.py` | Supabase persistence, WebSocket connection manager |
| `models.py` | Pydantic data models / input-output validation |
| `services.py` | Behavioral analysis logic (intrusion, fall, abandoned object, crowding) |

Out of scope: the Next.js dashboard, the YOLO/ONNX inference pipeline, and infrastructure (RPi 5, Hailo-8 deployment), which would warrant a separate review.

## 2. Methodology

Two complementary methods were used, as recommended for secure code review:

1. **Automated static analysis** — [Bandit](https://bandit.readthedocs.io/) (a Python-specific SAST tool) was run against the four files. Full output is in `bandit_report.txt`.
2. **Manual inspection** — line-by-line review focused on authentication/authorization, input validation, data exposure, error handling, and resource exhaustion, since this is a network-facing API that ingests untrusted data from edge devices and exposes a real-time feed to a web dashboard.

### 2.1 Static analysis result

```
Total issues (by severity):
    Undefined: 0
    Low: 0
    Medium: 0
    High: 0
```

Bandit reported **zero findings**. This is expected and worth noting explicitly: Bandit is pattern-based and excels at catching things like `eval()`, hardcoded credentials, weak hashing algorithms, or raw SQL string concatenation — none of which appear in this codebase. The actual risks here are **architectural/business-logic flaws** (missing authentication, permissive CORS, lack of rate limiting), which static analyzers structurally cannot detect. This is exactly why the task asks for manual inspection in addition to tooling.

## 3. Findings Summary

| # | Severity | Finding | Location | CWE |
|---|---|---|---|---|
| 1 | 🔴 High | No authentication on any endpoint | `main.py` (all routes) | CWE-306 |
| 2 | 🔴 High | Unauthenticated, state-destroying debug endpoint | `main.py:157` (`DELETE /alerts/buffer/`) | CWE-862 |
| 3 | 🟠 Medium | Permissive CORS (`*` + credentials) | `main.py:60-66` | CWE-942 |
| 4 | 🟠 Medium | No rate limiting / unbounded payload size | `main.py:92` (`POST /process_frame/`) | CWE-770 |
| 5 | 🟠 Medium | Verbose logging of detection data (privacy risk) | `services.py:218-236` | CWE-532 |
| 6 | 🟡 Low | Broad exception handling hides root cause | `database.py:141`, `:184` | CWE-396 |
| 7 | 🟡 Low | Debug/test routes shipped alongside production routes | `main.py:147-163` | CWE-489 |

---

## 4. Detailed Findings

### Finding 1 — No authentication on any endpoint (High)

**Location:** every route in `main.py` (`/process_frame/`, `/alerts/`, `/alerts/buffer/`, `/stats/`, `/ws/alerts`)

**Issue:** None of the endpoints check who is calling them. `POST /process_frame/` is the entry point that feeds the whole alerting pipeline (Supabase insert + WebSocket broadcast), yet anyone who can reach the API over the network can post arbitrary fabricated detections and trigger fake "Intrusion" or "Chute" alerts, or silently feed garbage to dilute real alerts.

**Why it matters here specifically:** this is a *security surveillance* system. An attacker who can forge alerts can both create false alarms (denial-of-service on the human operator's attention) and, more importantly, suppress trust in real alerts — or learn the camera's detection zones/thresholds by probing responses.

**Evidence — interesting detail:** `requirements.txt` already lists `python-jose[cryptography]` with the comment `# JWT (auth future si besoin)` — confirming auth was planned but never wired in.

**Remediation:** add a dependency-based check (API key or JWT) on all state-changing and data-exposing routes. See `remediation/security.py` for a minimal API-key implementation that can be swapped for JWT/Keycloak later (you already use Keycloak in the ELMA project — same pattern could be reused here).

---

### Finding 2 — Unauthenticated debug endpoint that destroys data (High)

**Location:** `main.py`, `DELETE /alerts/buffer/`

```python
@app.delete("/alerts/buffer/", tags=["Debug"])
async def clear_local_buffer():
    """Vide le buffer local d'alertes (debug uniquement)."""
    ...
```

**Issue:** tagging a route `"Debug"` does not restrict access to it — it is just metadata for the OpenAPI docs (visible at `/docs`, which is itself public by default in FastAPI). Anyone who finds this in the auto-generated Swagger UI can wipe the local alert buffer with a single HTTP request.

**Remediation:** either remove this route entirely before deployment, or gate it behind the same auth dependency as Finding 1 **and** an explicit environment check (`if not settings.DEBUG: raise HTTPException(404)`), and disable `/docs` and `/redoc` in production (`app = FastAPI(docs_url=None, redoc_url=None)` when `ENV=production`).

---

### Finding 3 — Permissive CORS configuration (Medium)

**Location:** `main.py:60-66`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Restreindre en production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Issue:** `allow_origins=["*"]` combined with `allow_credentials=True` is a known anti-pattern. Per the CORS spec, browsers actually reject this exact combination (a wildcard origin cannot be paired with credentialed requests), so in practice this either silently fails for credentialed calls or — more importantly — signals that origin restriction was deferred ("Restreindre en production" is already a comment in your own code, so this finding mostly confirms what you already flagged).

**Remediation:** replace `["*"]` with an explicit list read from an environment variable, e.g. `["https://your-dashboard.vercel.app", "http://localhost:3000"]`, and only set `allow_credentials=True` if you actually use cookies (you don't appear to — you'd use Bearer tokens instead, which don't need credentialed CORS at all).

---

### Finding 4 — No rate limiting / unbounded detections payload (Medium)

**Location:** `main.py:92` (`POST /process_frame/`), `models.py` (`FrameData.detections`)

**Issue:** `detections: list[Detection]` has no upper bound. A malicious or buggy client could send a single request with thousands of fabricated detections, each of which gets run through 4 analysis rules (`O(n)` to `O(n²)` for the abandoned-object distance check), and every resulting alert triggers a Supabase write **and** a WebSocket broadcast to every connected dashboard client. There's also no per-IP/per-camera rate limit on the endpoint itself.

**Remediation:**
- Add `Field(..., max_length=200)` (or a realistic max for your camera resolution) to `FrameData.detections` in `models.py`.
- Add request rate limiting with `slowapi` (a FastAPI-friendly wrapper around `limits`), e.g. 10 requests/sec per camera_id/IP on `/process_frame/`.

---

### Finding 5 — Verbose logging of detection data (Medium, privacy)

**Location:** `services.py:218-236` (`analyze_behavior`)

```python
logger.info(f"📊 Total détections : {len(detections)}")
for i, det in enumerate(detections):
    logger.info(f"  [{i}] class_id={det.class_id} ... track_id={det.track_id}")
```

**Issue:** this is debug-level instrumentation left in the main analysis path. It logs every detection (including `track_id`, which persists across frames and can re-identify a tracked person) to plaintext logs on every single frame. Given your project's own constraint — Privacy by Design and CNDP (loi 09-08) compliance — persistent, unredacted logs of individual tracking IDs are exactly the kind of data trail that compliance review would flag, especially if logs aren't access-controlled or rotated/purged.

**Remediation:**
- Drop this to `logger.debug(...)` (off by default in production) instead of `logger.info(...)`.
- If you need it for tuning thresholds, log aggregate counts only (`len(persons)`, not each `track_id`), or gate detailed per-detection logs behind an explicit `DEBUG_VERBOSE_DETECTIONS` flag you can disable for the deployed RPi 5.

---

### Finding 6 — Broad exception handling (Low)

**Location:** `database.py:141` and `:184`

```python
except Exception as e:
    logger.error(f"❌ Erreur insert Supabase : {e}")
    _local_alert_buffer.append(alert_dict)
    return False
```

**Issue:** catching bare `Exception` is not a vulnerability by itself, but it silently swallows *every* possible failure mode (network errors, auth failures, malformed data, Supabase quota errors) the same way, which can mask recurring problems (e.g. an expired `SUPABASE_SERVICE_KEY`) until the local buffer silently becomes the only source of truth.

**Remediation:** catch narrower exception types where practical (e.g. `httpx.HTTPError`, `postgrest.exceptions.APIError`) and consider alerting (not just logging) when persistence repeatedly falls back to the local buffer — for a surveillance system, you want to *know* if your alerts stop reaching durable storage.

---

### Finding 7 — Debug routes shipped with production routes (Low)

**Location:** `main.py:147-163` (`GET`/`DELETE /alerts/buffer/`)

**Issue:** related to Finding 2 but distinct — there's no separation (e.g. a separate router, or conditional registration) between production endpoints and debug/testing endpoints. It's easy to forget to remove or gate these before a real deployment.

**Remediation:** group debug routes in their own `APIRouter` and only `app.include_router(debug_router)` when `ENV != "production"`.

---

## 5. What was reviewed and found to be done well

To keep this balanced — several things in this codebase reflect good practice already:

- **Pydantic validation is solid**: `BoundingBox`, `Detection`, and `FrameData` use `Field(..., ge=..., le=...)` constraints, which already block a lot of malformed-input classes of bugs (negative coordinates, out-of-range confidence, invalid `class_id`).
- **No SQL injection risk**: persistence goes through the official `supabase-py` client (PostgREST under the hood), which uses parameterized requests — there is no raw string-built SQL anywhere in the reviewed files.
- **Secrets are not hardcoded**: `SUPABASE_URL`/`SUPABASE_SERVICE_KEY` are loaded via `python-dotenv` from `.env`, and `.gitignore` correctly excludes `.env`/`.env.local` from the repository.
- **Graceful degradation**: the Supabase-down fallback to a local in-memory buffer is a sensible resilience pattern (though see Finding 6 for the logging/alerting gap around it).
- **Unpredictable alert IDs**: `uuid.uuid4()` for `Alert.id` avoids enumerable/sequential identifiers.

## 6. Priority Remediation Order

1. Add authentication to all routes (Finding 1) — blocks the most damage with the least effort.
2. Remove or auth-gate the debug `DELETE /alerts/buffer/` route (Finding 2).
3. Lock down CORS to known origins (Finding 3).
4. Cap `detections` list size + add basic rate limiting (Finding 4).
5. Reduce logging verbosity / add a debug flag (Finding 5).
6. Narrow exception handling + add alerting on persistent fallback (Finding 6).
7. Separate debug routes into their own conditionally-loaded router (Finding 7).

See `remediation/` for a working example of fixes #1, #3, and #4 you can merge directly into `main.py`/`models.py`.
