# ============================================================
# main_patched_excerpt.py — Extraits de main.py CORRIGÉS
# Montre les changements pour Findings #1, #2, #3, #4
# (Pas un fichier exécutable seul — à fusionner dans main.py)
# ============================================================

import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from security import verify_api_key   # <-- nouveau (Finding #1, #2)

# ------------------------------------------------------------
# Finding #3 — CORS restreint via variable d'environnement
# au lieu de allow_origins=["*"]
# ------------------------------------------------------------
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000"
).split(",")

app = FastAPI(
    title="Surveillance IA — API Backend",
    version="1.0.0",
    # Finding #2 — désactiver la doc publique en production
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    redoc_url=None if os.getenv("ENV") == "production" else "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # plus de wildcard
    allow_credentials=False,          # pas de cookies -> pas besoin de credentials
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
)


# ------------------------------------------------------------
# Finding #1 — route protégée par API key
# ------------------------------------------------------------
@app.post(
    "/process_frame/",
    response_model=ProcessFrameResponse,   # noqa: F821 (défini dans models.py)
    tags=["Pipeline"],
    dependencies=[Depends(verify_api_key)],   # <-- AJOUT
)
async def process_frame(frame_data: FrameData):  # noqa: F821
    ...  # logique inchangée, voir main.py original


# ------------------------------------------------------------
# Finding #2 — endpoint debug désormais protégé ET
# désactivé hors environnement de développement
# ------------------------------------------------------------
@app.delete(
    "/alerts/buffer/",
    tags=["Debug"],
    dependencies=[Depends(verify_api_key)],   # <-- AJOUT
)
async def clear_local_buffer():
    if os.getenv("ENV") == "production":
        # Finding #7 — masque même l'existence de la route en prod
        raise HTTPException(status_code=404, detail="Not found")
    from database import _local_alert_buffer
    count = len(_local_alert_buffer)
    _local_alert_buffer.clear()
    return {"cleared": count}
