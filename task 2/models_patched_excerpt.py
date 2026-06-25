# ============================================================
# models_patched_excerpt.py — Extrait de models.py CORRIGÉ
# Montre le changement pour Finding #4 (payload non borné)
# (Pas un fichier exécutable seul — à fusionner dans models.py)
# ============================================================

from pydantic import BaseModel, Field
from datetime import datetime


class FrameData(BaseModel):
    """Données complètes d'un frame vidéo traité."""
    camera_id:  str             = Field(..., description="ID caméra ex: cam_01")
    frame_id:   int             = Field(..., ge=0)
    timestamp:  datetime        = Field(default_factory=datetime.utcnow)
    fps:        float           = Field(..., ge=0.0)

    # Finding #4 — borne réaliste : une frame 640x640 ne contiendra
    # raisonnablement jamais plus de ~200 objets détectés simultanément.
    # Empêche un payload malveillant/buggé de surcharger l'analyse
    # comportementale (O(n) à O(n^2)) et le broadcast WebSocket.
    detections: list["Detection"] = Field(default_factory=list, max_length=200)
