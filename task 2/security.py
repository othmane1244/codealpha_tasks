# ============================================================
# security.py — Authentification API Key (Finding #1, #2)
# A ajouter au projet Phase-4 et importer dans main.py
# ============================================================
"""
Dépendance FastAPI minimale pour protéger les routes sensibles avec une
clé API statique partagée entre le RPi 5 et le backend.

C'est une solution de transition simple. Pour une version plus robuste,
remplacer par un JWT signé (python-jose est déjà dans requirements.txt)
ou réutiliser Keycloak comme dans le projet ELMA.

Configuration : ajouter dans .env
    API_KEY=<une-valeur-aleatoire-longue-genere-avec-secrets.token_urlsafe(32)>
"""

import os
import secrets
from fastapi import Header, HTTPException, status

API_KEY = os.getenv("API_KEY")

if not API_KEY:
    # Fail loudly at startup rather than silently accepting every request.
    raise RuntimeError(
        "API_KEY n'est pas défini dans l'environnement (.env). "
        "Générez-en une avec: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )


async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """
    Dépendance FastAPI à utiliser avec Depends(verify_api_key) sur les
    routes sensibles (POST /process_frame/, DELETE /alerts/buffer/, etc.)

    Utilise secrets.compare_digest pour éviter les attaques par timing.
    """
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API invalide ou manquante.",
        )
