import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

load_dotenv()

app = FastAPI(title="Canva GPT API")

CANVA_CLIENT_ID = os.getenv("CANVA_CLIENT_ID")
CANVA_CLIENT_SECRET = os.getenv("CANVA_CLIENT_SECRET")
CANVA_REDIRECT_URI = os.getenv("CANVA_REDIRECT_URI")

AUTH_URL = "https://www.canva.com/api/oauth/authorize"
TOKEN_URL = "https://api.canva.com/rest/v1/oauth/token"

oauth_store = {}
token_store = {}


def create_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return code_verifier, code_challenge


@app.get("/")
def home():
    return {
        "status": "ok",
        "next": "Open http://127.0.0.1:3001/oauth/start"
    }


@app.get("/oauth/start")
def oauth_start():
    if not CANVA_CLIENT_ID or not CANVA_CLIENT_SECRET or not CANVA_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Missing Canva environment variables")

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = create_pkce_pair()
    oauth_store[state] = {"code_verifier": code_verifier}

    params = {
        "client_id": CANVA_CLIENT_ID,
        "redirect_uri": CANVA_REDIRECT_URI,
        "response_type": "code",
        "scope": "profile:read design:content:read design:meta:read",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    return RedirectResponse(f"{AUTH_URL}?{urlencode(params)}")


@app.get("/oauth/redirect")
def oauth_redirect(
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
):
    if error:
        raise HTTPException(status_code=400, detail=f"Canva OAuth error: {error}")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    stored = oauth_store.get(state)
    if not stored:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    code_verifier = stored["code_verifier"]

    basic_auth = base64.b64encode(
        f"{CANVA_CLIENT_ID}:{CANVA_CLIENT_SECRET}".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {basic_auth}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CANVA_REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=20)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    token_data = response.json()
    token_store["canva"] = token_data

    return HTMLResponse("""
    <h2>Canva OAuth 연결 성공</h2>
    <p>Access token을 받았습니다.</p>
    <p>이 창은 닫아도 됩니다.</p>
    <p>다음 테스트: <a href="/token/check">/token/check</a></p>
    """)


@app.get("/token/check")
def token_check():
    token_data = token_store.get("canva")

    if not token_data:
        return {
            "connected": False,
            "message": "아직 Canva OAuth 연결이 안 됐습니다. /oauth/start 먼저 열어주세요."
        }

    return {
        "connected": True,
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in"),
        "scope": token_data.get("scope"),
        "has_access_token": bool(token_data.get("access_token")),
        "has_refresh_token": bool(token_data.get("refresh_token")),
    }


EXPORT_URL = "https://api.canva.com/rest/v1/exports"


def get_access_token():
    token_data = token_store.get("canva")
    if not token_data or not token_data.get("access_token"):
        raise HTTPException(
            status_code=401,
            detail="Canva 연결이 안 되어 있습니다. /oauth/start 먼저 실행하세요.",
        )
    return token_data["access_token"]


@app.post("/export/start")
def export_start(design_id: str, file_type: str = "png"):
    """
    예:
    POST http://127.0.0.1:3001/export/start?design_id=DESIGN_ID&file_type=png
    file_type: png, jpg, pdf, pptx, mp4, gif
    """
    access_token = get_access_token()

    allowed_types = {"png", "jpg", "pdf", "pptx", "mp4", "gif"}
    if file_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"file_type은 {sorted(allowed_types)} 중 하나여야 합니다.",
        )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    payload = {
        "design_id": design_id,
        "format": {
            "type": file_type
        }
    }

    response = requests.post(EXPORT_URL, headers=headers, json=payload, timeout=30)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()


@app.get("/export/check/{export_id}")
def export_check(export_id: str):
    """
    예:
    GET http://127.0.0.1:3001/export/check/EXPORT_JOB_ID
    """
    access_token = get_access_token()

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    response = requests.get(
        f"{EXPORT_URL}/{export_id}",
        headers=headers,
        timeout=30,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()