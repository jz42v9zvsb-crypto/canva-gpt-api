import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field


load_dotenv()

app = FastAPI(title="Canva GPT API")

CANVA_CLIENT_ID = os.getenv("CANVA_CLIENT_ID")
CANVA_CLIENT_SECRET = os.getenv("CANVA_CLIENT_SECRET")
CANVA_REDIRECT_URI = os.getenv("CANVA_REDIRECT_URI")

AUTH_URL = "https://www.canva.com/api/oauth/authorize"
TOKEN_URL = "https://api.canva.com/rest/v1/oauth/token"

EXPORT_URL = "https://api.canva.com/rest/v1/exports"
BRAND_TEMPLATES_URL = "https://api.canva.com/rest/v1/brand-templates"
AUTOFILLS_URL = "https://api.canva.com/rest/v1/autofills"

# 지금은 테스트용 메모리 저장소.
# Render 서버가 재시작되면 token_store가 비워지므로 /oauth/start를 다시 해야 함.
oauth_store = {}
token_store = {}


class AutofillRequest(BaseModel):
    brand_template_id: str = Field(
        ...,
        description="Canva Brand Template ID",
    )
    title: str = Field(
        ...,
        description="Autofill로 새로 생성할 Canva 디자인 제목",
    )
    data: dict = Field(
        ...,
        description="Brand Template dataset 필드에 채울 데이터",
    )


def create_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")

    return code_verifier, code_challenge


def get_access_token():
    token_data = token_store.get("canva")

    if not token_data or not token_data.get("access_token"):
        raise HTTPException(
            status_code=401,
            detail="Canva 연결이 안 되어 있습니다. /oauth/start 먼저 실행하세요.",
        )

    return token_data["access_token"]


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "Canva GPT API server is running.",
        "oauth_start": "/oauth/start",
        "token_check": "/token/check",
        "docs": "/docs",
        "capabilities": "/capabilities",
    }


@app.get("/capabilities")
def capabilities():
    return {
        "status": "ok",
        "features": [
            "canva_oauth",
            "token_check",
            "export_start",
            "export_check",
            "brand_templates",
            "brand_template_dataset",
            "autofill_start",
            "autofill_check",
        ],
        "endpoints": {
            "oauth_start": "/oauth/start",
            "token_check": "/token/check",
            "export_start": "/export/start",
            "export_check": "/export/check/{export_id}",
            "brand_templates": "/brand-templates",
            "brand_template_dataset": "/brand-templates/{brand_template_id}/dataset",
            "autofill_start": "/autofill/start",
            "autofill_check": "/autofill/check/{job_id}",
        },
    }


@app.get("/oauth/start")
def oauth_start():
    if not CANVA_CLIENT_ID or not CANVA_CLIENT_SECRET or not CANVA_REDIRECT_URI:
        raise HTTPException(
            status_code=500,
            detail="Missing Canva environment variables",
        )

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = create_pkce_pair()

    oauth_store[state] = {
        "code_verifier": code_verifier,
    }

    # Brand Template / Autofill 권한까지 요청.
    # 만약 Canva에서 invalid_scope가 뜨면, 아래 scope를 줄여서 테스트하면 됨.
    scope = (
        "profile:read "
        "design:content:read "
        "design:meta:read "
        "brandtemplate:meta:read "
        "brandtemplate:content:read"
    )

    params = {
        "client_id": CANVA_CLIENT_ID,
        "redirect_uri": CANVA_REDIRECT_URI,
        "response_type": "code",
        "scope": scope,
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
        raise HTTPException(
            status_code=400,
            detail=f"Canva OAuth error: {error}",
        )

    if not code or not state:
        raise HTTPException(
            status_code=400,
            detail="Missing code or state",
        )

    stored = oauth_store.get(state)

    if not stored:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired state",
        )

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

    response = requests.post(
        TOKEN_URL,
        headers=headers,
        data=data,
        timeout=20,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    token_data = response.json()
    token_store["canva"] = token_data

    return HTMLResponse(
        """
        <h2>Canva OAuth 연결 성공</h2>
        <p>Access token을 받았습니다.</p>
        <p>이 창은 닫아도 됩니다.</p>
        <p>다음 테스트: <a href="/token/check">/token/check</a></p>
        """
    )


@app.get("/token/check")
def token_check():
    token_data = token_store.get("canva")

    if not token_data:
        return {
            "connected": False,
            "message": "아직 Canva OAuth 연결이 안 됐습니다. /oauth/start 먼저 열어주세요.",
        }

    return {
        "connected": True,
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in"),
        "scope": token_data.get("scope"),
        "has_access_token": bool(token_data.get("access_token")),
        "has_refresh_token": bool(token_data.get("refresh_token")),
    }


@app.post("/export/start")
def export_start(
    design_id: str,
    file_type: str = "png",
):
    """
    Canva 디자인을 export job으로 생성합니다.

    예:
    POST /export/start?design_id=DAHJn5I7CDA&file_type=png

    file_type:
    png, jpg, pdf, pptx, mp4, gif
    """
    access_token = get_access_token()

    allowed_types = {
        "png",
        "jpg",
        "pdf",
        "pptx",
        "mp4",
        "gif",
    }

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
            "type": file_type,
        },
    }

    response = requests.post(
        EXPORT_URL,
        headers=headers,
        json=payload,
        timeout=30,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()


@app.get("/export/check/{export_id}")
def export_check(export_id: str):
    """
    Canva export job 상태를 확인합니다.

    예:
    GET /export/check/cb51bf6e-7843-4da3-b6bf-1e214d8915fc
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


@app.get("/brand-templates")
def list_brand_templates(
    dataset: str = "non_empty",
    limit: int = 20,
):
    """
    Canva Brand Template 목록을 조회합니다.

    dataset:
    - any: dataset 필드 유무와 상관없이 조회
    - non_empty: Autofill 가능한 dataset 필드가 있는 템플릿만 조회
    """
    access_token = get_access_token()

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    params = {
        "dataset": dataset,
        "limit": limit,
    }

    response = requests.get(
        BRAND_TEMPLATES_URL,
        headers=headers,
        params=params,
        timeout=30,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()


@app.get("/brand-templates/{brand_template_id}/dataset")
def get_brand_template_dataset(brand_template_id: str):
    """
    특정 Brand Template의 Autofill dataset 필드 구조를 조회합니다.
    예: title, subtitle, body_1, image_1 같은 필드 확인용.
    """
    access_token = get_access_token()

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    response = requests.get(
        f"{BRAND_TEMPLATES_URL}/{brand_template_id}/dataset",
        headers=headers,
        timeout=30,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()


@app.post("/autofill/start")
def autofill_start(request: AutofillRequest):
    """
    Brand Template에 데이터를 채워 새 Canva 디자인을 생성합니다.

    FastAPI docs에서 테스트하기:
    /docs → POST /autofill/start → Try it out

    body 예시:
    {
      "brand_template_id": "BRAND_TEMPLATE_ID",
      "title": "감도 카드뉴스 테스트",
      "data": {
        "headline": {
          "type": "text",
          "text": "샤넬이 인도를 보는 방식"
        }
      }
    }
    """
    access_token = get_access_token()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    payload = {
        "brand_template_id": request.brand_template_id,
        "title": request.title,
        "data": request.data,
    }

    response = requests.post(
        AUTOFILLS_URL,
        headers=headers,
        json=payload,
        timeout=30,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()


@app.get("/autofill/check/{job_id}")
def autofill_check(job_id: str):
    """
    Autofill job 상태를 확인합니다.
    성공하면 새로 생성된 Canva design 정보가 반환됩니다.
    """
    access_token = get_access_token()

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    response = requests.get(
        f"{AUTOFILLS_URL}/{job_id}",
        headers=headers,
        timeout=30,
    )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.text,
        )

    return response.json()