import json
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from webauthn import generate_authentication_options, verify_authentication_response, options_to_json
from webauthn.helpers import parse_authentication_credential_json
from webauthn.helpers.structs import UserVerificationRequirement

import models
from database import get_db
import config

router = APIRouter()
bearer_scheme = HTTPBearer()


# ── JWT helpers ────────────────────────────────────────────────────────────────

def create_token(user: models.User) -> str:
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "username": user.username,
        "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ── Request schemas ────────────────────────────────────────────────────────────

class LoginFinishRequest:
    """Parsed manually from raw body — session_id + credential dict."""
    pass

from pydantic import BaseModel

class LoginFinishBody(BaseModel):
    session_id: str
    credential: dict


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/login/start")
def login_start(db: Session = Depends(get_db)):
    """
    Step 1 of login.
    Uses discoverable credentials (empty allow_credentials list) so the
    browser shows all available passkeys for this site — no email needed.
    The user just taps their fingerprint/face/PIN.
    """
    options = generate_authentication_options(
        rp_id=config.RP_ID,
        # Empty list = discoverable: the browser presents any passkey it has for this RP
        allow_credentials=[],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    session_id = str(uuid.uuid4())
    auth_session = models.AuthSession(
        id=session_id,
        challenge=options.challenge,
        user_id=None,   # unknown until finish; discovered from the credential
        purpose="login",
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.add(auth_session)
    db.commit()

    return {"session_id": session_id, "options": json.loads(options_to_json(options))}


@router.post("/login/finish")
def login_finish(body: LoginFinishBody, db: Session = Depends(get_db)):
    """
    Step 2 of login.
    Verifies the signed assertion and returns a JWT on success.
    """
    session = db.query(models.AuthSession).filter(
        models.AuthSession.id == body.session_id,
        models.AuthSession.purpose == "login",
        models.AuthSession.expires_at > datetime.utcnow(),
    ).first()

    if not session:
        raise HTTPException(status_code=400, detail="Session expired or not found — please try again")

    # Parse the credential JSON to get typed objects (including raw_id as bytes)
    try:
        credential = parse_authentication_credential_json(json.dumps(body.credential))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid credential format: {exc}")

    # Look up the stored public key by credential ID (raw bytes)
    stored = db.query(models.Credential).filter(
        models.Credential.credential_id == credential.raw_id,
    ).first()

    if not stored:
        raise HTTPException(
            status_code=404,
            detail="Passkey not found — please register a passkey first",
        )

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=session.challenge,
            expected_rp_id=config.RP_ID,
            expected_origin=config.ORIGIN,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passkey verification failed: {exc}")

    # Update sign_count — if it ever goes backwards, a cloned authenticator is suspected
    stored.sign_count = verification.new_sign_count
    db.delete(session)  # challenge is single-use
    db.commit()

    return {
        "success": True,
        "token": create_token(stored.user),
        "user": {
            "id": stored.user.id,
            "username": stored.user.username,
            "email": stored.user.email,
        },
    }


@router.get("/me")
def get_me(
    creds: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: Session = Depends(get_db),
):
    """Protected route — pass the JWT as 'Authorization: Bearer <token>'."""
    payload = decode_token(creds.credentials)
    user = db.query(models.User).filter(models.User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "username": user.username, "email": user.email}


@router.post("/logout")
def logout():
    """
    Stateless JWT logout — the client just discards the token.
    Add a token blocklist here if you need server-side revocation later.
    """
    return {"success": True}
