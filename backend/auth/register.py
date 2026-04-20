import json
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from webauthn import generate_registration_options, verify_registration_response, options_to_json
from webauthn.helpers import parse_registration_credential_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

import models
from database import get_db
import config

router = APIRouter()


class RegisterStartRequest(BaseModel):
    username: str
    email: EmailStr


class RegisterFinishRequest(BaseModel):
    session_id: str
    credential: dict  # raw JSON object sent by the browser via @simplewebauthn/browser


@router.post("/register/start")
def register_start(body: RegisterStartRequest, db: Session = Depends(get_db)):
    """
    Step 1 of registration.
    Creates (or retrieves) the user, generates a WebAuthn challenge,
    stores it in a short-lived session, and returns the options for the browser.
    """
    # Get existing user or create a new one
    user = db.query(models.User).filter(models.User.email == body.email).first()
    if not user:
        user = models.User(username=body.username, email=body.email)
        db.add(user)
        db.flush()  # assigns user.id without a full commit

    # Exclude already-registered credentials so the same device cannot be added twice
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in user.credentials
    ]

    options = generate_registration_options(
        rp_id=config.RP_ID,
        rp_name=config.RP_NAME,
        user_id=str(user.id).encode("utf-8"),
        user_name=user.email,
        user_display_name=user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            # PREFERRED: use a device-bound passkey (Touch ID, Face ID, Windows Hello)
            # if available; fall back to security key
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=exclude_credentials,
    )

    # Persist the challenge for verification in /register/finish
    session_id = str(uuid.uuid4())
    auth_session = models.AuthSession(
        id=session_id,
        challenge=options.challenge,
        user_id=user.id,
        purpose="register",
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.add(auth_session)
    db.commit()

    # options_to_json() returns a JSON string — parse it so FastAPI sends it as an object
    return {"session_id": session_id, "options": json.loads(options_to_json(options))}


@router.post("/register/finish")
def register_finish(body: RegisterFinishRequest, db: Session = Depends(get_db)):
    """
    Step 2 of registration.
    Verifies the credential created by the browser and stores the public key.
    Returns a JWT on success.
    """
    session = db.query(models.AuthSession).filter(
        models.AuthSession.id == body.session_id,
        models.AuthSession.purpose == "register",
        models.AuthSession.expires_at > datetime.utcnow(),
    ).first()

    if not session:
        raise HTTPException(status_code=400, detail="Session expired or not found — please try again")

    try:
        credential = parse_registration_credential_json(json.dumps(body.credential))
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=session.challenge,
            expected_rp_id=config.RP_ID,
            expected_origin=config.ORIGIN,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passkey verification failed: {exc}")

    # Persist the public key — this is what we check against on every future login
    transports = body.credential.get("response", {}).get("transports", [])
    new_credential = models.Credential(
        user_id=session.user_id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=json.dumps(transports),
    )
    db.add(new_credential)
    db.delete(session)  # challenge is single-use
    db.commit()

    user = db.query(models.User).filter(models.User.id == session.user_id).first()

    from auth.login import create_token
    return {
        "success": True,
        "token": create_token(user),
        "user": {"id": user.id, "username": user.username, "email": user.email},
    }
