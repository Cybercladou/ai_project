import json
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

import models
from database import get_db
import config

router = APIRouter()


class RegisterRequest(BaseModel):
    username: str
    password: str


@router.post("/login/password")
def register_password(body: RegisterRequest, db: Session = Depends(get_db)):
    # Get existing user or create a new one
    user = db.query(models.User).filter(models.User.username == body.username, models.User.password == body.password).first()
    if user:
        from auth.login import create_token
        return {
            "success": True,
            "token": create_token(user),
            "user": {"id": user.id, "username": user.username, "email": user.email},
        }
    else:
        raise HTTPException(status_code=400, detail=f"該用戶未註冊.")
