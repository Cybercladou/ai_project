import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, LargeBinary, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=True)
    email = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    credentials = relationship("Credential", back_populates="user")


class Credential(Base):
    """One row per passkey device. A user can have multiple passkeys."""
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Raw bytes from WebAuthn — stored as BLOB
    credential_id = Column(LargeBinary, unique=True, nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)

    # sign_count increments each use — used to detect cloned authenticators
    sign_count = Column(Integer, default=0)

    # JSON list of transport hints e.g. ["internal", "hybrid"]
    transports = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="credentials")

    def get_transports(self) -> list:
        return json.loads(self.transports) if self.transports else []


class AuthSession(Base):
    """Short-lived challenge storage for in-flight WebAuthn ceremonies."""
    __tablename__ = "auth_sessions"

    id = Column(String, primary_key=True)       # UUID returned to client
    challenge = Column(LargeBinary, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # null until finish
    purpose = Column(String, nullable=False)    # "register" or "login"
    expires_at = Column(DateTime, nullable=False)
