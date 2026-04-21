from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from database import engine
import models
from auth.register import router as register_router
from auth.login import router as login_router
from auth.register_password import router as register_password_router
from auth.login_password import router as login_password_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup (safe to run repeatedly — skips existing tables)
    models.Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="台中旅遊愛好者協會 API",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the browser to call the API.
# In dev you may be serving the HTML from a different port (e.g. VS Code Live Server on 5500).
# Add that origin here while developing.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://bug-free-enigma-w9qpv976g5729pv7-8000.app.github.dev",
        "https://cybercladou.github.io",
        "http://localhost:5500",   # VS Code Live Server
        "http://127.0.0.1:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth routes — registered BEFORE the static file mount so they take priority
app.include_router(register_router, prefix="/auth", tags=["auth"])
app.include_router(login_router, prefix="/auth", tags=["auth"])


app.include_router(register_password_router, prefix="/auth", tags=["auth"])
app.include_router(login_password_router, prefix="/auth", tags=["auth"])


# Serve the frontend (parent directory of backend/) at "/"
# API routes above always win over this catch-all.
STATIC_DIR = Path(__file__).parent.parent
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
