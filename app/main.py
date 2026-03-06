"""SecureScan FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os

from app.database import init_db
from app.routers import scans, reports


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SecureScan",
    description="Website Security Risk Assessment Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(scans.router)
app.include_router(reports.router)

# Serve static assets
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

# Serve the frontend SPA
_template_dir = os.path.join(os.path.dirname(__file__), "templates")


@app.get("/", include_in_schema=False)
async def serve_index():
    return FileResponse(os.path.join(_template_dir, "index.html"))


@app.get("/health")
async def health():
    return {"status": "ok", "service": "SecureScan"}
