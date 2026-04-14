import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

# TEMP REMOVED (causing crash on Render)
# from backend.config import RATE_LIMIT
# from backend.models.database import init_db

from backend.utils.logger import log
import backend.api.routes as routes

# Safe limiter (without RATE_LIMIT)
limiter = Limiter(key_func=get_remote_address)

# Lightweight startup (no heavy loading)
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting lightweight LEXA Backend...")
    yield
    log.info("Shutting down LEXA Backend.")

app = FastAPI(
    title="LEXA Cyber Security Direction Engine",
    description="Backend API for AI-based Threat Triage and Analysis.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Register routes
app.include_router(routes.router, prefix="/api/v1")
@app.get("/")
def home():
    return {"message": "LEXA backend running "}

# Local run (Render ignore karega)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)