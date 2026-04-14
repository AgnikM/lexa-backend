import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

from backend.config import RATE_LIMIT
from backend.models.database import init_db
from backend.utils.logger import log
import backend.api.routes as routes

# Initialize SlowAPI Limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])

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
    allow_origins=["*"], # Allow all origins, this is a public tool for now. Consider locking it down or configuring correctly.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Register routes
app.include_router(routes.router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    # Make sure we're in the right directory or pass standard python package string
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
