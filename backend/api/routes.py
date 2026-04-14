from fastapi import APIRouter

router = APIRouter()

@router.post("/analyze")
def analyze(data: dict):
    text = data.get("input", "")

    return {
        "status": "clean",
        "confidence": 95,
        "message": f"Analyzed: {text}"
    }

@router.get("/health")
def health():
    return {"status": "ok"}