import time
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from backend.models.schemas import AnalyzeRequest, AnalyzeResponse, HistoryResponse, FeedbackRequest, ThreatStatsResponse
from backend.models.models import Incident, Feedback
from backend.models.database import get_db
from backend.services.nlp_processor import ThreatNLPProcessor
from backend.services.classifier import LEXAClassifier
from backend.services.playbook_engine import PlaybookEngine
from backend.utils.virustotal import VirusTotalClient
from backend.utils.logger import log

router = APIRouter()

# Singletons (initialized on startup in main.py)
nlp = None
classifier = None
playbook_engine = None
vt_client = None

def get_severity(threat_type: str, confidence: float, vt_score: int) -> float:
    base_scores = {
        "phishing": 7.0, "malware": 9.0, "ransomware": 10.0,
        "ddos": 8.0, "sql_injection": 8.5, "social_engineering": 6.0, "unknown": 4.0
    }
    score = base_scores.get(threat_type, 5.0)
    # Adjust based on confidence
    score *= confidence
    # Increase if VT flags it heavily
    if vt_score > 0:
        score = min(10.0, score + 2.0)
    return round(score, 1)

def get_label(severity: float) -> str:
    if severity >= 8.5: return "Critical"
    if severity >= 7.0: return "High"
    if severity >= 4.0: return "Medium"
    return "Low"

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_threat(request: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    start_time = time.time()
    
    # 1. Initialization
    vt_result = None
    vt_malicious_count = 0
    attack_vector = None
    
    # Use NLP logic if Text, else direct
    content = request.content
    cleaned_input = content

    # 2. Input Type specific branching
    if request.input_type == "url":
        vt_result = await vt_client.scan_url(content)
        # Assuming URL threat, we process normally or guess
        cleaned_input = content
        attack_vector = "Web"
    elif request.input_type == "hash":
        vt_result = await vt_client.get_file_report(content)
        cleaned_input = content
        attack_vector = "File"
    else:
        # text
        iocs = nlp.extract_iocs(content)
        cleaned_input = nlp.clean_text(content)
        if len(iocs.get('urls', [])) > 0:
            attack_vector = "Email/Web"

    # Fetch VT stats if completed
    if vt_result and "data" in vt_result and "attributes" in vt_result["data"]:
        stats = vt_result["data"]["attributes"].get("last_analysis_stats", {})
        vt_malicious_count = stats.get("malicious", 0)

    # 3. Predict Class + Severity
    predicted_type, confidence = classifier.predict(cleaned_input)
    
    # 4. Score logic
    severity = get_severity(predicted_type, confidence, vt_malicious_count)
    label = get_label(severity)

    # 5. Playbook Generation
    playbook_response = playbook_engine.generate_playbook(predicted_type, severity)

    # 6. Database saving
    process_time = round((time.time() - start_time) * 1000, 2)
    incident = Incident(
        input_type=request.input_type,
        raw_input=content,
        cleaned_text=cleaned_input,
        threat_type=predicted_type,
        severity_score=severity,
        label=label,
        confidence=confidence,
        attack_vector=attack_vector,
        actions=playbook_response["actions"],
        vt_result=vt_result,
        processing_ms=process_time
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    return AnalyzeResponse(
        id=incident.id,
        input_type=incident.input_type,
        threat_type=incident.threat_type,
        severity_score=incident.severity_score,
        label=incident.label,
        confidence=incident.confidence,
        attack_vector=incident.attack_vector,
        playbook=playbook_response,
        vt_result=incident.vt_result,
        processing_ms=incident.processing_ms
    )

@router.get("/history", response_model=HistoryResponse)
async def get_history(page: int = 1, size: int = 20, db: AsyncSession = Depends(get_db)):
    offset = (page - 1) * size
    query = select(Incident).order_by(Incident.created_at.desc()).offset(offset).limit(size)
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    total_query = select(func.count(Incident.id))
    total_res = await db.execute(total_query)
    total = total_res.scalar()

    return HistoryResponse(
        items=incidents,
        total=total,
        page=page,
        size=size
    )

@router.post("/feedback")
async def receive_feedback(request: FeedbackRequest, db: AsyncSession = Depends(get_db)):
    feedback = Feedback(
        incident_id=request.incident_id,
        user_label=request.user_label,
        comments=request.comments
    )
    db.add(feedback)
    await db.commit()
    return {"status": "success", "message": "Feedback recorded."}

@router.get("/threats", response_model=ThreatStatsResponse)
async def get_threat_stats(db: AsyncSession = Depends(get_db)):
    total_query = select(func.count(Incident.id))
    total_res = await db.execute(total_query)
    total = total_res.scalar()

    dist_query = select(Incident.threat_type, func.count(Incident.id)).group_by(Incident.threat_type)
    dist_res = await db.execute(dist_query)
    distribution = {row[0]: row[1] for row in dist_res.all()}

    avg_ms_query = select(func.avg(Incident.processing_ms))
    avg_ms_res = await db.execute(avg_ms_query)
    avg_ms = avg_ms_res.scalar() or 0.0

    return {
        "total_analyzed": total,
        "threat_distribution": distribution,
        "avg_processing_time_ms": round(avg_ms, 2)
    }

@router.get("/health")
async def health_check():
    return {"status": "online", "message": "LEXA API is running."}
