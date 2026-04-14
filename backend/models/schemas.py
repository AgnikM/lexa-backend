from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class AnalyzeRequest(BaseModel):
    input_type: str = Field(..., pattern='^(text|url|hash)$', description="Type of input: text, url, or hash")
    content: str = Field(..., description="The actual text content, URL, or File Hash to analyze")

class ActionNode(BaseModel):
    description: str
    priority: str

class AnalyzedPlaybook(BaseModel):
    summary: str
    actions: List[ActionNode]
    prevention: List[str]
    references: List[str]

class AnalyzeResponse(BaseModel):
    id: str
    input_type: str
    threat_type: str
    severity_score: float
    label: str
    confidence: float
    attack_vector: Optional[str] = None
    playbook: Optional[AnalyzedPlaybook] = None
    vt_result: Optional[Dict[str, Any]] = None
    processing_ms: float

class HistoryResponse(BaseModel):
    items: List[AnalyzeResponse]
    total: int
    page: int
    size: int

class FeedbackRequest(BaseModel):
    incident_id: str
    user_label: str
    comments: Optional[str] = None

class ThreatStatsResponse(BaseModel):
    total_analyzed: int
    threat_distribution: Dict[str, int]
    avg_processing_time_ms: float
