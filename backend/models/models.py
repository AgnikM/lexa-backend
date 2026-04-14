from sqlalchemy import Column, String, Float, JSON, DateTime, Integer
import uuid
from backend.models.database import Base
from datetime import datetime

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    input_type = Column(String, nullable=False) # 'text', 'url', 'hash'
    raw_input = Column(String, nullable=False)
    cleaned_text = Column(String, nullable=True)
    
    threat_type = Column(String, nullable=False)
    severity_score = Column(Float, nullable=False)
    label = Column(String, nullable=False) # 'Low', 'Medium', 'High', 'Critical'
    confidence = Column(Float, nullable=False)
    
    attack_vector = Column(String, nullable=True)
    actions = Column(JSON, nullable=True) # Playbook actions applied
    vt_result = Column(JSON, nullable=True) # VirusTotal results if applicable
    
    processing_ms = Column(Float, nullable=False)


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user_label = Column(String, nullable=False) # What the user thinks it actually is
    comments = Column(String, nullable=True)
