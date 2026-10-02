from sqlalchemy import Column, String, Float, DateTime, Integer, Boolean, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True)
    debian_release = Column(String(50), nullable=False)
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=False)
    package_type = Column(String(20), nullable=False)
    latest_available_version = Column(String(100))
    repository_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)

class CVEVerdict(Base):
    __tablename__ = "cve_verdicts"

    id = Column(Integer, primary_key=True)
    package_id = Column(Integer, ForeignKey("packages.id"))
    cve_id = Column(String(20), nullable=False)
    applicability_verdict = Column(String(20), nullable=False)
    verdict_success = Column(Boolean)
    verdict_confidence = Column(Float)
    justification_text = Column(String(2000))
    analysis_timestamp = Column(DateTime)
    retry_count = Column(Integer, default=0)
    last_retry_time = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AssessmentRequest(Base):
    __tablename__ = "assessment_requests"

    id = Column(Integer, primary_key=True)
    request_id = Column(String(36), unique=True)
    smart_patch_instance_id = Column(String(255))
    sonic_version = Column(String(100))
    cve_list = Column(JSON)
    device_context = Column(JSON)
    response_cached = Column(Boolean)
    assessment_duration_ms = Column(Integer)
    submitted_at = Column(DateTime, default=datetime.utcnow)

class AsyncOperation(Base):
    __tablename__ = "async_operations"

    id = Column(Integer, primary_key=True)
    operation_id = Column(String(36), unique=True)
    operation_type = Column(String(50))
    status = Column(String(20))
    progress_percentage = Column(Integer)
    error_message = Column(String(500))
    log_file_path = Column(String(500))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_by = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

class MetricsSnapshot(Base):
    __tablename__ = "metrics_snapshots"

    id = Column(Integer, primary_key=True)
    snapshot_time = Column(DateTime, nullable=False)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Float)
    smart_patch_instance_id = Column(String(255))
    tags = Column(JSON)
    recorded_at = Column(DateTime, default=datetime.utcnow)
