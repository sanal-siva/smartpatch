from sqlalchemy.orm import Session
from app.db.models import Package, CVEVerdict, AssessmentRequest, AsyncOperation, MetricsSnapshot
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class DBOperations:
    @staticmethod
    def create_package(db: Session, debian_release: str, package_name: str, version: str, pkg_type: str):
        pkg = Package(
            debian_release=debian_release,
            package_name=package_name,
            package_version=version,
            package_type=pkg_type
        )
        db.add(pkg)
        db.commit()
        return pkg

    @staticmethod
    def create_cve_verdict(db: Session, package_id: int, cve_id: str, verdict: str, confidence: float, justification: str):
        verdict_obj = CVEVerdict(
            package_id=package_id,
            cve_id=cve_id,
            applicability_verdict=verdict,
            verdict_confidence=confidence,
            justification_text=justification,
            analysis_timestamp=datetime.utcnow()
        )
        db.add(verdict_obj)
        db.commit()
        return verdict_obj

    @staticmethod
    def log_assessment_request(db: Session, request_id: str, smart_patch_id: str, sonic_version: str, cve_list: list, cached: bool, duration_ms: int):
        req = AssessmentRequest(
            request_id=request_id,
            smart_patch_instance_id=smart_patch_id,
            sonic_version=sonic_version,
            cve_list=cve_list,
            response_cached=cached,
            assessment_duration_ms=duration_ms
        )
        db.add(req)
        db.commit()
        return req

    @staticmethod
    def create_async_operation(db: Session, operation_id: str, op_type: str, created_by: str = "system"):
        op = AsyncOperation(
            operation_id=operation_id,
            operation_type=op_type,
            status="queued",
            progress_percentage=0,
            created_by=created_by
        )
        db.add(op)
        db.commit()
        return op

    @staticmethod
    def update_operation_status(db: Session, operation_id: str, status: str, progress: int = 0, error: str = None):
        op = db.query(AsyncOperation).filter(AsyncOperation.operation_id == operation_id).first()
        if op:
            op.status = status
            op.progress_percentage = progress
            if error:
                op.error_message = error
            if status in ["completed", "failed"]:
                op.completed_at = datetime.utcnow()
            db.commit()
        return op
