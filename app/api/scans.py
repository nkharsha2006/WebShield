from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.connectivity import check_local_connectivity
from app.database import get_db
from app.models import Application, ConnectivityResult, ScanRun
from app.scan_schemas import ScanRunRead

router = APIRouter(tags=["Scans"])


def utc_now():
    return datetime.now(UTC)


@router.post(
    "/applications/{application_id}/scans",
    response_model=ScanRunRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scan_run(
    application_id: int,
    db: Session = Depends(get_db),
):
    application = db.get(Application, application_id)

    if application is None:
        raise HTTPException(
            status_code=404,
            detail="Application not found.",
        )

    if not application.is_active:
        raise HTTPException(
            status_code=409,
            detail="Application is inactive.",
        )

    scan = ScanRun(
        application_id=application_id,
        status="QUEUED",
        scanner="pending",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


@router.post("/scans/{scan_id}/run-connectivity")
def run_scan_connectivity(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = db.get(ScanRun, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan run not found.",
        )

    if scan.status != "QUEUED":
        raise HTTPException(
            status_code=409,
            detail=f"Scan cannot run from status {scan.status}.",
        )

    application = db.get(Application, scan.application_id)

    if application is None:
        raise HTTPException(
            status_code=404,
            detail="Application not found.",
        )

    if not application.is_active:
        raise HTTPException(
            status_code=409,
            detail="Application is inactive.",
        )

    scan.status = "RUNNING"
    scan.scanner = "connectivity-check"
    scan.started_at = utc_now()
    scan.error_message = None
    db.commit()

    try:
        result = check_local_connectivity(application.base_url)

        saved_result = ConnectivityResult(
            scan_id=scan.id,
            reachable=result["reachable"],
            http_status=result["http_status"],
            elapsed_ms=result["elapsed_ms"],
            message=result["message"],
            checked_at=utc_now(),
        )

        scan.status = "COMPLETED" if result["reachable"] else "FAILED"
        scan.completed_at = utc_now()

        if not result["reachable"]:
            scan.error_message = result["message"]

        db.add(saved_result)
        db.commit()
        db.refresh(scan)
        db.refresh(saved_result)

        return {
            "scan": ScanRunRead.model_validate(scan).model_dump(),
            "connectivity": {
                "id": saved_result.id,
                "scan_id": saved_result.scan_id,
                "reachable": saved_result.reachable,
                "http_status": saved_result.http_status,
                "elapsed_ms": saved_result.elapsed_ms,
                "message": saved_result.message,
                "checked_at": saved_result.checked_at,
            },
        }

    except Exception as exc:
        db.rollback()

        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            scan.status = "FAILED"
            scan.completed_at = utc_now()
            scan.error_message = f"Connectivity assessment error: {type(exc).__name__}"
            db.commit()

        raise HTTPException(
            status_code=500,
            detail="The connectivity assessment could not be saved.",
        ) from exc


@router.get(
    "/scans",
    response_model=list[ScanRunRead],
)
def list_scan_runs(
    application_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
):
    query = db.query(ScanRun)

    if application_id is not None:
        query = query.filter(ScanRun.application_id == application_id)

    return query.order_by(ScanRun.id.desc()).all()


@router.get(
    "/scans/{scan_id}/connectivity-result",
)
def get_connectivity_result(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = db.get(ScanRun, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan run not found.",
        )

    result = (
        db.query(ConnectivityResult)
        .filter(ConnectivityResult.scan_id == scan_id)
        .first()
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="No saved connectivity result for this scan.",
        )

    return {
        "id": result.id,
        "scan_id": result.scan_id,
        "reachable": result.reachable,
        "http_status": result.http_status,
        "elapsed_ms": result.elapsed_ms,
        "message": result.message,
        "checked_at": result.checked_at,
    }


@router.get(
    "/scans/{scan_id}",
    response_model=ScanRunRead,
)
def get_scan_run(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = db.get(ScanRun, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan run not found.",
        )

    return scan


@router.post(
    "/applications/{application_id}/connectivity-check",
)
def run_application_connectivity_check(
    application_id: int,
    db: Session = Depends(get_db),
):
    application = db.get(Application, application_id)

    if application is None:
        raise HTTPException(
            status_code=404,
            detail="Application not found.",
        )

    if not application.is_active:
        raise HTTPException(
            status_code=409,
            detail="Application is inactive.",
        )

    result = check_local_connectivity(application.base_url)

    return {
        "application_id": application.id,
        "application_name": application.name,
        "target_url": application.base_url,
        **result,
    }
