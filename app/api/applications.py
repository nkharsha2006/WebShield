from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Application
from app.schemas import (
    ApplicationCreate,
    ApplicationRead,
    ApplicationStatusUpdate,
)

router = APIRouter(
    prefix="/applications",
    tags=["Applications"],
)


def validate_lab_url(url: str) -> str:
    """Allow only explicitly local lab targets in this prototype."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid target URL or port.",
        ) from exc

    if (
        parsed.scheme not in {"http", "https"}
        or hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(
            status_code=422,
            detail="Only local lab URLs are allowed in this prototype.",
        )

    return url


@router.post(
    "",
    response_model=ApplicationRead,
    status_code=status.HTTP_201_CREATED,
)
def register_application(
    payload: ApplicationCreate,
    db: Session = Depends(get_db),
):
    name = payload.name.strip()

    if not name:
        raise HTTPException(
            status_code=422,
            detail="Application name cannot be blank.",
        )

    base_url = validate_lab_url(payload.base_url)

    application = Application(
        name=name,
        base_url=base_url,
        is_active=payload.is_active,
    )

    db.add(application)
    db.commit()
    db.refresh(application)

    return application


@router.get(
    "",
    response_model=list[ApplicationRead],
)
def list_applications(db: Session = Depends(get_db)):
    return db.query(Application).order_by(Application.id).all()


@router.patch(
    "/{application_id}",
    response_model=ApplicationRead,
)
def update_application_status(
    application_id: int,
    payload: ApplicationStatusUpdate,
    db: Session = Depends(get_db),
):
    application = db.get(Application, application_id)

    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found.",
        )

    application.is_active = payload.is_active
    db.commit()
    db.refresh(application)

    return application
