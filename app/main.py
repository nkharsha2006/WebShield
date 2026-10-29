from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.api.applications import router as applications_router
from app.api.dashboard import router as dashboard_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.api.security import router as security_router
from app.api.zap import router as zap_router
from app.database import Base, SessionLocal, engine
from app.models import VulnerabilityFinding
from app.api.zap_scans import router as zap_scans_router

BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Create any missing tables without deleting existing data.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="WebShield",
    description=(
        "Evidence-Based Web Vulnerability Verification "
        "and Regression Detection Platform"
    ),
    version="0.7.0",
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request):
    """Render the WebShield dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={},
    )


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get(
    "/findings/{finding_id}/view",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def finding_details_page(
    finding_id: int,
    request: Request,
):
    """Render the HTML page for an existing finding."""
    db = SessionLocal()

    try:
        finding = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.id == finding_id)
            .first()
        )

        if finding is None:
            return HTMLResponse(
                content="<h1>Finding not found</h1><p>Check the finding ID and try again.</p><p><a href='/'>Return to dashboard</a></p>",
                status_code=404,
            )

        return templates.TemplateResponse(
            request=request,
            name="finding_details.html",
            context={},
        )
    finally:
        db.close()


# Preserve every existing API router.
app.include_router(applications_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(zap_router)
app.include_router(security_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
app.include_router(zap_scans_router)
