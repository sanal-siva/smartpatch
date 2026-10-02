"""Public application shell; every operational API requires authentication."""
import hashlib
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(prefix="/ui", tags=["ui"])
UI_ROOT = Path(__file__).parent
templates = Jinja2Templates(directory=str(UI_ROOT / "templates"))
ASSET_VERSION = hashlib.sha256(b"".join((UI_ROOT / path).read_bytes() for path in
    ("static/css/style.css", "static/js/app.js"))).hexdigest()[:12]

UI_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
}

PAGES = {
    "": "overview", "fleet": "fleet", "findings": "findings",
    "coverage": "coverage", "changes": "changes", "plans": "plans",
    "jobs": "jobs", "tools": "tools", "settings": "settings",
    "tokens": "tokens", "releases": "releases",
    "packages-trends": "packages-trends", "cve-trends": "cve-trends",
    "request-status": "request-status",
    "remediation-status": "remediation-status",
}
ALIASES = {
    "setup": "settings",
    "smart-patch-integration": "fleet",
}


@router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse(request=request, name="workspace.html", context={"page": "overview", "asset_version": ASSET_VERSION}, headers=UI_HEADERS)


@router.get("/{page}", response_class=HTMLResponse)
async def workspace(request: Request, page: str):
    if page in ALIASES:
        return RedirectResponse(f"/ui/{ALIASES[page]}", status_code=307)
    if page not in PAGES:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Page not found")
    return templates.TemplateResponse(request=request, name="workspace.html", context={"page": PAGES[page], "asset_version": ASSET_VERSION}, headers=UI_HEADERS)
