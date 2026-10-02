"""Exercise the public shell without starting scanners, jobs, or a database."""
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from httpx import AsyncClient, ASGITransport

from app.ui.routes import router, PAGES, ALIASES

UI_ROOT = Path(__file__).parents[2] / "app" / "ui"


@pytest.fixture
def client():
    app = FastAPI()
    app.mount("/ui/static", StaticFiles(directory=UI_ROOT / "static"), name="static")
    app.include_router(router)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
@pytest.mark.parametrize("route,page", PAGES.items())
async def test_operational_routes_render_public_shell_without_credentials(client, route, page):
    response = await client.get(f"/ui/{route}")
    assert response.status_code == 200
    assert f'data-page="{page}"' in response.text
    assert 'id="auth-dialog"' in response.text
    assert 'type="password"' in response.text
    assert 'Awaiting connection' in response.text
    assert 'frame-ancestors \'none\'' in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    # Navigation is public, operational data is fetched only after authentication.
    assert 'id="page-content"' in response.text
    assert "Bearer " not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("old,new", ALIASES.items())
async def test_legacy_routes_land_on_working_views(client, old, new):
    response = await client.get(f"/ui/{old}", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == f"/ui/{new}"


@pytest.mark.asyncio
async def test_unknown_page_does_not_select_an_arbitrary_template(client):
    assert (await client.get("/ui/unregistered-page")).status_code == 404


@pytest.mark.asyncio
async def test_assets_are_local_and_available(client):
    response = await client.get("/ui/")
    assert 'src="https://' not in response.text
    assert 'href="https://' not in response.text
    for path in ("/ui/static/css/style.css", "/ui/static/js/app.js"):
        assert path in response.text
        asset = UI_ROOT / "static" / path.removeprefix("/ui/static/")
        assert asset.is_file()
        assert asset.stat().st_size > 1000


def test_untrusted_api_content_has_no_html_execution_sink():
    script = (UI_ROOT / "static" / "js" / "app.js").read_text()
    for unsafe in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write(", "eval("):
        assert unsafe not in script
    assert "sessionStorage.setItem(TOKEN_KEY, token)" in script
    assert "localStorage.setItem(TOKEN_KEY" not in script
    assert "redirect: 'error'" in script
    assert "headers.set('Authorization'" in script
