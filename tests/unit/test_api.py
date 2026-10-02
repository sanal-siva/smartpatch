"""Import compatibility check; authenticated lifecycle coverage lives in integration."""
from app.main import app, create_app


def test_application_factory_exposes_smart_patch_routes_without_starting_workers():
    assert callable(create_app)
    paths = {getattr(route, 'path', None) for route in app.routes}
    assert {'/health', '/api/v1/agents/sync', '/api/v1/findings'} <= paths
    assert app.state.runtime is None
