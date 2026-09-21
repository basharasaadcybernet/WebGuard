"""Static safety checks for provider-neutral Phase 10 deployment examples."""

from pathlib import Path

ROOT = Path(__file__).parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_backend_runtime_image_is_non_root_and_excludes_dev_command() -> None:
    dockerfile = read("Dockerfile.backend")
    runtime = dockerfile.split("FROM python:3.12-slim AS runtime", maxsplit=1)[1]
    assert "USER 10001:10001" in runtime
    assert 'CMD ["webguard-api"]' in runtime
    assert "EXPOSE 8000" in runtime
    assert '".[dev]"' not in runtime
    assert "pytest" not in runtime


def test_public_release_metadata_is_mit_licensed_and_versioned() -> None:
    pyproject = read("pyproject.toml")
    package = read("backend/src/webguard/__init__.py")
    dockerfile = read("Dockerfile.backend")
    license_text = read("LICENSE")

    assert 'version = "0.1.0"' in pyproject
    assert 'license = "MIT"' in pyproject
    assert 'license-files = ["LICENSE"]' in pyproject
    assert 'authors = [{ name = "Bashar Asaad" }]' in pyproject
    assert '__version__ = "0.1.0"' in package
    assert "COPY pyproject.toml README.md LICENSE ./" in dockerfile
    assert "MIT License" in license_text
    assert "Copyright (c) 2026 Bashar Asaad" in license_text


def test_public_identity_and_branding_policy_are_explicit() -> None:
    readme = read("README.md")
    branding = read("BRANDING.md")
    index = read("frontend/index.html")

    assert "Bashar Asaad" in readme
    assert "Bashar Asaad" in index
    assert "CyberNet WebGuard" not in readme
    assert "CyberNet WebGuard" not in index
    assert "No registered-trademark status is claimed" in branding
    assert "cybernet-webguard" in branding


def test_production_compose_keeps_backend_private_and_drops_privilege() -> None:
    compose = read("docker-compose.production.yml")
    backend = compose.split("  backend:", maxsplit=1)[1].split("  frontend:", maxsplit=1)[0]
    frontend = compose.split("  frontend:", maxsplit=1)[1].split("\nnetworks:", maxsplit=1)[0]
    assert "    expose:\n      - \"8000\"" in backend
    assert "    ports:" not in backend
    assert "    healthcheck:" in backend
    assert "/api/v1/health" in backend
    assert "condition: service_healthy" in frontend
    assert "      - ingress\n      - proxy" in frontend
    assert "  ingress: {}" in compose
    assert "  proxy:\n    internal: true" in compose
    assert "read_only: true" in backend
    assert "no-new-privileges:true" in backend
    assert "cap_drop:\n      - ALL" in backend
    assert "docker.sock" not in compose
    assert "network_mode: host" not in compose


def test_proxy_rejects_unknown_hosts_and_bounds_scan_ingress() -> None:
    nginx = read("deploy/nginx.conf")
    assert "listen 8080 default_server" in nginx
    assert "return 444" in nginx
    assert "server_name webguard.example.invalid" in nginx
    assert "client_max_body_size 4k" in nginx
    assert '"POST:/api/v1/scans" $binary_remote_addr' in nginx
    assert "limit_req_status 429" in nginx
    assert "limit_conn_status 503" in nginx
    assert "proxy_read_timeout 95s" in nginx


def test_local_validation_keeps_production_proxy_policy_unchanged() -> None:
    production = read("deploy/nginx.conf")
    local = read("deploy/nginx.local-validation.conf")
    assert local == production.replace(
        "server_name webguard.example.invalid;", "server_name webguard.localhost;"
    )

    override = read("docker-compose.local-validation.yml")
    assert "WEBGUARD_ALLOWED_HOSTS: webguard.localhost" in override
    assert "./deploy/nginx.local-validation.conf" in override


def test_proxy_overwrites_forwarded_client_data_and_disables_api_cache() -> None:
    nginx = read("deploy/nginx.conf")
    assert "proxy_set_header X-Forwarded-For $remote_addr" in nginx
    assert "$proxy_add_x_forwarded_for" not in nginx
    assert 'proxy_set_header Forwarded ""' in nginx
    assert 'add_header Cache-Control "no-store" always' in nginx
    assert "proxy_cache off" in nginx


def test_frontend_policy_is_self_hosted_and_source_maps_are_disabled() -> None:
    nginx = read("deploy/nginx.conf")
    vite = read("frontend/vite.config.ts")
    index = read("frontend/index.html")
    assert "connect-src 'self'" in nginx
    assert "script-src 'self'" in nginx
    assert "sourcemap: false" in vite
    assert "https://" not in index
    assert "http://" not in index


def test_example_environment_contains_no_wildcard_or_secret_value() -> None:
    example = read(".env.example")
    assert "WEBGUARD_ENV=production" in example
    assert "WEBGUARD_DEBUG=false" in example
    assert "WEBGUARD_ALLOWED_HOSTS=*" not in example
    assert "WEBGUARD_TRUSTED_PROXIES=*" not in example
    assert "password=" not in example.lower()
    assert "token=" not in example.lower()


def test_backend_image_uses_reviewed_production_constraints() -> None:
    dockerfile = read("Dockerfile.backend")
    constraints = read("requirements.production.txt")
    assert "--constraint requirements.production.txt" in dockerfile
    assert "fastapi==" in constraints
    assert "httpx==" in constraints
    assert "uvicorn==" in constraints
    assert "pytest==" not in constraints
    assert "ruff==" not in constraints
