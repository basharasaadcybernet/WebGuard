"""Static checks for the self-contained local WebGuard release."""

from pathlib import Path

ROOT = Path(__file__).parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_public_release_metadata_is_mit_licensed_versioned_and_self_contained() -> None:
    pyproject = read("pyproject.toml")
    package = read("backend/src/webguard/__init__.py")
    license_text = read("LICENSE")

    assert 'version = "0.1.0"' in pyproject
    assert 'license = "MIT"' in pyproject
    assert 'license-files = ["LICENSE"]' in pyproject
    assert 'authors = [{ name = "Bashar Asaad" }]' in pyproject
    assert '__version__ = "0.1.0"' in package
    assert 'webguard = "webguard.cli.app:main"' in pyproject
    assert "webguard-api" not in pyproject
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


def test_obsolete_external_runtime_artifacts_are_removed() -> None:
    removed = (
        ".dockerignore",
        ".env.example",
        "Dockerfile.backend",
        "Dockerfile.frontend",
        "docker-compose.yml",
        "docker-compose.production.yml",
        "docker-compose.local-validation.yml",
        "requirements.production.txt",
        "deploy/nginx.conf",
        "deploy/nginx.local-validation.conf",
        "docs/DEPLOYMENT.md",
        "docs/PRODUCTION_CHECKLIST.md",
    )

    assert all(not (ROOT / path).exists() for path in removed)
    assert "docker" not in read("README.md").lower()


def test_frontend_build_targets_the_python_package_without_source_maps() -> None:
    vite = read("frontend/vite.config.ts")
    static = ROOT / "backend/src/webguard/web/static"
    index = (static / "index.html").read_text(encoding="utf-8")

    assert 'outDir: "../backend/src/webguard/web/static"' in vite
    assert "sourcemap: false" in vite
    assert static.is_dir()
    assert (static / "brand/logo.svg").is_file()
    assert any((static / "assets").glob("*.js"))
    assert any((static / "assets").glob("*.css"))
    assert not any(static.rglob("*.map"))
    assert "https://" not in index
    assert "http://" not in index


def test_release_docs_use_the_single_webguard_web_workflow() -> None:
    readme = read("README.md")
    cli = read("docs/CLI.md")
    web = read("docs/WEB.md")

    for document in (readme, cli, web):
        assert "webguard web" in document
        assert "webguard-api" not in document
        assert "docker" not in document.lower()
