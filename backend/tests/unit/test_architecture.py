"""Regression guards against bypassing the protected networking package."""

import ast
from pathlib import Path


def test_http_client_libraries_are_confined_to_pinned_transport() -> None:
    source_root = Path(__file__).parents[2] / "src" / "webguard"
    allowed = source_root / "security" / "transport.py"
    forbidden_roots = {"aiohttp", "httpcore", "httpx", "requests"}
    violations: list[str] = []

    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".", 1)[0] in forbidden_roots and path != allowed:
                    violations.append(f"{path.relative_to(source_root)} imports {name}")

    assert not violations, (
        "HTTP libraries must remain inside security/transport.py; future code must use "
        f"SafeHttpClient. Violations: {violations}"
    )


def test_raw_socket_access_is_confined_to_security_boundary() -> None:
    source_root = Path(__file__).parents[2] / "src" / "webguard"
    allowed = {
        source_root / "security" / "resolver.py",
        source_root / "security" / "transport.py",
    }
    violations: list[str] = []

    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Import)
                and any(alias.name == "socket" for alias in node.names)
                and path not in allowed
            ):
                violations.append(str(path.relative_to(source_root)))
            if isinstance(node, ast.ImportFrom) and node.module == "socket" and path not in allowed:
                violations.append(str(path.relative_to(source_root)))

    assert not violations, (
        f"Raw socket access must remain inside the security boundary. Violations: {violations}"
    )


def test_check_modules_cannot_import_networking_paths() -> None:
    source_root = Path(__file__).parents[2] / "src" / "webguard"
    checks_root = source_root / "checks"
    forbidden_roots = {
        "aiohttp",
        "ftplib",
        "http",
        "httpcore",
        "httpx",
        "requests",
        "smtplib",
        "socket",
        "urllib",
        "urllib3",
        "websockets",
    }
    forbidden_internal = {"webguard.scanner.network"}
    violations: list[str] = []

    for path in checks_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if (
                    name.split(".", 1)[0] in forbidden_roots
                    or name in forbidden_internal
                    or name.startswith("webguard.security")
                ):
                    violations.append(f"{path.relative_to(source_root)} imports {name}")

    assert not violations, (
        "Checks receive ScanContext and must not import network clients or raw networking. "
        f"Violations: {violations}"
    )
