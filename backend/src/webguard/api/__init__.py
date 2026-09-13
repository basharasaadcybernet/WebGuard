"""Secure, stateless REST adapter for the existing WebGuard engine."""

from webguard.api.app import create_app
from webguard.api.config import API_SCHEMA_VERSION, API_VERSION, ApiSettings

__all__ = ["API_SCHEMA_VERSION", "API_VERSION", "ApiSettings", "create_app"]
