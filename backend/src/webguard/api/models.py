"""Versioned public request, success, and error contracts for the REST adapter."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator

from webguard.api.config import API_SCHEMA_VERSION, API_VERSION
from webguard.domain.models import ContractModel
from webguard.reporting import ReportDocument


class ApiErrorCode(StrEnum):
    """Stable machine-readable execution errors, never security findings."""

    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_TARGET = "INVALID_TARGET"
    INVALID_HOST = "INVALID_HOST"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    RATE_LIMITED = "RATE_LIMITED"
    SERVICE_BUSY = "SERVICE_BUSY"
    SCAN_TIMEOUT = "SCAN_TIMEOUT"
    CLIENT_DISCONNECTED = "CLIENT_DISCONNECTED"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ScanApiRequest(ContractModel):
    """The complete public scan input; scanner policy is intentionally absent."""

    target: Annotated[str, StringConstraints(min_length=1, max_length=2048)] = Field(
        description="Absolute HTTP or HTTPS URL to inspect passively.",
        examples=["https://example.com"],
    )

    @field_validator("target")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Target cannot contain control characters")
        return value


class ScanApiResponse(ContractModel):
    """Small API envelope around the shared Phase 7 report contract."""

    api_version: Literal["v1"] = API_VERSION
    api_schema_version: Literal["1.0"] = API_SCHEMA_VERSION
    request_id: UUID
    report: ReportDocument


class HealthResponse(ContractModel):
    status: Literal["ok"] = "ok"


class VersionResponse(ContractModel):
    webguard_version: str
    api_version: Literal["v1"] = API_VERSION
    api_schema_version: Literal["1.0"] = API_SCHEMA_VERSION
    report_schema_version: str
    ruleset_version: str
    scoring_version: str


class ApiErrorResponse(ContractModel):
    code: ApiErrorCode
    message: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    request_id: UUID
