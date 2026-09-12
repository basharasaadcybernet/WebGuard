"""Enums used in serialized WebGuard contracts."""

from enum import StrEnum


class FindingStatus(StrEnum):
    """Outcome of an individual posture rule."""

    PASS = "PASS"
    INFO = "INFO"
    WARNING = "WARNING"
    FAIL = "FAIL"
    ERROR = "ERROR"


class Severity(StrEnum):
    """Security relevance of a non-pass finding."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HttpScheme(StrEnum):
    """Schemes the network boundary accepts."""

    HTTP = "http"
    HTTPS = "https"


class ScanState(StrEnum):
    """Completion state of a scan."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ScanErrorKind(StrEnum):
    """Origin of a non-vulnerability operational scan error."""

    TARGET = "TARGET"
    NETWORK = "NETWORK"
    CHECK = "CHECK"


class Grade(StrEnum):
    """Future human-readable score grade."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
