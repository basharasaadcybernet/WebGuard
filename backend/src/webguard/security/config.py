"""Conservative network limits for the security boundary."""

from pydantic import BaseModel, ConfigDict, Field, model_validator


class NetworkLimits(BaseModel):
    """Immutable limits applied to all outbound requests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_ports: frozenset[int] = frozenset({80, 443})
    dns_timeout_seconds: float = Field(default=3.0, gt=0, le=15)
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    read_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    write_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    pool_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    total_timeout_seconds: float = Field(default=15.0, gt=0, le=60)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    max_requests: int = Field(default=8, ge=1, le=20)

    @model_validator(mode="after")
    def validate_ports(self) -> "NetworkLimits":
        if not self.allowed_ports or any(port < 1 or port > 65535 for port in self.allowed_ports):
            raise ValueError("allowed_ports must contain valid TCP ports")
        return self
