"""Fail-closed exceptions raised by the security boundary."""


class SecurityBoundaryError(Exception):
    """Base class for safe, expected boundary failures."""


class URLPolicyError(SecurityBoundaryError):
    """The submitted URL violates the accepted URL policy."""


class DNSResolutionError(SecurityBoundaryError):
    """The hostname could not be resolved safely."""


class BlockedAddressError(SecurityBoundaryError):
    """At least one resolved address is not globally routable."""


class RedirectPolicyError(SecurityBoundaryError):
    """A redirect violates a limit or target policy."""


class RequestBudgetExceeded(SecurityBoundaryError):
    """The scan attempted more outbound requests than permitted."""


class RequestTimedOut(SecurityBoundaryError):
    """An outbound request exceeded a configured timeout."""


class ResponseTooLarge(SecurityBoundaryError):
    """A response exceeded its configured decoded-byte limit."""


class TransportError(SecurityBoundaryError):
    """The pinned transport failed without exposing unsafe internals."""


class EndpointUnavailable(SecurityBoundaryError):
    """The validated destination could not establish a connection."""


class ConnectionRefused(SecurityBoundaryError):
    """The validated destination explicitly refused the connection."""


class ConnectionTerminated(SecurityBoundaryError):
    """The peer reset or prematurely terminated the connection."""


class TLSHandshakeFailed(SecurityBoundaryError):
    """TLS negotiation failed without reliable certificate-specific evidence."""


class TLSCertificateUntrusted(SecurityBoundaryError):
    """TLS certificate chain validation did not establish trust."""


class TLSHostnameMismatch(SecurityBoundaryError):
    """TLS certificate identity did not match the validated hostname."""


class TLSCertificateExpired(SecurityBoundaryError):
    """TLS certificate validation reported an expired certificate."""
