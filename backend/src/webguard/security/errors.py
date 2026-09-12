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
