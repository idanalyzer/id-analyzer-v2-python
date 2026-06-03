"""Exception types raised by the ID Analyzer v2 SDK.

This module defines the two exception classes used throughout the SDK:

- :class:`APIError` for errors reported by the ID Analyzer API itself.
- :class:`InvalidArgumentException` for client-side argument validation
  failures raised before any request is sent.
"""


class APIError(Exception):
    """Raised when the ID Analyzer API returns an error response.

    This exception is only raised when exception throwing has been enabled
    on an API client via ``throwApiException(True)``. When raised, the
    exception message contains the human-readable error message returned by
    the API and ``args[1]`` contains the API error code.

    Args:
        message (str): Human-readable error message returned by the API.
        code: Machine-readable error code returned by the API.
    """

    pass


class InvalidArgumentException(Exception):
    """Raised when an argument supplied to the SDK fails client-side validation.

    This exception is raised locally (before any HTTP request is made) when a
    required parameter is missing, malformed, or otherwise invalid, for
    example an unparseable image input, an out-of-range ``limit``, or an
    invalid webhook URL.

    Args:
        message (str): Human-readable description of the validation failure.
    """

    pass