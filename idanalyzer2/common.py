"""Internal helper utilities shared by the ID Analyzer v2 SDK clients.

This module contains the low-level helpers used by the API client classes:
input normalization (:func:`ParseInput`), endpoint/region resolution
(:func:`GetEndpoint`), and API response/error handling
(:func:`ApiExceptionHandle`). These functions are implementation details of
the SDK and are not part of the supported public API.
"""

import validators
import os
import base64
from .myException import APIError, InvalidArgumentException


def ParseInput(str, allowCache=False):
    """Normalize an image input into a value the API accepts.

    Accepts a cache reference, a remote URL, a local file path, or a raw
    base64 string, and returns the value in the form expected by the API.
    Local file paths are read from disk and base64-encoded; URLs, cache
    references, and long base64 strings are passed through unchanged.

    Args:
        str (str): The image input. May be a ``ref:``-prefixed cache
            reference (only honored when ``allowCache`` is True), an HTTP(S)
            URL, a path to a local file, or a base64-encoded image string.
        allowCache (bool): Whether to accept a ``ref:`` cache reference and
            pass it through unchanged. Defaults to False.

    Returns:
        str: The cache reference, URL, or base64-encoded image content
        suitable for submission to the API.

    Raises:
        InvalidArgumentException: If the input is not a valid cache
            reference, URL, existing file path, or sufficiently long base64
            string.
    """
    if allowCache and str[:4] == 'ref:':
        return str
    if validators.url(str):
        return str

    if os.path.exists(str):
        f = open(str, 'rb')
        content = f.read()
        f.close()
        return base64.b64encode(content).decode('ascii')

    if len(str) > 100:
        return str

    raise InvalidArgumentException('Invalid input image, file not found or malformed URL.')


_REGION_ENDPOINTS = {
    'us': 'https://api2.idanalyzer.com',
    'eu': 'https://api2-eu.idanalyzer.com',
}


def GetEndpoint(uri):
    """Resolve an API path into a fully-qualified endpoint URL.

    If ``uri`` is already an absolute HTTP(S) URL it is returned unchanged.
    Otherwise the regional API base URL is selected from the
    ``IDANALYZER_REGION`` environment variable (``us`` or ``eu``, defaulting
    to ``us``) and ``uri`` is appended as a path.

    Args:
        uri (str): An absolute HTTP(S) URL, or an API path relative to the
            regional base URL (for example ``"scan"`` or
            ``"transaction/{id}"``).

    Returns:
        str: The fully-qualified endpoint URL to request.

    Raises:
        InvalidArgumentException: If ``IDANALYZER_REGION`` is set to a value
            other than a supported region (``us`` or ``eu``).
    """
    if uri[:4].lower() == 'http':
        return uri

    region = (os.getenv('IDANALYZER_REGION') or 'us').lower()
    if region not in _REGION_ENDPOINTS:
        raise InvalidArgumentException(
            "Invalid IDANALYZER_REGION '{}', valid regions are: {}.".format(
                region, ', '.join(sorted(_REGION_ENDPOINTS))))

    return '{}/{}'.format(_REGION_ENDPOINTS[region], uri)


def ApiExceptionHandle(resp, throwError):
    """Parse an API response and optionally raise on a reported error.

    Decodes the JSON body of an API response. If the body contains an
    ``error`` object and error throwing is enabled, an :class:`APIError` is
    raised; otherwise the decoded body is returned to the caller as-is.

    Args:
        resp (requests.Response): The HTTP response returned by a requests
            call to the API.
        throwError (bool): Whether to raise :class:`APIError` when the
            response body contains an ``error`` object. When False, error
            responses are returned to the caller unchanged.

    Returns:
        dict: The decoded JSON response body.

    Raises:
        APIError: If ``throwError`` is True and the response body contains an
            ``error`` object. The exception message is the API error message
            and ``args[1]`` is the API error code.
    """
    respJson = resp.json()
    if 'error' in respJson and throwError:
        raise APIError(respJson['error']['message'], respJson['error']['code'])
    return respJson

