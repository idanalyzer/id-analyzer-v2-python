import validators
import os
import base64
from .myException import APIError, InvalidArgumentException


def ParseInput(str, allowCache=False):
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
    if uri[:4].lower() == 'http':
        return uri

    region = (os.getenv('IDANALYZER_REGION') or 'us').lower()
    if region not in _REGION_ENDPOINTS:
        raise InvalidArgumentException(
            "Invalid IDANALYZER_REGION '{}', valid regions are: {}.".format(
                region, ', '.join(sorted(_REGION_ENDPOINTS))))

    return '{}/{}'.format(_REGION_ENDPOINTS[region], uri)


def ApiExceptionHandle(resp, throwError):
    respJson = resp.json()
    if 'error' in respJson and throwError:
        raise APIError(respJson['error']['message'], respJson['error']['code'])
    return respJson

