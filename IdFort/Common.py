import validators
import os
import base64
from IdFort.MyException import APIError, InvalidArgumentException


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


def GetEndpoint(uri):
    if uri[:4].lower() == 'http':
        return uri

    region = os.getenv('IDANALYZER_REGION', None)
    if region is None:
        return 'https://v2-us1.idanalyzer.com/{}'.format(uri)

    if region.lower() == 'eu':
        return 'https://api2-eu.idanalyzer.com/{}'.format(uri)


def ApiExceptionHandle(resp, throwError):
    respJson = resp.json()
    if 'error' in respJson and throwError:
        raise APIError(respJson['error']['message'], respJson['error']['code'])
    return respJson

