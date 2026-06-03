"""Core API client classes for the ID Analyzer v2 SDK.

This module implements the public API client classes used to interact with
the ID Analyzer API v2:

- :class:`Profile` — build and override a KYC profile configuration.
- :class:`Scanner` — scan identity documents and perform ID face verification.
- :class:`Biometric` — standalone 1:1 face verification and liveness checks.
- :class:`Contract` — generate documents and manage contract templates.
- :class:`Transaction` — retrieve, list, update, delete and export transactions.
- :class:`Docupass` — create and manage Docupass hosted verification sessions.
- :class:`AML` — AML / PEP / sanctions screening.
- :class:`ProfileAPI` — server-side KYC profile management (CRUD + export).
- :class:`Webhook` — webhook delivery log management.
- :class:`Account` — account profile, quota and usage information.

All API client classes derive from the internal :class:`_ApiParent` base
class, which handles authentication, the shared HTTP session, and common
configuration. The API key is read from the ``IDANALYZER_KEY`` environment
variable unless supplied explicitly, and the target region is read from
``IDANALYZER_REGION``.
"""

import os
import json
import re
from urllib.parse import urlparse
import ipaddress
from .myException import APIError, InvalidArgumentException
from .common import ParseInput, GetEndpoint, ApiExceptionHandle
import requests
import datetime


class _ApiParent:
    """Base class for all ID Analyzer API client objects.

    Provides shared behaviour for the concrete API clients: resolving the API
    key, holding the mutable request configuration, and owning the
    authenticated :class:`requests.Session` used for all HTTP calls. This
    class is an internal implementation detail and is not intended to be
    instantiated directly.
    """

    def __init__(self, apiKey=None):
        """Initialize the API client and authenticated HTTP session.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted (or
                None), the key is read from the ``IDANALYZER_KEY`` environment
                variable. Defaults to None.

        Raises:
            Exception: If no API key is supplied and the ``IDANALYZER_KEY``
                environment variable is unset or empty.
        """
        self.apiKey = self.getApiKey(apiKey)
        self.client_library = "python-sdk"
        if self.apiKey is None or self.apiKey == "":
            raise Exception("Please set API key via environment variable 'IDANALYZER_KEY'")
        self.config = {
            "client": self.client_library,
        }
        self.throwError = False
        self.http = requests.session()
        self.http.headers = {
            'Content-Type': 'application/json',
            'X-Api-Key': self.apiKey,
        }

    def getApiKey(self, customKey=None):
        """Resolve the API key to use for requests.

        Args:
            customKey (str, optional): An explicitly supplied API key. If
                None, the key is read from the ``IDANALYZER_KEY`` environment
                variable. Defaults to None.

        Returns:
            str or None: The resolved API key, or None if neither a custom key
            nor the ``IDANALYZER_KEY`` environment variable is set.
        """
        return customKey if customKey is not None else os.getenv('IDANALYZER_KEY', None)

    def setParam(self, key, value):
        """Set an arbitrary API parameter and its value.

        This allows you to set any API parameter directly without using the
        built-in helper methods, for example to use a feature not yet exposed
        by a dedicated method.

        Args:
            key (str): Parameter key.
            value: Parameter value.

        Returns:
            None
        """
        self.config[key] = value

    def throwApiException(self, sw=False):
        """Configure whether API errors raise an exception.

        Controls whether an :class:`APIError` is raised when an API response
        contains an error message, instead of returning the error body to the
        caller.

        Args:
            sw (bool): If True, raise :class:`APIError` upon an API error. If
                False, return the error response unchanged. Defaults to False.

        Returns:
            None
        """
        self.throwError = sw


class Profile:
    """KYC profile configuration for scan and verification requests.

    A profile selects a base server-side KYC profile (either a custom profile
    ID or one of the built-in security presets) and optionally layers
    per-request overrides on top of it. The override-building methods on this
    class mutate :attr:`profileOverride`, which is then attached to a
    :class:`Scanner` or :class:`Biometric` request via their ``setProfile``
    methods.

    Attributes:
        SECURITY_NONE (str): Built-in preset with no validation security.
        SECURITY_LOW (str): Built-in preset with low validation security.
        SECURITY_MEDIUM (str): Built-in preset with medium validation security.
        SECURITY_HIGH (str): Built-in preset with high validation security.
        profileId (str): The selected base profile ID or preset.
        profileOverride (dict): Per-request configuration overrides.
    """

    SECURITY_NONE = "security_none"
    SECURITY_LOW = "security_low"
    SECURITY_MEDIUM = "security_medium"
    SECURITY_HIGH = "security_high"

    def __init__(self, profileId):
        """Initialize a KYC profile.

        Args:
            profileId (str): Custom profile ID or one of the preset profiles
                (``security_none``, ``security_low``, ``security_medium``,
                ``security_high``). If left blank, :attr:`SECURITY_NONE` is
                used.
        """
        self.URL_VALIDATION_REGEX = "((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        self.profileId = profileId if profileId != '' else self.SECURITY_NONE
        self.profileOverride = {}

    def loadFromJson(self, jsonStr: str):
        """Replace the profile overrides with values from a JSON string.

        Args:
            jsonStr (str): JSON string containing profile override information.
                It is parsed and used to replace :attr:`profileOverride`.

        Returns:
            None
        """
        self.profileOverride = json.loads(jsonStr)

    def canvasSize(self, pixels: int):
        """Set the maximum canvas size, in pixels, for input images.

        Input images larger than this size are scaled down before further
        processing. A smaller image improves inference time but reduces result
        accuracy. Set to 0 to disable image resizing.

        Args:
            pixels (int): Maximum width/height of the processing canvas in
                pixels, or 0 to disable resizing.

        Returns:
            None
        """
        self.profileOverride['canvasSize'] = pixels

    def orientationCorrection(self, enabled: bool):
        """Enable or disable automatic image orientation correction.

        Args:
            enabled (bool): If True, correct image orientation for rotated
                images.

        Returns:
            None
        """
        self.profileOverride['orientationCorrection'] = enabled

    def objectDetection(self, enabled: bool):
        """Enable or disable detection of signature, document and face locations.

        Args:
            enabled (bool): If True, automatically detect and return the
                locations of signature, document and face.

        Returns:
            None
        """
        self.profileOverride['objectDetection'] = enabled

    def AAMVABarcodeParsing(self, enabled: bool):
        """Enable or disable AAMVA barcode parsing for US/CA ID/DL.

        Disable this to improve performance if you are not planning on
        scanning ID/DL from the US or Canada.

        Args:
            enabled (bool): If True, parse the AAMVA barcode on US/CA
                ID/driver's licenses.

        Returns:
            None
        """
        self.profileOverride['AAMVABarcodeParsing'] = enabled

    def saveResult(self, enableSaveTransaction: bool, enableSaveTransactionImages: bool):
        """Configure whether transaction results and images are saved on cloud.

        Args:
            enableSaveTransaction (bool): If True, save scan transaction
                results on the cloud.
            enableSaveTransactionImages (bool): If True, also save the output
                images. Only applied when ``enableSaveTransaction`` is True.

        Returns:
            None
        """
        self.profileOverride['saveResult'] = enableSaveTransaction
        if enableSaveTransaction:
            self.profileOverride['saveImage'] = enableSaveTransactionImages

    def outputImage(self, enableOutputImage: bool, outputFormat="url"):
        """Configure whether an output image is returned in the API response.

        Args:
            enableOutputImage (bool): If True, return the output image as part
                of the API response.
            outputFormat (str): Format of the returned image, e.g. ``"url"``
                or ``"base64"``. Only applied when ``enableOutputImage`` is
                True. Defaults to ``"url"``.

        Returns:
            None
        """
        self.profileOverride['outputImage'] = enableOutputImage
        if enableOutputImage:
            self.profileOverride['outputType'] = outputFormat

    def autoCrop(self, enableAutoCrop: bool, enableAdvancedAutoCrop: bool):
        """Configure image cropping before output is saved and returned.

        Args:
            enableAutoCrop (bool): If True, crop the document from the image
                before saving and returning output.
            enableAdvancedAutoCrop (bool): If True, enable advanced auto-crop
                for more aggressive document edge detection.

        Returns:
            None
        """
        self.profileOverride['crop'] = enableAutoCrop
        self.profileOverride['advancedCrop'] = enableAdvancedAutoCrop

    def outputSize(self, pixels: int):
        """Set the maximum width/height, in pixels, for output and saved images.

        Args:
            pixels (int): Maximum width/height in pixels for output and saved
                images.

        Returns:
            None
        """
        self.profileOverride['outputSize'] = pixels

    def inferFullName(self, enabled: bool):
        """Enable or disable generation of a combined full name field.

        Args:
            enabled (bool): If True, generate a full name field by combining
                the parsed first name, middle name and last name.

        Returns:
            None
        """
        self.profileOverride['inferFullName'] = enabled

    def splitFirstName(self, enabled: bool):
        """Enable or disable splitting a multi-word first name.

        Args:
            enabled (bool): If True and the first name contains more than one
                word, move the second word onwards into the middle name field.

        Returns:
            None
        """
        self.profileOverride['splitFirstName'] = enabled

    def transactionAuditReport(self, enabled: bool):
        """Enable or disable generation of a per-transaction PDF audit report.

        Args:
            enabled (bool): If True, generate a detailed PDF audit report for
                every transaction.

        Returns:
            None
        """
        self.profileOverride['transactionAuditReport'] = enabled

    def setTimezone(self, timezone: str):
        """Set the timezone used in audit reports.

        If left blank, UTC is used. Refer to
        https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for the
        list of valid TZ database names.

        Args:
            timezone (str): TZ database timezone name (for example
                ``"America/New_York"``).

        Returns:
            None
        """
        self.profileOverride['timezone'] = timezone

    def obscure(self, fieldKeys: list[str]):
        """Redact specified data fields before transaction storage.

        The listed fields are redacted before the transaction is stored and
        are also blurred from the output and saved image.

        Args:
            fieldKeys (list[str]): List of data field keys to redact.

        Returns:
            None
        """
        self.profileOverride['obscure'] = fieldKeys

    def webhook(self, url: str = "https://www.example.com/webhook.php"):
        """Set the server URL that receives Docupass and scan results.

        Args:
            url (str): A remote HTTP(S) server URL to receive Docupass
                verification and scan transaction results. Defaults to
                ``"https://www.example.com/webhook.php"``.

        Returns:
            None

        Raises:
            InvalidArgumentException: If the URL is malformed, points to a
                private/reserved IP address or localhost, or uses a scheme
                other than http/https.
        """
        valid = re.match(self.URL_VALIDATION_REGEX, url)
        if valid is None:
            raise InvalidArgumentException('Invalid URL format')

        urlinfo = urlparse(url)
        try:
            ipv4 = ipaddress.IPv4Address(urlinfo.hostname)
        except ValueError as e:
            ipv4 = None

        if ipv4 is not None and (ipv4.is_private or ipv4.is_reserved) or urlinfo.hostname.lower() == 'localhost':
            raise InvalidArgumentException('Invalid URL, the host does not appear to be a remote host.')

        if urlinfo.scheme not in ['http', 'https']:
            raise InvalidArgumentException("Invalid URL, only http and https protocols are allowed.")

        self.profileOverride['webhook'] = url

    def threshold(self, thresholdKey: str, thresholdValue: float):
        """Set the validation threshold of a specified component.

        Args:
            thresholdKey (str): The threshold component key to configure.
            thresholdValue (float): The threshold value to apply.

        Returns:
            None
        """
        self.profileOverride['thresholds'][thresholdKey] = thresholdValue

    def decisionTrigger(self, reviewTrigger: float = 1, rejectTrigger: float = 1):
        """Set the score thresholds that trigger review and reject decisions.

        Args:
            reviewTrigger (float): If the final total review score is equal to
                or greater than this value, the final KYC decision is
                ``"review"``. Defaults to 1.
            rejectTrigger (float): If the final total reject score is equal to
                or greater than this value, the final KYC decision is
                ``"reject"``. Reject has higher priority than review. Defaults
                to 1.

        Returns:
            None
        """
        self.profileOverride['decisionTrigger'] = {
            'review': reviewTrigger,
            'reject': rejectTrigger,
        }

    def setWarning(self, code: str = "UNRECOGNIZED_DOCUMENT", enabled: bool = True, reviewThreshold: float = -1,
                   rejectThreshold: float = 0, weight: float = 1):
        """Enable, disable and fine-tune a Document Validation Component.

        Controls how each Document Validation Component (warning) affects the
        final decision.

        Args:
            code (str): Document Validation Component code / warning code.
                Defaults to ``"UNRECOGNIZED_DOCUMENT"``.
            enabled (bool): Whether the current Document Validation Component
                is enabled. Defaults to True.
            reviewThreshold (float): If the current validation has failed to
                pass, and this value is greater than or equal to zero, and the
                confidence of this warning is greater than or equal to this
                value, the total review score is increased by ``weight``.
                Defaults to -1.
            rejectThreshold (float): If the current validation has failed to
                pass, and this value is greater than or equal to zero, and the
                confidence of this warning is greater than or equal to this
                value, the total reject score is increased by ``weight``.
                Defaults to 0.
            weight (float): Weight to add to the total review and reject score
                when the validation fails to pass. Defaults to 1.

        Returns:
            None
        """
        if 'decisions' not in self.profileOverride:
            self.profileOverride['decisions'] = {}
        self.profileOverride['decisions'][code] = {
            "enabled": enabled,
            "review": reviewThreshold,
            "reject": rejectThreshold,
            "weight": weight,
        }

    def restrictDocumentCountry(self, countryCodes: str = "US,CA,UK"):
        """Restrict accepted documents to the specified issuing countries.

        Checks whether the document was issued by one of the specified
        countries. For example, ``"US,CA"`` accepts documents from the United
        States and Canada.

        Args:
            countryCodes (str): ISO ALPHA-2 country codes separated by commas.
                Defaults to ``"US,CA,UK"``.

        Returns:
            None
        """
        if 'acceptedDocuments' in self.profileOverride:
            self.profileOverride['acceptedDocuments'] = {}
        self.profileOverride['acceptedDocuments']['documentCountry'] = countryCodes

    def restrictDocumentState(self, states: str = "CA,TX"):
        """Restrict accepted documents to the specified issuing states.

        Checks whether the document was issued by one of the specified states.
        For example, ``"CA,TX"`` accepts documents from California and Texas.

        Args:
            states (str): State full names or abbreviations separated by
                commas. Defaults to ``"CA,TX"``.

        Returns:
            None
        """
        if 'acceptedDocuments' in self.profileOverride:
            self.profileOverride['acceptedDocuments'] = {}
        self.profileOverride['acceptedDocuments']['documentState'] = states

    def restrictDocumentType(self, documentType: str = "DIP"):
        """Restrict accepted documents to the specified document types.

        Checks whether the document is one of the specified types. For
        example, ``"PD"`` accepts both passports and driver's licenses.

        Args:
            documentType (str): One or more document type codes, where
                ``P`` = Passport, ``D`` = Driver's License, ``I`` = Identity
                Card. Defaults to ``"DIP"``.

        Returns:
            None
        """
        if 'acceptedDocuments' in self.profileOverride:
            self.profileOverride['acceptedDocuments'] = {}
        self.profileOverride['acceptedDocuments']['documentType'] = documentType


class Biometric(_ApiParent):
    """Client for standalone biometric face verification and liveness checks.

    Wraps the ``/face`` and ``/liveness`` API endpoints to perform 1:1 face
    verification against a reference image and standalone liveness detection
    on a selfie photo or video. A KYC profile must be set via
    :meth:`setProfile` before calling the verification methods.
    """

    def __init__(self, apiKey=None):
        """Initialize the biometric client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

        self.config.update({
            "profile": "",
            "profileOverride": {},
            "customData": "",
        })

    def setCustomData(self, customData):
        """Attach an arbitrary string to the transaction.

        Args:
            customData (str): An arbitrary string to save with the
                transaction, e.g. an internal customer reference number.

        Returns:
            None
        """
        self.config['customData'] = customData

    def setProfile(self, profile):
        """Set the KYC profile used for verification requests.

        Args:
            profile (Profile): A :class:`Profile` object whose ID and
                overrides configure the request.

        Returns:
            None

        Raises:
            InvalidArgumentException: If ``profile`` is not a :class:`Profile`
                object.
        """
        if isinstance(profile, Profile):
            self.config['profile'] = profile.profileId
            if len(profile.profileOverride.keys()) > 0:
                self.config['profileOverride'] = profile.profileOverride
            else:
                del self.config['profileOverride']
        else:
            raise InvalidArgumentException("Provided profile is not a 'KYCProfile' object.")

    def verifyFace(self, referenceFaceImage: str = '', facePhoto: str = "", faceVideo: str = ""):
        """Perform 1:1 face verification against a reference face image.

        Verifies a selfie photo or selfie video against a reference face
        image. Exactly one of ``facePhoto`` or ``faceVideo`` should be
        supplied as the verification input.

        Args:
            referenceFaceImage (str): Reference face image to compare against
                (file path, base64 content, URL, or cache reference). Required.
                Defaults to ``''``.
            facePhoto (str): Selfie face photo (file path, base64 content,
                URL, or cache reference). Defaults to ``""``.
            faceVideo (str): Selfie face video (file path, base64 content or
                URL). Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the verification result.

        Raises:
            InvalidArgumentException: If no KYC profile has been set, if
                ``referenceFaceImage`` is empty, if neither ``facePhoto`` nor
                ``faceVideo`` is supplied, or if an image input cannot be
                parsed.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if self.config['profile'] == "":
            raise InvalidArgumentException(
                "KYC Profile not configured, please use setProfile before calling this function.")

        payload = self.config
        if referenceFaceImage == '':
            raise InvalidArgumentException("Reference face image required.")

        if facePhoto == "" and faceVideo == "":
            raise InvalidArgumentException("Verification face image required.")

        payload['reference'] = ParseInput(referenceFaceImage, True)

        if facePhoto != "":
            payload['face'] = ParseInput(facePhoto, True)
        elif faceVideo != "":
            payload['faceVideo'] = ParseInput(faceVideo)

        resp = self.http.post(GetEndpoint('face'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def verifyLiveness(self, facePhoto: str = "", faceVideo: str = ""):
        """Perform a standalone liveness check on a selfie photo or video.

        Exactly one of ``facePhoto`` or ``faceVideo`` should be supplied.

        Args:
            facePhoto (str): Selfie face photo (file path, base64 content,
                URL, or cache reference). Defaults to ``""``.
            faceVideo (str): Selfie face video (file path, base64 content or
                URL). Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the liveness result.

        Raises:
            InvalidArgumentException: If no KYC profile has been set, if
                neither ``facePhoto`` nor ``faceVideo`` is supplied, or if an
                image input cannot be parsed.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if self.config['profile'] == "":
            raise InvalidArgumentException(
                'KYC Profile not configured, please use setProfile before calling this function.')

        payload = self.config
        if facePhoto == "" and faceVideo == "":
            raise InvalidArgumentException('Verification face image required.')

        if facePhoto != "":
            payload['face'] = ParseInput(facePhoto, True)
        elif faceVideo != "":
            payload['faceVideo'] = ParseInput(faceVideo)

        resp = self.http.post(GetEndpoint('liveness'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)


class Contract(_ApiParent):
    """Client for contract document generation and template management.

    Wraps the ``/generate`` and ``/contract`` API endpoints to generate
    documents from templates and transaction data, and to create, read,
    update, delete and list contract templates.
    """

    def __init__(self, apiKey=None):
        """Initialize the contract client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    def generate(self, templateId: str = '', _format: str = 'PDF', transactionId: str = '', fillData=None):
        """Generate a document from a template and transaction data.

        Args:
            templateId (str): Template ID to generate from. Required. Defaults
                to ``''``.
            _format (str): Output format, one of ``"PDF"``, ``"DOCX"`` or
                ``"HTML"``. Defaults to ``"PDF"``.
            transactionId (str): Fill the template with data from the
                specified transaction. Defaults to ``''``.
            fillData (dict, optional): Key-value pairs to autofill dynamic
                fields. Data from the user ID takes precedence in case of a
                conflict. For example, ``{"myparameter": "abc"}`` fills
                ``%{myparameter}`` in the template with ``"abc"``. Defaults to
                None (treated as an empty dict).

        Returns:
            dict: The decoded API response containing the generated document.

        Raises:
            InvalidArgumentException: If ``templateId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if fillData is None:
            fillData = {}

        payload = {
            'format': _format,
        }
        if templateId == "":
            raise InvalidArgumentException('Template ID required.')
        payload['templateId'] = templateId
        if transactionId != '':
            payload['transactionId'] = transactionId

        if len(fillData.keys()) > 0:
            payload['fillData'] = fillData

        resp = self.http.post(GetEndpoint('generate'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def listTemplate(self, order: int = -1, limit: int = 10, offset: int = 0, filterTemplateId: str = ""):
        """Retrieve a list of contract templates.

        Args:
            order (int): Sort order, ``-1`` for newest first or ``1`` for
                oldest first. Defaults to ``-1``.
            limit (int): Number of items to return per call. Must be greater
                than 0 and less than 100. Defaults to 10.
            offset (int): Start the list from this entry index. Defaults to 0.
            filterTemplateId (str): Filter results by template ID. Defaults to
                ``""``.

        Returns:
            dict: The decoded API response containing the list of templates.

        Raises:
            InvalidArgumentException: If ``order`` is not 1 or -1, or if
                ``limit`` is out of range.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if order not in [1, -1]:
            raise InvalidArgumentException("'order' should be integer of 1 or -1.")

        if limit <= 0 or limit >= 100:
            raise InvalidArgumentException(
                "'limit' should be a positive integer greater than 0 and less than or equal to 100.")

        payload = {
            "order": order,
            "limit": limit,
            "offset": offset,
        }

        if filterTemplateId != "":
            payload['templateid'] = filterTemplateId

        resp = self.http.get(GetEndpoint('contract'), params=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def getTemplate(self, templateId: str = ""):
        """Retrieve a single contract template.

        Args:
            templateId (str): Template ID to retrieve. Required. Defaults to
                ``""``.

        Returns:
            dict: The decoded API response containing the template.

        Raises:
            InvalidArgumentException: If ``templateId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if templateId == "":
            raise InvalidArgumentException('Template ID required.')

        resp = self.http.get(GetEndpoint('contract/{}'.format(templateId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def deleteTemplate(self, templateId: str = ""):
        """Delete a contract template.

        Args:
            templateId (str): Template ID to delete. Required. Defaults to
                ``""``.

        Returns:
            dict: The decoded API response confirming the deletion.

        Raises:
            InvalidArgumentException: If ``templateId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if templateId == "":
            raise InvalidArgumentException('Template ID required.')

        resp = self.http.delete(GetEndpoint('contract/{}'.format(templateId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def createTemplate(self, name: str = "", content: str = "", orientation: str = "0", timezone: str = "UTC",
                       font: str = "Open Sans"):
        """Create a new contract template.

        Args:
            name (str): Template name. Required. Defaults to ``""``.
            content (str): Template HTML content. Required. Defaults to ``""``.
            orientation (str): Page orientation, ``"0"`` for portrait
                (default) or ``"1"`` for landscape. Defaults to ``"0"``.
            timezone (str): Template timezone. Defaults to ``"UTC"``.
            font (str): Template font. Defaults to ``"Open Sans"``.

        Returns:
            dict: The decoded API response containing the created template.

        Raises:
            InvalidArgumentException: If ``name`` or ``content`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if name == "":
            raise InvalidArgumentException("Template name required.")
        if content == "":
            raise InvalidArgumentException("Template content required.")
        payload = {
            "name": name,
            "content": content,
            "orientation": orientation,
            "timezone": timezone,
            "font": font,
        }

        resp = self.http.post(GetEndpoint('contract'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def updateTemplate(self, templateId: str = "", name: str = "", content: str = "", orientation: str = "0",
                       timezone: str = "UTC",
                       font: str = "Open Sans"):
        """Update an existing contract template.

        Args:
            templateId (str): Template ID to update. Required. Defaults to
                ``""``.
            name (str): Template name. Required. Defaults to ``""``.
            content (str): Template HTML content. Required. Defaults to ``""``.
            orientation (str): Page orientation, ``"0"`` for portrait
                (default) or ``"1"`` for landscape. Defaults to ``"0"``.
            timezone (str): Template timezone. Defaults to ``"UTC"``.
            font (str): Template font. Defaults to ``"Open Sans"``.

        Returns:
            dict: The decoded API response containing the updated template.

        Raises:
            InvalidArgumentException: If ``templateId``, ``name`` or
                ``content`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if templateId == "":
            raise InvalidArgumentException('Template ID required.')
        if name == "":
            raise InvalidArgumentException("Template name required.")
        if content == "":
            raise InvalidArgumentException("Template content required.")

        payload = {
            "name": name,
            "content": content,
            "orientation": orientation,
            "timezone": timezone,
            "font": font,
        }
        resp = self.http.post(GetEndpoint("contract/{}".format(templateId)), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)


class Scanner(_ApiParent):
    """Client for identity document scanning and ID face verification.

    Wraps the ``/scan``, ``/quickscan`` and ``/veryquickscan`` API endpoints.
    Before calling :meth:`scan`, configure the request using the various
    setter methods (for example :meth:`setProfile`, :meth:`verifyUserInformation`,
    :meth:`restrictCountry`) which accumulate options in :attr:`config`. A KYC
    profile must be set via :meth:`setProfile` before calling :meth:`scan`.
    """

    def __init__(self, apiKey=None):
        """Initialize the scanner client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey=apiKey)
        self.config.update({
            "document": "",
            "documentBack": "",
            "face": "",
            "faceVideo": "",
            "profile": "",
            "profileOverride": {},
            "verifyName": "",
            "verifyDob": "",
            "verifyAge": "",
            "verifyAddress": "",
            "verifyPostcode": "",
            "verifyDocumentNumber": "",
            "restrictCountry": "",
            "restrictState": "",
            "restrictType": "",
            "ip": "",
            "customData": "",
        })

    def setUserIp(self, ip: str):
        """Set the end user's IP address for issuing-country cross-checks.

        The IP address is used to check whether the ID was issued from the
        same country as the IP. If no value is provided, the HTTP connection
        IP is used.

        Args:
            ip (str): The end user's IP address.

        Returns:
            None
        """
        self.config['ip'] = ip

    def setCustomData(self, customData: str):
        """Attach an arbitrary string to the transaction.

        Args:
            customData (str): An arbitrary string to save with the
                transaction, e.g. an internal customer reference number.

        Returns:
            None
        """
        self.config['customData'] = customData

    def setContractOptions(self, templateId: str = "", _format: str = "PDF", extraFillData=None):
        """Configure automatic contract generation from the scanned ID.

        Automatically generates a contract document using values parsed from
        the uploaded ID. Passing an empty ``templateId`` clears any previously
        configured contract options.

        Args:
            templateId (str): Up to 5 contract template IDs separated by
                commas. Defaults to ``""`` (disables contract generation).
            _format (str): Output format, one of ``"PDF"``, ``"DOCX"`` or
                ``"HTML"``. Defaults to ``"PDF"``.
            extraFillData (dict, optional): Key-value pairs to autofill dynamic
                fields. Data from the user ID takes precedence in case of a
                conflict. For example, ``{"myparameter": "abc"}`` fills
                ``%{myparameter}`` in the template with ``"abc"``. Defaults to
                None (treated as an empty dict).

        Returns:
            None
        """
        if extraFillData is None:
            extraFillData = {}
        if templateId != "":
            self.config['contractGenerate'] = templateId
            self.config['contractFormat'] = _format
            if len(extraFillData.keys()) > 0:
                self.config['contractPrefill'] = extraFillData
            else:
                del self.config['contractPrefill']
        else:
            del self.config['contractGenerate']
            del self.config['contractFormat']
            del self.config['contractPrefill']

    def setProfile(self, profile):
        """Set the KYC profile used for scan requests.

        Args:
            profile (Profile): A :class:`Profile` object whose ID and
                overrides configure the request.

        Returns:
            None

        Raises:
            InvalidArgumentException: If ``profile`` is not a :class:`Profile`
                object.
        """
        if isinstance(profile, Profile):
            self.config['profile'] = profile.profileId
            if len(profile.profileOverride.keys()) > 0:
                self.config['profileOverride'] = profile.profileOverride
            else:
                del self.config['profileOverride']
        else:
            raise InvalidArgumentException("Provided profile is not a 'KYCProfile' object.")

    def verifyUserInformation(self, documentNumber: str = "", fullName: str = "", dob: str = "", ageRange: str = "",
                              address: str = "", postcode: str = ""):
        """Provide customer information to cross-check against the document.

        Configures expected customer details that the scan will verify against
        the uploaded document.

        Args:
            documentNumber (str): Document or ID number. Defaults to ``""``.
            fullName (str): Full name. Defaults to ``""``.
            dob (str): Date of birth in ``YYYY/MM/DD`` format. Defaults to
                ``""``.
            ageRange (str): Age range, for example ``"18-40"``. Defaults to
                ``""``.
            address (str): Address. Defaults to ``""``.
            postcode (str): Postcode. Defaults to ``""``.

        Returns:
            None

        Raises:
            InvalidArgumentException: If ``dob`` is not in ``YYYY/MM/DD``
                format, or if ``ageRange`` is not in ``minAge-maxAge`` format.
        """
        self.config['verifyDocumentNumber'] = documentNumber
        self.config['verifyName'] = fullName
        if dob == "":
            self.config['verifyDob'] = dob
        else:
            try:
                datetime.datetime.strptime(dob, '%Y/%m/%d')
                self.config['verifyDob'] = dob
            except ValueError:
                raise InvalidArgumentException('Invalid birthday format (YYYY/MM/DD)')

        if ageRange == "":
            self.config['verifyAge'] = ageRange
        else:
            if re.match("^\d+-\d+$", ageRange) is None:
                raise InvalidArgumentException('Invalid age range format (minAge-maxAge)')
            self.config['verifyAge'] = ageRange

        self.config['verifyAddress'] = address
        self.config['verifyPostcode'] = postcode

    def restrictCountry(self, countryCodes: str = "US,CA,UK"):
        """Restrict accepted documents to the specified issuing countries.

        Checks whether the document was issued by one of the specified
        countries. For example, ``"US,CA"`` accepts documents from the United
        States and Canada.

        Args:
            countryCodes (str): ISO ALPHA-2 country codes separated by commas.
                Defaults to ``"US,CA,UK"``.

        Returns:
            None
        """
        self.config['restrictCountry'] = countryCodes

    def restrictState(self, states: str = "CA,TX"):
        """Restrict accepted documents to the specified issuing states.

        Checks whether the document was issued by one of the specified states.
        For example, ``"CA,TX"`` accepts documents from California and Texas.

        Args:
            states (str): State full names or abbreviations separated by
                commas. Defaults to ``"CA,TX"``.

        Returns:
            None
        """
        self.config['restrictState'] = states

    def restrictType(self, documentType: str = "DIP"):
        """Restrict accepted documents to the specified document types.

        Checks whether the document is one of the specified types. For
        example, ``"PD"`` accepts both passports and driver's licenses.

        Args:
            documentType (str): One or more document type codes, where
                ``P`` = Passport, ``D`` = Driver's License, ``I`` = Identity
                Card. Defaults to ``"DIP"``.

        Returns:
            None
        """
        self.config['restrictType'] = documentType

    def scan(self, documentFront: str = "", documentBack: str = "", facePhoto: str = "", faceVideo: str = ""):
        """Initiate a full identity document scan and ID face verification.

        Submits the supplied images to start a standard scan transaction. A
        KYC profile must have been set via :meth:`setProfile` first. At most
        one of ``facePhoto`` or ``faceVideo`` is used for face verification.

        Args:
            documentFront (str): Front of document (file path, base64 content,
                URL, or cache reference). Required. Defaults to ``""``.
            documentBack (str): Back of document (file path, base64 content,
                URL, or cache reference). Defaults to ``""``.
            facePhoto (str): Face photo (file path, base64 content, URL, or
                cache reference). Defaults to ``""``.
            faceVideo (str): Face video (file path, base64 content or URL).
                Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the scan result.

        Raises:
            InvalidArgumentException: If no KYC profile has been set, if
                ``documentFront`` is empty, or if an image input cannot be
                parsed.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if self.config['profile'] == "":
            raise InvalidArgumentException(
                "KYC Profile not configured, please use setProfile before calling this function.")

        payload = self.config
        if documentFront == "":
            raise InvalidArgumentException("Primary document image required.")
        payload['document'] = ParseInput(documentFront, True)

        if documentBack != "":
            payload['documentBack'] = ParseInput(documentBack, True)

        if facePhoto != "":
            payload['face'] = ParseInput(facePhoto, True)
        elif faceVideo != "":
            payload['faceVideo'] = ParseInput(faceVideo)

        resp = self.http.post(GetEndpoint('scan'), json=payload, timeout=60)
        return ApiExceptionHandle(resp, self.throwError)

    def quickScan(self, documentFront: str = "", documentBack: str = "", cacheImage: bool = False):
        """Initiate a quick identity document OCR scan.

        Performs an OCR-only scan without full KYC validation.

        Args:
            documentFront (str): Front of document (file path, base64 content
                or URL). Required. Defaults to ``""``.
            documentBack (str): Back of document (file path, base64 content or
                URL). Defaults to ``""``.
            cacheImage (bool): If True, cache the uploaded image(s) for 24
                hours and return a cache reference for each image; the
                reference hash can be used to start a standard scan transaction
                without re-uploading the file. Defaults to False.

        Returns:
            dict: The decoded API response containing the OCR result.

        Raises:
            InvalidArgumentException: If ``documentFront`` is empty, or if an
                image input cannot be parsed.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        payload = {
            'saveFile': cacheImage,
        }
        if documentFront == "":
            raise InvalidArgumentException("Primary document image required.")
        payload['document'] = ParseInput(documentFront)

        if documentBack != "":
            payload['documentBack'] = ParseInput(documentBack)

        resp = self.http.post(GetEndpoint('quickscan'), json=payload, timeout=60)
        return ApiExceptionHandle(resp, self.throwError)

    def veryQuickScan(self, documentFront: str = "", documentBack: str = "", cacheImage: bool = False):
        """Initiate a very quick (fast) identity document OCR scan.

        Faster but less thorough than :meth:`quickScan`, useful for
        high-throughput OCR-only use cases.

        Args:
            documentFront (str): Front of document (file path, base64 content
                or URL). Required. Defaults to ``""``.
            documentBack (str): Back of document (file path, base64 content or
                URL). Defaults to ``""``.
            cacheImage (bool): If True, cache the uploaded image(s) for 24
                hours and return a cache reference for each image; the
                reference hash can be used to start a standard scan transaction
                without re-uploading the file. Defaults to False.

        Returns:
            dict: The decoded API response containing the OCR result.

        Raises:
            InvalidArgumentException: If ``documentFront`` is empty, or if an
                image input cannot be parsed.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        payload = {
            'saveFile': cacheImage,
        }
        if documentFront == "":
            raise InvalidArgumentException("Primary document image required.")
        payload['document'] = ParseInput(documentFront)

        if documentBack != "":
            payload['documentBack'] = ParseInput(documentBack)

        resp = self.http.post(GetEndpoint('veryquickscan'), json=payload, timeout=60)
        return ApiExceptionHandle(resp, self.throwError)


class Transaction(_ApiParent):
    """Client for retrieving, managing and exporting transaction records.

    Wraps the ``/transaction``, ``/imagevault``, ``/filevault`` and
    ``/export/transaction`` API endpoints to retrieve, list, update and delete
    transactions, download their images and files, and export transaction
    archives.
    """

    def __init__(self, apiKey=None):
        """Initialize the transaction client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    def getTransaction(self, transactionId: str = ""):
        """Retrieve a single transaction record.

        Args:
            transactionId (str): Transaction ID to retrieve. Required.
                Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the transaction record.

        Raises:
            InvalidArgumentException: If ``transactionId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if transactionId == "":
            raise InvalidArgumentException("Transaction ID required.")

        resp = self.http.get(GetEndpoint("transaction/{}".format(transactionId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def listTransaction(self, order: int = -1, limit: int = 10, offset: int = 0, createdAtMin: int = 0,
                        createdAtMax: int = 0, filterCustomData: str = "", filterDecision: str = "",
                        filterDocupass: str = "", filterProfileId: str = ""):
        """Retrieve a list of transaction history.

        Args:
            order (int): Sort order, ``-1`` for newest first or ``1`` for
                oldest first. Defaults to ``-1``.
            limit (int): Number of items to return per call. Must be greater
                than 0 and less than 100. Defaults to 10.
            offset (int): Start the list from this entry index. Defaults to 0.
            createdAtMin (int): List only transactions created after this Unix
                timestamp. Ignored when 0. Defaults to 0.
            createdAtMax (int): List only transactions created before this Unix
                timestamp. Ignored when 0. Defaults to 0.
            filterCustomData (str): Filter results by the ``customData`` field.
                Defaults to ``""``.
            filterDecision (str): Filter results by decision (``accept``,
                ``review`` or ``reject``). Defaults to ``""``.
            filterDocupass (str): Filter results by Docupass reference.
                Defaults to ``""``.
            filterProfileId (str): Filter results by KYC profile ID. Defaults
                to ``""``.

        Returns:
            dict: The decoded API response containing the list of transactions.

        Raises:
            InvalidArgumentException: If ``order`` is not 1 or -1, or if
                ``limit`` is out of range.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if order not in [1, -1]:
            raise InvalidArgumentException("'order' should be integer of 1 or -1.")

        if limit <= 0 or limit >= 100:
            raise InvalidArgumentException(
                "'limit' should be a positive integer greater than 0 and less than or equal to 100.")

        payload = {
            "order": order,
            "limit": limit,
            "offset": offset,
        }
        if createdAtMin > 0:
            payload['createdAtMin'] = createdAtMin
        if createdAtMax > 0:
            payload['createdAtMax'] = createdAtMax

        if filterCustomData != "":
            payload['customData'] = filterCustomData
        if filterDocupass != "":
            payload['docupass'] = filterDocupass
        if filterDecision != "":
            payload['decision'] = filterDecision
        if filterProfileId != "":
            payload['profileId'] = filterProfileId

        resp = self.http.get(GetEndpoint('transaction'), params=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def updateTransaction(self, transactionId: str = "", decision: str = ""):
        """Update a transaction's decision.

        The updated decision is relayed to the webhook if one is configured.

        Args:
            transactionId (str): Transaction ID to update. Required. Defaults
                to ``""``.
            decision (str): New decision, one of ``accept``, ``review`` or
                ``reject``. Defaults to ``""``.

        Returns:
            dict: The decoded API response confirming the update.

        Raises:
            InvalidArgumentException: If ``transactionId`` is empty, or if
                ``decision`` is not one of ``accept``, ``review`` or
                ``reject``.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if transactionId == "":
            raise InvalidArgumentException('Transaction ID required.')

        if decision not in ['accept', 'review', 'reject']:
            raise InvalidArgumentException("'decision' should be either accept, review or reject.")

        resp = self.http.patch(GetEndpoint('transaction/{}'.format(transactionId)), json={
            'decision': decision,
        }, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def deleteTransaction(self, transactionId: str = ""):
        """Delete a transaction.

        Args:
            transactionId (str): Transaction ID to delete. Required. Defaults
                to ``""``.

        Returns:
            dict: The decoded API response confirming the deletion.

        Raises:
            InvalidArgumentException: If ``transactionId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if transactionId == "":
            raise InvalidArgumentException('Transaction ID required.')

        resp = self.http.delete(GetEndpoint('transaction/{}'.format(transactionId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def saveImage(self, imageToken: str = "", destination: str = ""):
        r"""Download a transaction image to the local file system.

        Args:
            imageToken (str): Image token obtained from a transaction API
                response. Required. Defaults to ``""``.
            destination (str): Full destination path including file name; the
                file extension should be ``jpg``, for example
                ``'\home\idcard.jpg'``. Required. Defaults to ``""``.

        Returns:
            None: The image is written to ``destination`` on disk.

        Raises:
            InvalidArgumentException: If ``imageToken`` or ``destination`` is
                empty.
        """
        if imageToken == "":
            raise InvalidArgumentException("'imageToken' required.")

        if destination == "":
            raise InvalidArgumentException("'destination' required.")

        resp = self.http.get(GetEndpoint('imagevault/{}'.format(imageToken)), timeout=30, stream=True)
        f = open(destination, 'wb')
        f.write(resp.content)
        f.close()

    def saveFile(self, fileName: str = "", destination: str = ""):
        r"""Download a transaction file to the local file system.

        Downloads a file using the secured file name obtained from a
        transaction.

        Args:
            fileName (str): Secured file name obtained from a transaction.
                Required. Defaults to ``""``.
            destination (str): Full destination path including file name, for
                example ``'\home\auditreport.pdf'``. Required. Defaults to
                ``""``.

        Returns:
            None: The file is written to ``destination`` on disk.

        Raises:
            InvalidArgumentException: If ``fileName`` or ``destination`` is
                empty.
        """
        if fileName == "":
            raise InvalidArgumentException("'fileName' required.")
        if destination == "":
            raise InvalidArgumentException("'destination' required.")

        resp = self.http.get(GetEndpoint('filevault/{}'.format(fileName)), timeout=30, stream=True)
        f = open(destination, 'wb')
        f.write(resp.content)
        f.close()

    def exportTransaction(self, destination: str = "", transactionId: list = None, exportType: str = "csv",
                          ignoreUnrecognized: bool = False,
                          ignoreDuplicate: bool = False, createdAtMin: int = 0,
                          createdAtMax: int = 0, filterCustomData: str = "", filterDecision: str = "",
                          filterDocupass: str = "", filterProfileId: str = ""):
        r"""Export a transaction archive to the local file system.

        Requests a transaction export and, if the API returns a download URL,
        downloads the resulting archive to ``destination``.

        Args:
            destination (str): Full destination path including file name; the
                file extension should be ``zip``, for example
                ``'\home\archive.zip'``. Required. Defaults to ``""``.
            transactionId (list, optional): Export only the specified
                transaction IDs. Defaults to None (treated as an empty list,
                exporting all matching transactions).
            exportType (str): Export format, either ``'csv'`` or ``'json'``.
                Defaults to ``"csv"``.
            ignoreUnrecognized (bool): If True, ignore unrecognized documents.
                Defaults to False.
            ignoreDuplicate (bool): If True, ignore duplicated entries.
                Defaults to False.
            createdAtMin (int): Export only transactions created after this
                Unix timestamp. Ignored when 0. Defaults to 0.
            createdAtMax (int): Export only transactions created before this
                Unix timestamp. Ignored when 0. Defaults to 0.
            filterCustomData (str): Filter the export by the ``customData``
                field. Defaults to ``""``.
            filterDecision (str): Filter the export by decision (``accept``,
                ``review`` or ``reject``). Defaults to ``""``.
            filterDocupass (str): Filter the export by Docupass reference.
                Defaults to ``""``.
            filterProfileId (str): Filter the export by KYC profile ID.
                Defaults to ``""``.

        Returns:
            None: When an export URL is returned, the archive is written to
            ``destination`` on disk; otherwise nothing is written.

        Raises:
            InvalidArgumentException: If ``destination`` is empty, or if
                ``exportType`` is not ``'csv'`` or ``'json'``.
        """
        if transactionId is None:
            transactionId = []

        if destination == '':
            raise InvalidArgumentException("'destination' required.")

        if exportType not in ['csv', 'json']:
            raise InvalidArgumentException("'exportType' should be either 'json' or 'csv'.")

        payload = {
            "exportType": exportType,
            "ignoreUnrecognized": ignoreUnrecognized,
            "ignoreDuplicate": ignoreDuplicate,
        }
        if len(transactionId) > 0:
            payload['transactionId'] = transactionId

        if createdAtMin > 0:
            payload['createdAtMin'] = createdAtMin

        if createdAtMax > 0:
            payload['createdAtMax'] = createdAtMax

        if filterCustomData != "":
            payload['customData'] = filterCustomData

        if filterDocupass != "":
            payload['docupass'] = filterDocupass

        if filterDecision != "":
            payload['decision'] = filterDecision

        if filterProfileId != "":
            payload['profileId'] = filterProfileId

        resp = self.http.post(GetEndpoint('export/transaction'), json=payload, timeout=300)
        respJson = resp.json()
        if 'Url' in respJson:
            resp = self.http.get(GetEndpoint(respJson['Url']), timeout=300, stream=True)
            f = open(destination, 'wb')
            f.write(resp.content)
            f.close()


class Docupass(_ApiParent):
    """Client for creating and managing Docupass hosted verification sessions.

    Wraps the ``/docupass`` API endpoint to create Docupass verification
    sessions (hosted ID scanning / face verification pages) and to list,
    retrieve and delete existing sessions.
    """

    def __init__(self, apiKey=None):
        """Initialize the Docupass client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    def listDocupass(self, order: int = -1, limit: int = 10, offset: int = 0):
        """Retrieve a list of Docupass sessions.

        Args:
            order (int): Sort order, ``-1`` for newest first or ``1`` for
                oldest first. Defaults to ``-1``.
            limit (int): Number of items to return per call. Must be greater
                than 0 and less than 100. Defaults to 10.
            offset (int): Start the list from this entry index. Defaults to 0.

        Returns:
            dict: The decoded API response containing the list of Docupass
            sessions.

        Raises:
            InvalidArgumentException: If ``order`` is not 1 or -1, or if
                ``limit`` is out of range.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if order not in [1, -1]:
            raise InvalidArgumentException("'order' should be integer of 1 or -1.")

        if limit <= 0 or limit >= 100:
            raise InvalidArgumentException(
                "'limit' should be a positive integer greater than 0 and less than or equal to 100.")

        payload = {
            "order": order,
            "limit": limit,
            "offset": offset,
        }
        resp = self.http.get(GetEndpoint('docupass'), params=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def createDocupass(self, profile=None, contractFormat='pdf', contractGenerate='', reusable=False,
                       contractPrefill='',
                       contractSign='', customData='', language='', mode=0,
                       referenceDocument=None, referenceDocumentBack=None, referenceFace=None,
                       userPhone='', verifyAddress='', verifyAge='', verifyDOB='',
                       verifyDocumentNumber='', verifyName='', verifyPostcode=''):
        """Create a new Docupass hosted verification session.

        Args:
            profile (str): KYC profile ID to apply to the verification.
                Required. Defaults to None.
            contractFormat (str): Generated contract format, one of ``pdf``,
                ``docx`` or ``html``. Defaults to ``'pdf'``.
            contractGenerate (str): Contract template ID(s) to auto-generate
                from the verified ID. Defaults to ``''``.
            reusable (bool): Whether the Docupass session can be used by
                multiple users. Defaults to False.
            contractPrefill (str): Key-value data used to prefill dynamic
                contract fields. Defaults to ``''``.
            contractSign (str): Contract signing configuration. Defaults to
                ``''``.
            customData (str): Arbitrary string to save with the transaction.
                Defaults to ``''``.
            language (str): UI language for the hosted verification page.
                Defaults to ``''``.
            mode (int): Verification mode. Defaults to 0.
            referenceDocument (str, optional): Reference document image to
                verify against. Defaults to None.
            referenceDocumentBack (str, optional): Reference document back
                image. Defaults to None.
            referenceFace (str, optional): Reference face image to verify
                against. Defaults to None.
            userPhone (str): User phone number. Defaults to ``''``.
            verifyAddress (str): Expected address to verify against the
                document. Defaults to ``''``.
            verifyAge (str): Expected age range to verify (e.g. ``"18-99"``).
                Defaults to ``''``.
            verifyDOB (str): Expected date of birth to verify. Defaults to
                ``''``.
            verifyDocumentNumber (str): Expected document number to verify.
                Defaults to ``''``.
            verifyName (str): Expected full name to verify. Defaults to ``''``.
            verifyPostcode (str): Expected postcode to verify. Defaults to
                ``''``.

        Returns:
            dict: The decoded API response containing the created Docupass
            session.

        Raises:
            InvalidArgumentException: If ``profile`` is None.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if profile is None:
            raise InvalidArgumentException('Profile is required.')

        payload = {
            'mode': mode,
            'profile': profile,
            'contractFormat': contractFormat,
            'contractGenerate': contractGenerate,
            'reusable': reusable,
        }

        if contractPrefill != '' and contractPrefill is not None:
            payload['contractPrefill'] = contractPrefill
        if contractSign != '' and contractSign is not None:
            payload['contractSign'] = contractSign
        if customData != '' and customData is not None:
            payload['customData'] = customData
        if language != '' and language is not None:
            payload['language'] = language
        if referenceDocument != '' and referenceDocument is not None:
            payload['referenceDocument'] = referenceDocument
        if referenceDocumentBack != '' and referenceDocumentBack is not None:
            payload['referenceDocumentBack'] = referenceDocumentBack
        if referenceFace != '' and referenceFace is not None:
            payload['referenceFace'] = referenceFace
        if userPhone != '' and userPhone is not None:
            payload['userPhone'] = userPhone
        if verifyAddress != '' and verifyAddress is not None:
            payload['verifyAddress'] = verifyAddress
        if verifyAge != '' and verifyAge is not None:
            payload['verifyAge'] = verifyAge
        if verifyDOB != '' and verifyDOB is not None:
            payload['verifyDOB'] = verifyDOB
        if verifyDocumentNumber != '' and verifyDocumentNumber is not None:
            payload['verifyDocumentNumber'] = verifyDocumentNumber
        if verifyName != '' and verifyName is not None:
            payload['verifyName'] = verifyName
        if verifyPostcode != '' and verifyPostcode is not None:
            payload['verifyPostcode'] = verifyPostcode

        resp = self.http.post(GetEndpoint('docupass'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def getDocupass(self, reference=''):
        """Retrieve a single Docupass record by reference.

        Args:
            reference (str): Docupass reference ID. Required. Defaults to
                ``''``.

        Returns:
            dict: The decoded API response containing the Docupass record.

        Raises:
            InvalidArgumentException: If ``reference`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if reference == '':
            raise InvalidArgumentException("'reference' is required.")
        resp = self.http.get(GetEndpoint('docupass/{}'.format(reference)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def deleteDocupass(self, reference=''):
        """Delete a Docupass session by reference.

        Args:
            reference (str): Docupass reference ID. Required. Defaults to
                ``''``.

        Returns:
            dict: The decoded API response confirming the deletion.

        Raises:
            InvalidArgumentException: If ``reference`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if reference == '':
            raise InvalidArgumentException("'reference' is required.")
        resp = self.http.delete(GetEndpoint('docupass/{}'.format(reference)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)


class AML(_ApiParent):
    """Client for AML / PEP / sanctions screening.

    Wraps the ``/aml`` (v1) and ``/amlv3`` (v3) API endpoints to screen
    persons and entities against AML, PEP and sanctions databases.
    """

    def __init__(self, apiKey=None):
        """Initialize the AML client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    def search(self, name: str = "", idNumber: str = "", entity: int = 0, country: str = "",
               database=None, birthYear: str = ""):
        """Search the AML database (v1 endpoint).

        At least one of ``name`` or ``idNumber`` must be supplied.

        Args:
            name (str): Person's name or business name to search for. Defaults
                to ``""``.
            idNumber (str): Document number to search for. Defaults to ``""``.
            entity (int): Entity type, ``0`` for a person or ``1`` for a
                corporation/legal entity. Defaults to 0.
            country (str): Two-digit ISO country code to filter by
                country/nationality. Defaults to ``""``.
            database (list, optional): List of databases to search, e.g.
                ``["us_ofac", "eu_fsf"]``. If omitted, all databases are
                searched. Defaults to None.
            birthYear (str): Filter by year of birth. Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the search results.

        Raises:
            InvalidArgumentException: If both ``name`` and ``idNumber`` are
                empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if name == "" and idNumber == "":
            raise InvalidArgumentException("Either 'name' or 'idNumber' is required.")
        payload = {'entity': entity}
        if name != "":
            payload['name'] = name
        if idNumber != "":
            payload['idNumber'] = idNumber
        if country != "":
            payload['country'] = country
        if birthYear != "":
            payload['birthYear'] = birthYear
        if database:
            payload['database'] = database

        resp = self.http.post(GetEndpoint('aml'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def searchV3(self, text: str = "", id: str = "", limit: int = 0, page: int = 0):
        """Search the AML database (v3 endpoint).

        Provide either a free-text query or one or more entity IDs.

        Args:
            text (str): Full-text query (name, alias,
                document/passport/tax/registration number, etc.). Defaults to
                ``""``.
            id (str): One or more AML entity IDs separated by comma or newline
                (max 50). Defaults to ``""``.
            limit (int): Number of results to return per page. Ignored when 0.
                Defaults to 0.
            page (int): Result page number. Ignored when 0. Defaults to 0.

        Returns:
            dict: The decoded API response containing the search results.

        Raises:
            InvalidArgumentException: If both ``text`` and ``id`` are empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if text == "" and id == "":
            raise InvalidArgumentException("Either 'text' or 'id' is required.")
        payload = {}
        if text != "":
            payload['text'] = text
        if id != "":
            payload['id'] = id
        if limit > 0:
            payload['limit'] = limit
        if page > 0:
            payload['page'] = page

        resp = self.http.post(GetEndpoint('amlv3'), json=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)


class ProfileAPI(_ApiParent):
    """Client for server-side KYC profile management.

    Wraps the ``/profile`` and ``/export/profile`` API endpoints to create,
    read, update, delete, list and export server-side KYC profiles.
    """

    def __init__(self, apiKey=None):
        """Initialize the profile management client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    @staticmethod
    def _profileBody(name, profile):
        """Build the request body for a profile create/update request.

        Args:
            name (str): Profile name. Included in the body only when non-empty.
            profile: A :class:`Profile` object (whose overrides are merged in),
                a dict (merged in directly), or None.

        Returns:
            dict: The assembled request body.

        Raises:
            InvalidArgumentException: If ``profile`` is neither a
                :class:`Profile` object, a dict, nor None.
        """
        body = {}
        if name != "":
            body['name'] = name
        if profile is not None:
            if isinstance(profile, Profile):
                body.update(profile.profileOverride)
            elif isinstance(profile, dict):
                body.update(profile)
            else:
                raise InvalidArgumentException("'profile' should be a Profile object or dict.")
        return body

    def listProfile(self, order: int = -1, limit: int = 10, offset: int = 0):
        """List KYC profiles.

        Args:
            order (int): Sort order, ``-1`` for newest first or ``1`` for
                oldest first. Defaults to ``-1``.
            limit (int): Number of items to return per call. Defaults to 10.
            offset (int): Start the list from this entry index. Defaults to 0.

        Returns:
            dict: The decoded API response containing the list of profiles.

        Raises:
            InvalidArgumentException: If ``order`` is not 1 or -1.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if order not in [1, -1]:
            raise InvalidArgumentException("'order' should be integer of 1 or -1.")
        payload = {"order": order, "limit": limit, "offset": offset}
        resp = self.http.get(GetEndpoint('profile'), params=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def getProfile(self, profileId: str = ""):
        """Retrieve a single KYC profile.

        Args:
            profileId (str): Profile ID to retrieve. Required. Defaults to
                ``""``.

        Returns:
            dict: The decoded API response containing the profile.

        Raises:
            InvalidArgumentException: If ``profileId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if profileId == "":
            raise InvalidArgumentException("'profileId' required.")
        resp = self.http.get(GetEndpoint('profile/{}'.format(profileId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def createProfile(self, name: str = "", profile=None):
        """Create a new KYC profile.

        Args:
            name (str): Profile name. Required. Defaults to ``""``.
            profile: A :class:`Profile` object (its overrides become the
                profile config) or a dict. Defaults to None.

        Returns:
            dict: The decoded API response containing the created profile.

        Raises:
            InvalidArgumentException: If ``name`` is empty, or if ``profile``
                is neither a :class:`Profile` object, a dict, nor None.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if name == "":
            raise InvalidArgumentException("Profile name required.")
        resp = self.http.post(GetEndpoint('profile'), json=self._profileBody(name, profile), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def updateProfile(self, profileId: str = "", name: str = "", profile=None):
        """Update an existing KYC profile.

        Args:
            profileId (str): Profile ID to update. Required. Defaults to ``""``.
            name (str): Profile name. Included only when non-empty. Defaults to
                ``""``.
            profile: A :class:`Profile` object (its overrides become the
                profile config) or a dict. Defaults to None.

        Returns:
            dict: The decoded API response containing the updated profile.

        Raises:
            InvalidArgumentException: If ``profileId`` is empty, or if
                ``profile`` is neither a :class:`Profile` object, a dict, nor
                None.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if profileId == "":
            raise InvalidArgumentException("'profileId' required.")
        resp = self.http.put(GetEndpoint('profile/{}'.format(profileId)),
                             json=self._profileBody(name, profile), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def deleteProfile(self, profileId: str = ""):
        """Delete a KYC profile.

        Args:
            profileId (str): Profile ID to delete. Required. Defaults to ``""``.

        Returns:
            dict: The decoded API response confirming the deletion.

        Raises:
            InvalidArgumentException: If ``profileId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if profileId == "":
            raise InvalidArgumentException("'profileId' required.")
        resp = self.http.delete(GetEndpoint('profile/{}'.format(profileId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def exportProfile(self, profileId: str = ""):
        """Export a KYC profile (GET /export/profile/{id}).

        Args:
            profileId (str): Profile ID to export. Required. Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the exported profile.

        Raises:
            InvalidArgumentException: If ``profileId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if profileId == "":
            raise InvalidArgumentException("'profileId' required.")
        resp = self.http.get(GetEndpoint('export/profile/{}'.format(profileId)), timeout=60)
        return ApiExceptionHandle(resp, self.throwError)


class Webhook(_ApiParent):
    """Client for webhook delivery log management.

    Wraps the ``/webhook`` API endpoint to list webhook delivery logs and to
    resend or delete individual deliveries.
    """

    def __init__(self, apiKey=None):
        """Initialize the webhook client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    def listWebhook(self, order: int = -1, limit: int = 10, offset: int = 0, event: str = "",
                    success: int = -1, createdAtMin: str = "", createdAtMax: str = ""):
        """List webhook delivery logs.

        Args:
            order (int): Sort order, ``-1`` for newest first or ``1`` for
                oldest first. Defaults to ``-1``.
            limit (int): Number of items to return per call. Defaults to 10.
            offset (int): Start the list from this entry index. Defaults to 0.
            event (str): Filter by event type. Ignored when empty. Defaults to
                ``""``.
            success (int): Filter by delivery success, ``1`` for successful or
                ``0`` for failed. Any other value (e.g. the default ``-1``) is
                ignored. Defaults to ``-1``.
            createdAtMin (str): List only deliveries created after this
                timestamp. Ignored when empty. Defaults to ``""``.
            createdAtMax (str): List only deliveries created before this
                timestamp. Ignored when empty. Defaults to ``""``.

        Returns:
            dict: The decoded API response containing the list of webhook
            delivery logs.

        Raises:
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        payload = {"order": order, "limit": limit, "offset": offset}
        if event != "":
            payload['event'] = event
        if success in (0, 1):
            payload['success'] = success
        if createdAtMin != "":
            payload['createdAtMin'] = createdAtMin
        if createdAtMax != "":
            payload['createdAtMax'] = createdAtMax
        resp = self.http.get(GetEndpoint('webhook'), params=payload, timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def resendWebhook(self, webhookId: str = ""):
        """Resend a webhook delivery.

        Args:
            webhookId (str): ID of the webhook delivery to resend. Required.
                Defaults to ``""``.

        Returns:
            dict: The decoded API response confirming the resend.

        Raises:
            InvalidArgumentException: If ``webhookId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if webhookId == "":
            raise InvalidArgumentException("'webhookId' required.")
        resp = self.http.post(GetEndpoint('webhook/{}'.format(webhookId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def deleteWebhook(self, webhookId: str = ""):
        """Delete a webhook delivery log.

        Args:
            webhookId (str): ID of the webhook delivery log to delete.
                Required. Defaults to ``""``.

        Returns:
            dict: The decoded API response confirming the deletion.

        Raises:
            InvalidArgumentException: If ``webhookId`` is empty.
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        if webhookId == "":
            raise InvalidArgumentException("'webhookId' required.")
        resp = self.http.delete(GetEndpoint('webhook/{}'.format(webhookId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)


class Account(_ApiParent):
    """Client for account information.

    Wraps the ``/myaccount`` API endpoint to retrieve the current account
    profile, quota and usage.
    """

    def __init__(self, apiKey=None):
        """Initialize the account client.

        Args:
            apiKey (str, optional): Your ID Analyzer API key. If omitted, the
                key is read from the ``IDANALYZER_KEY`` environment variable.
                Defaults to None.

        Raises:
            Exception: If no API key is supplied and ``IDANALYZER_KEY`` is
                unset or empty.
        """
        super().__init__(apiKey)

    def getAccount(self):
        """Retrieve the current account profile, quota and usage.

        Returns:
            dict: The decoded API response containing the account profile,
            quota and usage information.

        Raises:
            APIError: If exception throwing is enabled and the API returns an
                error.
        """
        resp = self.http.get(GetEndpoint('myaccount'), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)
