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
    def __init__(self, apiKey=None):
        """
        :param apiKey: You API key
        :raises Exception: Please set API key via environment variable 'IDANALYZER_KEY'
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
        return customKey if customKey is not None else os.getenv('IDANALYZER_KEY', None)

    def setParam(self, key, value):
        """
        Set an API parameter and its value, this function allows you to set any API parameter without using the built-in functions

        :param key: Parameter key
        :param value: Parameter value
        :return:
        """
        self.config[key] = value

    def throwApiException(self, sw=False):
        """
        Whether an exception should be thrown if API response contains an error message

        :param sw: Throw exception upon API error, defaults to false
        :return:
        """
        self.throwError = sw


class Profile:
    SECURITY_NONE = "security_none"
    SECURITY_LOW = "security_low"
    SECURITY_MEDIUM = "security_medium"
    SECURITY_HIGH = "security_high"

    def __init__(self, profileId):
        """
          Initialize KYC Profile

          :param profileId: Custom profile ID or preset profile (security_none, security_low, security_medium, security_high). SECURITY_NONE will be used if left blank.
        """
        self.URL_VALIDATION_REGEX = "((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        self.profileId = profileId if profileId != '' else self.SECURITY_NONE
        self.profileOverride = {}

    def loadFromJson(self, jsonStr: str):
        """
          Set profile configuration with provided JSON string

          :param jsonStr: JSON string containing profile information.
          :return
        """
        self.profileOverride = json.loads(jsonStr)

    def canvasSize(self, pixels: int):
        """
          Canvas Size in pixels, input image larger than this size will be scaled down before further processing, reduced image size will improve inference time but reduce result accuracy. Set 0 to disable image resizing.

          :param pixels
          :return
        """
        self.profileOverride['canvasSize'] = pixels

    def orientationCorrection(self, enabled: bool):
        """
        Correct image orientation for rotated images

        :param enabled:
        :return:
        """
        self.profileOverride['orientationCorrection'] = enabled

    def objectDetection(self, enabled: bool):
        """
        Enable to automatically detect and return the locations of signature, document and face.

        :param enabled:
        :return:
        """
        self.profileOverride['objectDetection'] = enabled

    def AAMVABarcodeParsing(self, enabled: bool):
        """
        Enable to parse AAMVA barcode for US/CA ID/DL. Disable this to improve performance if you are not planning on scanning ID/DL from US or Canada.

        :param enabled:
        :return:
        """
        self.profileOverride['AAMVABarcodeParsing'] = enabled

    def saveResult(self, enableSaveTransaction: bool, enableSaveTransactionImages: bool):
        """
        Whether scan transaction results and output images should be saved on cloud

        :param enableSaveTransaction:
        :param enableSaveTransactionImages:
        :return:
        """
        self.profileOverride['saveResult'] = enableSaveTransaction
        if enableSaveTransaction:
            self.profileOverride['saveImage'] = enableSaveTransactionImages

    def outputImage(self, enableOutputImage: bool, outputFormat="url"):
        """
        Whether to return output image as part of API response

        :param enableOutputImage:
        :param outputFormat:
        :return:
        """
        self.profileOverride['outputImage'] = enableOutputImage
        if enableOutputImage:
            self.profileOverride['outputType'] = outputFormat

    def autoCrop(self, enableAutoCrop: bool, enableAdvancedAutoCrop: bool):
        """
        Crop image before saving and returning output

        :param enableAutoCrop:
        :param enableAdvancedAutoCrop:
        :return:
        """
        self.profileOverride['crop'] = enableAutoCrop
        self.profileOverride['advancedCrop'] = enableAdvancedAutoCrop

    def outputSize(self, pixels: int):
        """
        Maximum width/height in pixels for output and saved image.

        :param pixels:
        :return:
        """
        self.profileOverride['outputSize'] = pixels

    def inferFullName(self, enabled: bool):
        """
        Generate a full name field using parsed first name, middle name and last name.

        :param enabled:
        :return:
        """
        self.profileOverride['inferFullName'] = enabled

    def splitFirstName(self, enabled: bool):
        """
        If first name contains more than one word, move second word onwards into middle name field.

        :param enabled:
        :return:
        """
        self.profileOverride['splitFirstName'] = enabled

    def transactionAuditReport(self, enabled: bool):
        """
        Enable to generate a detailed PDF audit report for every transaction.

        :param enabled:
        :return:
        """
        self.profileOverride['transactionAuditReport'] = enabled

    def setTimezone(self, timezone: str):
        """
        Set timezone for audit reports. If left blank, UTC will be used. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones TZ database name list.

        :param timezone:
        :return:
        """
        self.profileOverride['timezone'] = timezone

    def obscure(self, fieldKeys: list[str]):
        """
        A list of data fields key to be redacted before transaction storage, these fields will also be blurred from output & saved image.

        :param fieldKeys:
        :return:
        """
        self.profileOverride['obscure'] = fieldKeys

    def webhook(self, url: str = "https://www.example.com/webhook.php"):
        """
        Enter a server URL to listen for Docupass verification and scan transaction results

        :param url:
        :return:
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
        """
        Set validation threshold of a specified component

        :param thresholdKey:
        :param thresholdValue:
        :return:
        """
        self.profileOverride['thresholds'][thresholdKey] = thresholdValue

    def decisionTrigger(self, reviewTrigger: float = 1, rejectTrigger: float = 1):
        """
        Set decision trigger value

        :param reviewTrigger: If the final total review score is equal to or greater than this value, the final KYC decision will be "review"
        :param rejectTrigger: If the final total review score is equal to or greater than this value, the final KYC decision will be "reject". Reject has higher priority than review.
        :return:
        """
        self.profileOverride['decisionTrigger'] = {
            'review': reviewTrigger,
            'reject': rejectTrigger,
        }

    def setWarning(self, code: str = "UNRECOGNIZED_DOCUMENT", enabled: bool = True, reviewThreshold: float = -1,
                   rejectThreshold: float = 0, weight: float = 1):
        """
        Enable/Disable and fine-tune how each Document Validation Component affects the final decision.

        :param code: Document Validation Component Code / Warning Code
        :param enabled: Enable the current Document Validation Component
        :param reviewThreshold: If the current validation has failed to pass, and the specified number is greater than or equal to zero, and the confidence of this warning is greater than or equal to the specified value, the "total review score" will be added by the weight value.
        :param rejectThreshold: If the current validation has failed to pass, and the specified number is greater than or equal to zero, and the confidence of this warning is greater than or equal to the specified value, the "total reject score" will be added by the weight value.
        :param weight: Weight to add to the total review and reject score if the validation has failed to pass.
        :return:
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
        """
        Check if the document was issued by specified countries. Separate multiple values with comma. For example "US,CA" would accept documents from the United States and Canada.

        :param countryCodes: ISO ALPHA-2 Country Code separated by comma
        :return:
        """
        if 'acceptedDocuments' in self.profileOverride:
            self.profileOverride['acceptedDocuments'] = {}
        self.profileOverride['acceptedDocuments']['documentCountry'] = countryCodes

    def restrictDocumentState(self, states: str = "CA,TX"):
        """
        Check if the document was issued by specified state. Separate multiple values with comma. For example "CA,TX" would accept documents from California and Texas.

        :param states: State full name or abbreviation separated by comma
        :return:
        """
        if 'acceptedDocuments' in self.profileOverride:
            self.profileOverride['acceptedDocuments'] = {}
        self.profileOverride['acceptedDocuments']['documentState'] = states

    def restrictDocumentType(self, documentType: str = "DIP"):
        """
        Check if the document was one of the specified types. For example, "PD" would accept both passport and driver license.

        :param documentType: P: Passport, D: Driver's License, I: Identity Card
        :return:
        """
        if 'acceptedDocuments' in self.profileOverride:
            self.profileOverride['acceptedDocuments'] = {}
        self.profileOverride['acceptedDocuments']['documentType'] = documentType


class Biometric(_ApiParent):
    def __init__(self, apiKey=None):
        super().__init__(apiKey)

        self.config.update({
            "profile": "",
            "profileOverride": {},
            "customData": "",
        })

    def setCustomData(self, customData):
        """
        Set an arbitrary string you wish to save with the transaction. e.g Internal customer reference number

        :param customData:
        :return:
        """
        self.config['customData'] = customData

    def setProfile(self, profile):
        """
        Set KYC Profile

        :param profile: KYCProfile object
        :return:
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
        """
        Perform 1:1 face verification using selfie photo or selfie video, against a reference face image.

        :param referenceFaceImage: Front of Document (file path, base64 content, url, or cache reference)
        :param facePhoto: Face Photo (file path, base64 content or URL, or cache reference)
        :param faceVideo: Face Video (file path, base64 content or URL)
        :return:
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
        """
        Perform standalone liveness check on a selfie photo or video.

        :param facePhoto: Face Photo (file path, base64 content or URL, or cache reference)
        :param faceVideo: Face Video (file path, base64 content or URL)
        :return:
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
    def __init__(self, apiKey=None):
        super().__init__(apiKey)

    def generate(self, templateId: str = '', _format: str = 'PDF', transactionId: str = '', fillData=None):
        """
        Generate document using template and transaction data

        :param templateId: Template ID
        :param _format: PDF, DOCX or HTML
        :param transactionId: Fill the template with data from specified transaction
        :param fillData: Array data in key-value pairs to autofill dynamic fields, data from user ID will be used first in case of a conflict. For example, passing {"myparameter":"abc"} would fill %{myparameter} in contract template with "abc".
        :return:
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
        """
        Retrieve a list of contract templates

        :param order: Sort results by newest(-1) or oldest(1)
        :param limit: Number of items to be returned per call
        :param offset: Start the list from a particular entry index
        :param filterTemplateId: Filter result by template ID
        :return:
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
        """
        Get contract template

        :param templateId: Template ID
        :return:
        """
        if templateId == "":
            raise InvalidArgumentException('Template ID required.')

        resp = self.http.get(GetEndpoint('contract/{}'.format(templateId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def deleteTemplate(self, templateId: str = ""):
        """
        Delete contract template

        :param templateId: Template ID
        :return:
        """
        if templateId == "":
            raise InvalidArgumentException('Template ID required.')

        resp = self.http.delete(GetEndpoint('contract/{}'.format(templateId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def createTemplate(self, name: str = "", content: str = "", orientation: str = "0", timezone: str = "UTC",
                       font: str = "Open Sans"):
        """
        Create new contract template

        :param name: Template name
        :param content: Template HTML content
        :param orientation: 0=Portrait(Default) 1=Landscape
        :param timezone: Template timezone
        :param font: Template font
        :return:
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
        """
        Update contract template

        :param templateId: Template ID
        :param name: Template name
        :param content: Template HTML content
        :param orientation: 0=Portrait(Default) 1=Landscape
        :param timezone: Template timezone
        :param font: Template font
        :return:
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
    def __init__(self, apiKey=None):
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
        """
        Pass in user IP address to check if ID is issued from the same country as the IP address, if no value is provided http connection IP will be used.

        :param ip:
        :return:
        """
        self.config['ip'] = ip

    def setCustomData(self, customData: str):
        """
        Set an arbitrary string you wish to save with the transaction. e.g Internal customer reference number

        :param customData:
        :return:
        """
        self.config['customData'] = customData

    def setContractOptions(self, templateId: str = "", _format: str = "PDF", extraFillData=None):
        """
        Automatically generate contract document using value parsed from uploaded ID

        :param templateId: Enter up to 5 contract template ID (seperated by comma)
        :param _format: PDF, DOCX or HTML
        :param extraFillData: Array data in key-value pairs to autofill dynamic fields, data from user ID will be used first in case of a conflict. For example, passing {"myparameter":"abc"} would fill %{myparameter} in contract template with "abc".
        :return:
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
        """
        Set KYC Profile

        :param profile: KYCProfile object
        :return:
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
        """
        Check if customer information matches with uploaded document

        :param documentNumber: Document or ID number
        :param fullName: Full name
        :param dob: Date of birth in YYYY/MM/DD
        :param ageRange: Age range, example: 18-40
        :param address: Address
        :param postcode: Postcode
        :return:
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
        """
        Check if the document was issued by specified countries. Separate multiple values with comma. For example "US,CA" would accept documents from the United States and Canada.

        :param countryCodes: ISO ALPHA-2 Country Code separated by comma
        :return:
        """
        self.config['restrictCountry'] = countryCodes

    def restrictState(self, states: str = "CA,TX"):
        """
        Check if the document was issued by specified state. Separate multiple values with comma. For example "CA,TX" would accept documents from California and Texas.

        :param states: State full name or abbreviation separated by comma
        :return:
        """
        self.config['restrictState'] = states

    def restrictType(self, documentType: str = "DIP"):
        """
        Check if the document was one of the specified types. For example, "PD" would accept both passport and driver license.

        :param documentType: P: Passport, D: Driver's License, I: Identity Card
        :return:
        """
        self.config['restrictType'] = documentType

    def scan(self, documentFront: str = "", documentBack: str = "", facePhoto: str = "", faceVideo: str = ""):
        """
        Initiate a new identity document scan & ID face verification transaction by providing input images.

        :param documentFront: Front of Document (file path, base64 content, url, or cache reference)
        :param documentBack: Back of Document (file path, base64 content or URL, or cache reference)
        :param facePhoto: Face Photo (file path, base64 content or URL, or cache reference)
        :param faceVideo: Face Video (file path, base64 content or URL)
        :return:
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
        """
        Initiate a quick identity document OCR scan by providing input images.

        :param documentFront: Front of Document (file path, base64 content or URL)
        :param documentBack: Back of Document (file path, base64 content or URL)
        :param cacheImage: Cache uploaded image(s) for 24 hours and obtain a cache reference for each image, the reference hash can be used to start standard scan transaction without re-uploading the file.
        :return:
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


class Transaction(_ApiParent):
    def __init__(self, apiKey=None):
        super().__init__(apiKey)

    def getTransaction(self, transactionId: str = ""):
        """
        Retrieve a single transaction record

        :param transactionId: Transaction ID
        :return:
        """
        if transactionId == "":
            raise InvalidArgumentException("Transaction ID required.")

        resp = self.http.get(GetEndpoint("transaction/{}".format(transactionId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def listTransaction(self, order: int = -1, limit: int = 10, offset: int = 0, createdAtMin: int = 0,
                        createdAtMax: int = 0, filterCustomData: str = "", filterDecision: str = "",
                        filterDocupass: str = "", filterProfileId: str = ""):
        """
        Retrieve a list of transaction history

        :param order: Sort results by newest(-1) or oldest(1)
        :param limit: Number of items to be returned per call
        :param offset: Start the list from a particular entry index
        :param createdAtMin: List transactions that were created after this timestamp
        :param createdAtMax: List transactions that were created before this timestamp
        :param filterCustomData: Filter result by customData field
        :param filterDecision: Filter result by decision (accept, review, reject)
        :param filterDocupass: Filter result by Docupass reference
        :param filterProfileId: Filter result by KYC Profile ID
        :return:
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
        """
        Update transaction decision, updated decision will be relayed to webhook if set.

        :param transactionId: Transaction ID
        :param decision: New decision (accept, review or reject)
        :return:
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
        """
        Delete a transaction

        :param transactionId: Transaction ID
        :return:
        """
        if transactionId == "":
            raise InvalidArgumentException('Transaction ID required.')

        resp = self.http.delete(GetEndpoint('transaction/{}'.format(transactionId)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)

    def saveImage(self, imageToken: str = "", destination: str = ""):
        """
        Download transaction image onto local file system

        :param imageToken: Image token from transaction API response
        :param destination: Full destination path including file name, file extension should be jpg, for example: '\home\idcard.jpg'
        :return:
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
        """
        Download transaction file onto local file system using secured file name obtained from transaction

        :param fileName: Secured file name
        :param destination: Full destination path including file name, for example: '\home\auditreport.pdf'
        :return:
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
        """
        Download transaction archive onto local file system

        :param destination: Full destination path including file name, file extension should be zip, for example: '\home\archive.zip'
        :param exportType: 'csv' or 'json'
        :param ignoreUnrecognized: Ignore unrecognized documents
        :param ignoreDuplicate: Ignore duplicated entries
        :param transactionId: Export only the specified transaction IDs
        :param createdAtMin: Export only transactions that were created after this timestamp
        :param createdAtMax: Export only transactions that were created before this timestamp
        :param filterCustomData: Filter export by customData field
        :param filterDecision: Filter export by decision (accept, review, reject)
        :param filterDocupass: Filter export by Docupass reference
        :param filterProfileId: Filter export by KYC Profile ID
        :return:
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
    def __init__(self, apiKey=None):
        super().__init__(apiKey)

    def listDocupass(self, order: int = -1, limit: int = 10, offset: int = 0):
        """
        :param order:
        :param limit:
        :param offset:
        :return:
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
        """
        :param mode:
        :param profile:
        :param contractFormat:
        :param contractGenerate:
        :param reusable:
        :param contractPrefill:
        :param contractSign:
        :param customData:
        :param language:
        :param referenceDocument:
        :param referenceDocumentBack:
        :param referenceFace:
        :param userPhone:
        :param verifyAddress:
        :param verifyAge:
        :param verifyDOB:
        :param verifyDocumentNumber:
        :param verifyName:
        :param verifyPostcode:
        :return:
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

    def deleteDocupass(self, reference=''):
        """
        :param reference:
        :return:
        """
        if reference == '':
            raise InvalidArgumentException("'reference' is required.")
        resp = self.http.delete(GetEndpoint('docupass/{}'.format(reference)), timeout=30)
        return ApiExceptionHandle(resp, self.throwError)
