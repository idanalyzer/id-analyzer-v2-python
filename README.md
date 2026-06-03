# ID Analyzer Python SDK — Identity Verification, KYC, Document & Biometric API

[![PyPI version](https://img.shields.io/pypi/v/idanalyzer2.svg)](https://pypi.org/project/idanalyzer2/)
[![Python versions](https://img.shields.io/pypi/pyversions/idanalyzer2.svg)](https://pypi.org/project/idanalyzer2/)
[![license](https://img.shields.io/pypi/l/idanalyzer2.svg)](LICENSE)

Official Python client library for the **[ID Analyzer](https://www.idanalyzer.com) API v2** — automate identity document verification, KYC onboarding and biometric checks in minutes.

Scan and authenticate **passports, driver's licenses, ID cards, visas and residence permits from 190+ countries**, run **1:1 face match and liveness detection**, screen against **AML / PEP / sanctions** watchlists, and onboard users remotely with **DocuPass** hosted verification & e-signature.

- 🌐 **Website:** [www.idanalyzer.com](https://www.idanalyzer.com)
- 📚 **Developer docs & API reference:** [developer.idanalyzer.com](https://developer.idanalyzer.com/help)
- 🔑 **Get your API key:** [portal2.idanalyzer.com](https://portal2.idanalyzer.com)
- 💬 **Support:** support@idanalyzer.com

## Features

- **Document OCR & authentication** — passport, driver's license, ID card, visa & residence-permit recognition from 190+ countries, including MRZ and PDF417 / AAMVA barcode parsing.
- **Biometric verification** — 1:1 face match and liveness / presentation-attack detection.
- **AML screening** — PEP, sanctions, watchlist and adverse-media checks.
- **DocuPass** — hosted, no-code remote identity verification, KYC/AML onboarding and legally-binding e-signature.
- **KYC profiles, transaction vault, contract generation and webhooks.**
- **US & EU data-residency regions.**

> ⚠️ Never embed your API key in client-side apps (mobile, browser JS). Call the API from your server.

## Installation

```bash
pip install idanalyzer2
```

Requires Python 3.8+. The `requests` and `validators` dependencies install automatically.

## Authentication & region

Pass your API key to each client, or set the `IDANALYZER_KEY` environment variable. The SDK targets the US endpoint (`https://api2.idanalyzer.com`) by default; set `IDANALYZER_REGION=eu` for the EU endpoint (`https://api2-eu.idanalyzer.com`). An unrecognized region raises `InvalidArgumentException`.

## Quick start

```python
from idanalyzer2 import *

scanner = Scanner("YOUR_API_KEY")
scanner.throwApiException(True)
scanner.setProfile(Profile(Profile.SECURITY_MEDIUM))

# Scan a document + selfie for biometric verification
result = scanner.scan("id_front.jpg", "", "selfie.jpg")
print(result["decision"])   # accept / review / reject
```

## Examples

```python
from idanalyzer2 import *

# AML / PEP / sanctions screening
aml = AML("YOUR_API_KEY")
aml.search(name="John Smith", country="US")          # POST /aml
aml.searchV3(text="John Smith", limit=10, page=1)    # POST /amlv3

# DocuPass — hosted remote verification link
docupass = Docupass("YOUR_API_KEY")
link = docupass.createDocupass("YOUR_PROFILE_ID")
print(link["url"])
```

More demos in the [`/demo`](demo) folder.

## API coverage

The SDK wraps the complete ID Analyzer API v2 surface:

| Class | Methods |
|---|---|
| `Scanner` | `scan`, `quickScan`, `veryQuickScan` |
| `Biometric` | `verifyFace`, `verifyLiveness` |
| `AML` | `search` (`/aml`), `searchV3` (`/amlv3`) |
| `Contract` | `generate` + template CRUD |
| `Transaction` | `getTransaction`, `listTransaction`, `updateTransaction`, `deleteTransaction`, `exportTransaction`, `saveImage`, `saveFile` |
| `Docupass` | `createDocupass`, `listDocupass`, `getDocupass`, `deleteDocupass` |
| `ProfileAPI` | KYC profile create / list / get / update / delete / export |
| `Webhook` | `listWebhook`, `resendWebhook`, `deleteWebhook` |
| `Account` | `getAccount` |
| `Profile` | client-side KYC profile-override builder |

## Resources

- [ID Analyzer website](https://www.idanalyzer.com)
- [Developer documentation & API reference](https://developer.idanalyzer.com/help)
- [Python SDK guide](https://developer.idanalyzer.com/help/python)
- [Dashboard — get your API key](https://portal2.idanalyzer.com)

## Other ID Analyzer SDKs

[PHP](https://github.com/idanalyzer/id-analyzer-v2-php) · [Python](https://github.com/idanalyzer/id-analyzer-v2-python) · [Node.js](https://github.com/idanalyzer/id-analyzer-v2-nodejs) · [.NET](https://github.com/idanalyzer/id-analyzer-v2-dotnet) · [Java](https://github.com/idanalyzer/id-analyzer-v2-java) · [Go](https://github.com/idanalyzer/id-analyzer-v2-go)

## License

MIT © [ID Analyzer](https://www.idanalyzer.com) — see [LICENSE](LICENSE).
