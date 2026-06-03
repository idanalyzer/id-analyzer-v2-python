# Changelog

## 1.1.0 (2026-06-03)

Full API v2 surface parity + base URL fix.

### Fixed
- **Base URL now defaults to the `https://api2.idanalyzer.com`**
  instead of the single node `https://v2-us1.idanalyzer.com` (no HA). EU is
  unchanged (`https://api2-eu.idanalyzer.com` via `IDANALYZER_REGION=eu`).
- An unrecognized `IDANALYZER_REGION` now raises `InvalidArgumentException`
  instead of silently returning `None` (which crashed every request).
- Declared the `validators` dependency in `setup.py` (was imported but never
  declared → `ImportError` on a clean install).

### Added
- `Scanner.veryQuickScan` → `POST /veryquickscan`.
- `AML` class — `search` (`POST /aml`, incl. optional `birthYear`) and
  `searchV3` (`POST /amlv3`).
- `Docupass.getDocupass` → `GET /docupass/{reference}`.
- `ProfileAPI` class — server-side KYC profile CRUD + export
  (`/profile`, `/export/profile/{id}`).
- `Webhook` class — `listWebhook`/`resendWebhook`/`deleteWebhook` (`/webhook`).
- `Account` class — `getAccount` (`GET /myaccount`).
- Demos for the new classes under `/demo`.

### Packaging
- `python_requires>=3.8`; removed the inaccurate Python 2 classifier; pinned
  `requests>=2.20.0`.
