"""ID Analyzer v2 Python SDK.

This package provides Python clients for the ID Analyzer API v2, including
identity document scanning, biometric face verification, AML screening,
Docupass hosted verification, contract generation, transaction management,
KYC profile management, webhook management, and account information.

Importing this package re-exports the public API client classes (for example
:class:`Scanner`, :class:`Biometric`, :class:`Docupass`, :class:`AML`,
:class:`Contract`, :class:`Transaction`, :class:`ProfileAPI`,
:class:`Webhook`, :class:`Account`) and the :class:`Profile` configuration
helper, along with the :class:`APIError` and :class:`InvalidArgumentException`
exception types.

The target API region (``us`` or ``eu``) is selected via the
``IDANALYZER_REGION`` environment variable, and the API key may be supplied
either per-client or via the ``IDANALYZER_KEY`` environment variable.
"""

from .idanalyzer import *
from .myException import *
