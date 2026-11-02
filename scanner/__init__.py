"""WebVulnScanner — a lightweight, authorised-testing web vulnerability scanner."""

from .models import Finding, ScanResult  # noqa: F401 (re-export)
from .scanner import ScanConfig, Scanner  # noqa: F401 (re-export)

__version__ = "2.4.0"
