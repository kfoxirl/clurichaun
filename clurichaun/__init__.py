"""Clurichaun — universal secret, credential and endpoint scanner."""

from __future__ import annotations

from .detect import DetectorConfig, SecretDetector
from .ingest import FileIngestor, IngestLimits
from .models import Blob, Detector, Finding, ScanStats, Severity
from .scanner import ScanConfig, ScannerEngine
from .scope import ScopeFilter

__version__ = "0.1.0"

__all__ = [
    "Blob",
    "Detector",
    "DetectorConfig",
    "FileIngestor",
    "Finding",
    "IngestLimits",
    "ScanConfig",
    "ScanStats",
    "ScannerEngine",
    "ScopeFilter",
    "SecretDetector",
    "Severity",
    "__version__",
]
