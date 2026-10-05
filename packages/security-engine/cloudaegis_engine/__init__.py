"""CloudAegis security engine.

The engine is deliberately independent of the web application and of any
cloud SDK. Cloud providers translate their native API responses into
normalized :class:`~cloudaegis_engine.models.Resource` objects; detection
rules only ever see those normalized resources.
"""

from cloudaegis_engine.models import (
    CheckOutcome,
    Inventory,
    Resource,
    RuleMetadata,
    RuleResult,
    Severity,
)
from cloudaegis_engine.engine import ScanEngine, ScanOutput

__all__ = [
    "CheckOutcome",
    "Inventory",
    "Resource",
    "RuleMetadata",
    "RuleResult",
    "ScanEngine",
    "ScanOutput",
    "Severity",
]

__version__ = "1.0.0"
