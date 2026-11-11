"""The one data model every check returns.

Keeping checks pure (inputs in, findings out) is what lets a future AI layer
call the same functions and reason over the same JSON.
"""

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    ERROR = 2
    CRITICAL = 3

    def __str__(self):
        return self.name.lower()


@dataclass
class Finding:
    check: str  # stable ID, e.g. "GA003" or "auth.expired"
    severity: Severity
    area: str  # "auth", "cluster", "pipeline", "workflow", "argo"
    resource: str  # what it is about, e.g. "prod" or "org/repo:.github/workflows/ci.yml"
    message: str
    fix: str = ""
    link: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


def worst(findings):
    return max((f.severity for f in findings), default=None)
