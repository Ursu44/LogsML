from dataclasses import dataclass, field
from typing import List


@dataclass
class RuleResult:
    score:     float       = 0.0
    triggered: bool        = False
    rules:     List[str]   = field(default_factory=list)
    shortcut:  bool        = False
