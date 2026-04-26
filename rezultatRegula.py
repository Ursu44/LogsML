from dataclasses import dataclass, field
from typing import List

@dataclass
class RuleResult:
    triggered: bool = False
    score:     float = 0.0
    shortcut:  bool = False
    rules:     List[str] = field(default_factory=list)


def _fire(result: RuleResult,
          rule_name: str,
          score: float,
          shortcut: bool = False) -> None:

    result.triggered = True
    result.rules.append(rule_name)
    result.score = max(result.score, score)
    if shortcut:
        result.shortcut = True