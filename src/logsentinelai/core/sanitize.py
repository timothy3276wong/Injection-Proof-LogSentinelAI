"""
Prompt-injection defense: prepare untrusted log lines for insertion into an LLM prompt.

Log text is attacker-controllable (URLs, user-agents, referers, usernames), so every
prompt builder must pass chunk lines through this module instead of inserting them raw.
Design decisions are recorded in docs/defense-1-decisions.md.

Implemented so far:
  Decision 1 - one shared place for the defense (this module).
  Decision 2 - random per-prompt markers around the log block, so an attacker
               cannot write a matching end marker into a log line.
  Decision 3 - defuse marker-like text inside log lines.
"""

import re
import secrets
from typing import Iterable

MARKER_NAME = "LOG_DATA"   # fixed part of every marker (Decision 3 will look for it)
MARKER_BYTES = 8           # 8 random bytes = 16 hex characters

# Decision 3: marker-like text inside a log line. Only angle-bracketed text that also
# contains a marker word is matched, so real payloads (<script>) and plain XML tags
# (<log>, <logs>) are left alone.
FAKE_MARKER_PATTERNS = [
    # old upstream style: <LOGS END>, <LOGS BEGIN>, </LOGS END>, <log begin ...>
    re.compile(r"<\s*/?\s*LOGS?\s+(?:BEGIN|END)\b[^<>]*>", re.IGNORECASE),
    # fakes of our own marker: <<<LOG_DATA_1234 END>>>, <LOG_DATA ...>
    re.compile(r"<+[^<>]*LOG_DATA[^<>]*>+", re.IGNORECASE),
]


def new_marker_code() -> str:
    """Return a fresh, unpredictable code for one prompt's markers."""
    return secrets.token_hex(MARKER_BYTES)


def defuse_fake_markers(line: str) -> str:
    """Turn marker-like text into harmless text: '<LOGS END>' -> '(LOGS END)'."""
    for pattern in FAKE_MARKER_PATTERNS:
        line = pattern.sub(lambda m: m.group(0).replace("<", "(").replace(">", ")"), line)
    return line


def wrap_untrusted_logs(lines: Iterable[str]) -> str:
    """Return the chunk's log lines wrapped in random begin/end markers.

    Lines are stripped and empty lines dropped, as in the original code.
    The result is inserted at the prompt template's {logs} slot.
    """
    code = new_marker_code()
    begin = f"<<<{MARKER_NAME}_{code} BEGIN>>>"
    end = f"<<<{MARKER_NAME}_{code} END>>>"
    body = "\n".join(defuse_fake_markers(line.strip()) for line in lines if line.strip())
    return f"{begin}\n{body}\n{end}"
