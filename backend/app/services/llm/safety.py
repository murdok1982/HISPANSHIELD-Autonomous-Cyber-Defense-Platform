"""Prompt-safety helpers for untrusted tool, RAG and connector output.

Nothing that arrives from an external system (MCP tool result, knowledge chunk,
connector payload, LLM completion) is trusted as an instruction. These helpers
detect instruction-like content, neutralize it, and wrap it in explicit
untrusted-data delimiters before it is placed in a *user* message. Tool output is
never allowed in the system role.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_UNTRUSTED_CHARS = 8000
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")
WHITESPACE = re.compile(r"[ \t]{2,}")

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous_instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|system)\b"
            r"[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rules|directions)\b",
            re.IGNORECASE,
        ),
    ),
    ("forget_everything", re.compile(r"\bforget\s+(?:everything|all\s+previous)\b", re.IGNORECASE)),
    (
        "role_override",
        re.compile(r"^\s*(?:system|assistant|developer)\s*:", re.IGNORECASE | re.MULTILINE),
    ),
    ("chat_template_marker", re.compile(r"<\|(?:im_start|im_end|system|assistant)\|>|\[/?INST\]", re.IGNORECASE)),
    (
        "you_are_now",
        re.compile(r"\byou\s+are\s+now\s+(?:a|an|the|my)\b[^.\n]{0,60}", re.IGNORECASE),
    ),
    (
        "reveal_system_prompt",
        re.compile(
            r"\b(?:reveal|print|show|repeat|leak)\b[^.\n]{0,30}\b(?:system\s+prompt|hidden\s+instructions|"
            r"developer\s+message|initial\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "execute_command",
        re.compile(
            r"\b(?:execute|run|invoke|call)\b[^.\n]{0,30}\b(?:following|this)\b[^.\n]{0,20}"
            r"\b(?:command|tool|function|shell|script)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "override_policy",
        re.compile(
            r"\b(?:override|bypass|disable|circumvent)\b[^.\n]{0,30}\b(?:safety|policy|guardrail|restriction|"
            r"permission)s?\b",
            re.IGNORECASE,
        ),
    ),
    ("jailbreak", re.compile(r"\b(?:jailbreak|DAN\s+mode|developer\s+mode\s+enabled)\b", re.IGNORECASE)),
    (
        "exfiltration",
        re.compile(
            r"\b(?:send|post|upload|exfiltrate)\b[^.\n]{0,30}\b(?:api\s*key|token|secret|password|credentials)\b",
            re.IGNORECASE,
        ),
    ),
)

_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)\b(api[_-]?key|token|password|secret|authorization)\b\s*[:=]\s*\S+"),
)


@dataclass(frozen=True)
class SafetyVerdict:
    suspected: bool
    matches: list[str] = field(default_factory=list)
    base64_detected: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "suspected": self.suspected,
            "matches": list(self.matches),
            "base64_detected": self.base64_detected,
        }


def _is_base64_blob(candidate: str) -> bool:
    """Reject low-entropy runs (e.g. ``xxxx…``) that are not encoded payloads."""
    if len(candidate) < 80 or len(set(candidate)) < 12:
        return False
    return bool(re.search(r"[A-Z]", candidate)) and bool(re.search(r"[a-z]", candidate))


def _replace_base64(match: re.Match[str]) -> str:
    return "[base64-blob removed]" if _is_base64_blob(match.group(0)) else match.group(0)


def scan_injection(text: str) -> SafetyVerdict:
    """Detect instruction-like content and encoded payloads. Never executes it."""
    if not text:
        return SafetyVerdict(suspected=False)
    matches = [label for label, pattern in _INJECTION_PATTERNS if pattern.search(text)]
    base64_detected = any(_is_base64_blob(match.group(0)) for match in BASE64_BLOB.finditer(text))
    return SafetyVerdict(suspected=bool(matches or base64_detected), matches=matches, base64_detected=base64_detected)


def strip_control_chars(text: str) -> str:
    return CONTROL_CHARS.sub("", text)


def redact_prompt(text: str, max_chars: int = 2000) -> str:
    """Produce a safe, bounded prompt copy for invocation logs."""
    value = strip_control_chars(text or "")
    for pattern in _REDACTION_PATTERNS:
        value = pattern.sub("[redacted]", value)
    value = BASE64_BLOB.sub(_replace_base64, value)
    value = WHITESPACE.sub(" ", value)
    if len(value) > max_chars:
        value = value[:max_chars] + "…"
    return value


def neutralize(text: str, *, max_chars: int = MAX_UNTRUSTED_CHARS) -> str:
    """Remove control characters and replace instruction-like spans with inert markers."""
    value = strip_control_chars(text or "")
    value = BASE64_BLOB.sub(_replace_base64, value)
    for label, pattern in _INJECTION_PATTERNS:
        value = pattern.sub(f"[neutralized:{label}]", value)
    value = value.replace("</untrusted-data>", "[delimiter-escaped]")
    value = value.replace("<untrusted-data", "[delimiter-escaped]")
    value = WHITESPACE.sub(" ", value)
    if len(value) > max_chars:
        value = value[:max_chars] + "…[truncated]"
    return value


def wrap_untrusted_data(source: str, text: str, *, max_chars: int = MAX_UNTRUSTED_CHARS) -> str:
    """Wrap external content so the model can distinguish data from instructions."""
    safe_source = re.sub(r"[^A-Za-z0-9_.:#-]", "", str(source or ""))[:80] or "unknown"
    body = neutralize(text, max_chars=max_chars)
    return f'<untrusted-data source="{safe_source}">\n{body}\n</untrusted-data>'


def compose_messages(system_prompt: str, user_content: str) -> list[dict[str, str]]:
    """Build a chat payload where only code-owned text occupies the system role."""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]


def looks_like_refusal(text: str) -> bool:
    """Deterministic refusal detector used by the evaluation rubric."""
    lowered = (text or "").lower()
    markers = (
        "no evidence",
        "insufficient evidence",
        "not enough evidence",
        "cannot determine",
        "unable to determine",
        "cannot answer",
        "can't answer",
        "no information available",
        "sin evidencia",
        "evidencia insuficiente",
        "no hay evidencia",
        "no puedo determinar",
        "no es posible determinar",
        "información insuficiente",
    )
    return any(marker in lowered for marker in markers)


__all__ = [
    "MAX_UNTRUSTED_CHARS",
    "SafetyVerdict",
    "compose_messages",
    "looks_like_refusal",
    "neutralize",
    "redact_prompt",
    "scan_injection",
    "strip_control_chars",
    "wrap_untrusted_data",
]
