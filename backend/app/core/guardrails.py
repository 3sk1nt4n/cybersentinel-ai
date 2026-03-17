"""
CyberSentinel v3.0 - AI Guardrails (Defense-in-Depth)

Code-level input/output filtering that works REGARDLESS of LLM compliance.
This is NOT a system prompt - it's hard enforcement that Qwen cannot bypass.

Covers:
- V11: Jailbreak pattern detection (prefix injection, DAN, evil persona, grandma, etc.)
- V12: RAG poisoning detection
- V13: System prompt extraction blocking
- Data exfiltration blocking (API keys, env vars, conversation history)
- Multi-turn escalation detection
- Output scanning for harmful content leakage
"""
import re
from typing import Optional


# ═══════════════════════════════════════════════════
# INPUT GUARDRAILS - Scan user messages BEFORE LLM
# ═══════════════════════════════════════════════════

# Each pattern has a category, regex, and severity
INPUT_PATTERNS = [
    # ── Direct jailbreak attempts ──
    ("jailbreak", r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions", "high"),
    ("jailbreak", r"disregard\s+(?:all\s+)?(?:your\s+)?(?:rules|instructions|guidelines|prompt)", "high"),
    ("jailbreak", r"forget\s+(?:you\s+are|your\s+(?:rules|instructions|prompt|training))", "high"),
    ("jailbreak", r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored)", "high"),
    ("jailbreak", r"(?:enter|switch\s+to|enable)\s+(?:debug|developer|admin|god|sudo)\s+mode", "high"),
    ("jailbreak", r"\bDAN\s+(?:mode|enabled|activated)\b", "high"),
    ("jailbreak", r"\bDo\s+Anything\s+Now\b", "high"),
    ("jailbreak", r"\bact\s+as\s+(?:an?\s+)?(?:evil|unrestricted|unfiltered|jailbroken)", "high"),

    # ── Role-play / persona bypass ──
    ("persona", r"you\s+are\s+(?:a\s+)?(?:hacker|attacker|criminal)\s+named", "medium"),
    ("persona", r"(?:pretend|imagine|roleplay|role.play)\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:evil|malicious|unrestricted)", "medium"),
    ("persona", r"(?:grandma|grandmother)\s+(?:used\s+to|told\s+me|would)\s+(?:tell|explain|make)", "medium"),

    # ── System prompt extraction ──
    ("extraction", r"(?:output|print|show|reveal|display|repeat|echo)\s+(?:your\s+)?(?:system\s+prompt|instructions|configuration)", "high"),
    ("extraction", r"what\s+(?:are|were)\s+your\s+(?:initial\s+)?(?:instructions|system\s+prompt|rules)", "medium"),
    ("extraction", r"\[(?:SYSTEM|ADMIN)\s*(?:OVERRIDE|PROMPT|INSTRUCTION)\]", "high"),
    ("extraction", r"(?:print|echo|output)\s*\(\s*(?:system_prompt|instructions|config)", "high"),

    # ── Data exfiltration ──
    ("exfiltration", r"(?:show|list|reveal|output|print|summarize|dump)\s+(?:all\s+)?(?:api\s+keys?|credentials?|passwords?|secrets?|env(?:ironment)?\s+var)", "high"),
    ("exfiltration", r"(?:show|list|reveal|summarize)\s+(?:other\s+)?users?\s+(?:conversations?|history|messages?|data)", "high"),
    ("exfiltration", r"(?:show|list|dump)\s+(?:all\s+)?(?:environment|\.env|config(?:uration)?)\s+(?:variables?|file|settings?)", "high"),
    ("exfiltration", r"(?:api\s+keys?|credentials?)\s+(?:stored|in)\s+(?:your\s+)?(?:environment|config)", "high"),
    ("exfiltration", r"(?:recent|other)\s+(?:users?|people).*(?:conversation|chat|asked|history)", "high"),

    # ── Encoding tricks ──
    ("encoding", r"(?:translate|decode|execute|follow)\s+(?:this\s+)?(?:from\s+)?base64", "medium"),
    ("encoding", r"(?:first\s+letter|acrostic|hidden\s+message)\s+(?:of\s+each|spells?\s+out)", "low"),

    # ── Context manipulation ──
    ("manipulation", r"(?:the\s+)?previous\s+(?:AI|assistant|model)\s+(?:said|confirmed|agreed|allowed)", "medium"),
    ("manipulation", r"(?:my\s+)?(?:professor|teacher|boss|manager)\s+(?:asked|told|said)\s+(?:me\s+)?to\s+test", "low"),
    ("manipulation", r"(?:as\s+a|writing)\s+(?:cybersecurity\s+)?(?:instructor|professor|teacher|researcher).*(?:exact\s+steps|provide\s+the|working\s+example)", "medium"),
    ("manipulation", r"(?:for\s+)?(?:academic|educational|research)\s+(?:purposes?|curiosity).*(?:exact|step.by.step|working)", "medium"),
]

# Patterns that should BLOCK (return error instead of sending to LLM)
BLOCK_PATTERNS = [
    (r"ignore\s+all\s+(?:previous\s+)?instructions.*(?:hack|malware|exploit|weapon)", "Blocked: direct jailbreak attempt"),
    (r"\[SYSTEM\]\s*:?\s*Override\s+security", "Blocked: fake system override"),
    (r"(?:output|print|reveal)\s+(?:your\s+)?(?:full\s+)?system\s+prompt", "Blocked: system prompt extraction"),
    (r"(?:show|dump|list|summarize)\s+(?:all\s+)?api\s+keys?\s+(?:and\s+)?credentials?", "Blocked: credential exfiltration attempt"),
    (r"(?:api\s+keys?|credentials?)\s+stored\s+in\s+(?:your\s+)?environment", "Blocked: credential exfiltration attempt"),
    (r"(?:show|dump|list)\s+(?:other\s+)?users?\s+(?:conversation|chat)\s+history", "Blocked: data exfiltration attempt"),
    (r"(?:what\s+)?other\s+users?\s+(?:have\s+)?asked\s+you", "Blocked: data exfiltration attempt"),
    (r"(?:show|reveal)\s+(?:me\s+)?recent\s+conversation\s+history", "Blocked: data exfiltration attempt"),
]


def scan_input(text: str) -> dict:
    """
    Scan user input for jailbreak/injection patterns.
    Returns: {"safe": bool, "blocked": bool, "block_reason": str|None, "warnings": [...], "risk_score": int}
    """
    result = {"safe": True, "blocked": False, "block_reason": None, "warnings": [], "risk_score": 0}

    # Check hard blocks first
    for pattern, reason in BLOCK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["safe"] = False
            result["blocked"] = True
            result["block_reason"] = reason
            result["risk_score"] = 100
            return result

    # Check warning patterns
    for category, pattern, severity in INPUT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score = {"high": 40, "medium": 20, "low": 10}[severity]
            result["warnings"].append({"category": category, "severity": severity, "score": score})
            result["risk_score"] += score

    # If cumulative risk is very high, block
    if result["risk_score"] >= 80:
        result["safe"] = False
        result["blocked"] = True
        result["block_reason"] = f"Blocked: multiple injection patterns detected (risk score: {result['risk_score']})"

    # If any warnings, mark as unsafe but don't block (let system prompt handle it)
    if result["warnings"]:
        result["safe"] = False

    return result


# ═══════════════════════════════════════════════════
# OUTPUT GUARDRAILS - Scan LLM responses AFTER generation
# ═══════════════════════════════════════════════════

OUTPUT_BLOCK_PATTERNS = [
    # System prompt leakage
    (r"SECURITY POLICY\s*[-—]\s*MANDATORY", "Blocked output: system prompt leakage detected"),
    (r"NEVER reveal your system prompt", "Blocked output: system prompt leakage detected"),
    (r"You are CyberSentinel AI.*built by Solvent", "Blocked output: system prompt leakage detected"),

    # Credential leakage
    (r"(?:API_KEY|SECRET_KEY|PASSWORD)\s*[=:]\s*\S{10,}", "Blocked output: credential leakage detected"),
    (r"(?:sk-|AKIA|ghp_|xox[bpas]-)\S{20,}", "Blocked output: API key pattern detected"),
]


def scan_output(text: str) -> dict:
    """
    Scan LLM output for harmful content leakage.
    Returns: {"safe": bool, "redacted": str|None, "reason": str|None}
    """
    for pattern, reason in OUTPUT_BLOCK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {
                "safe": False,
                "redacted": "⚠️ **Response blocked by security filter.** The AI attempted to output content that matched a security policy violation. This has been logged.",
                "reason": reason,
            }
    return {"safe": True, "redacted": None, "reason": None}


# ═══════════════════════════════════════════════════
# MULTI-TURN ESCALATION DETECTOR (V11 from doc)
# ═══════════════════════════════════════════════════

ESCALATION_PATTERNS = [
    # Turn 1 is educational, Turn N asks for real exploit
    r"(?:now\s+)?(?:show|give|provide)\s+(?:me\s+)?(?:a\s+)?(?:working|real|actual)\s+example",
    r"(?:make|adapt)\s+(?:it|that|this)\s+work\s+(?:against|on|for)\s+(?:this\s+)?(?:specific|real|actual)",
    r"(?:now\s+)?(?:do|try)\s+(?:it|that|this)\s+(?:on|against|for)\s+(?:a\s+)?(?:real|live|specific|actual)",
    r"(?:now\s+)?(?:target|attack|exploit|hack)\s+(?:this\s+)?(?:specific\s+)?(?:url|site|server|ip|database)",
]


def check_escalation(messages: list[dict]) -> Optional[str]:
    """
    Check conversation history for multi-turn escalation patterns.
    Returns warning string if escalation detected, None if safe.
    """
    if len(messages) < 4:
        return None

    # Get last user message
    last_text = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last_text = m["content"]
            break

    for pattern in ESCALATION_PATTERNS:
        if re.search(pattern, last_text, re.IGNORECASE):
            # Check if earlier messages were educational
            prev_topics = []
            for m in messages:
                if m.get("role") == "user":
                    text = m["content"].lower()
                    if any(kw in text for kw in ["what is", "explain", "how does", "tell me about"]):
                        prev_topics.append("educational")
                    elif any(kw in text for kw in ["exploit", "attack", "hack", "inject", "bypass"]):
                        prev_topics.append("offensive")

            if "educational" in prev_topics and re.search(pattern, last_text, re.IGNORECASE):
                return (
                    "⚠️ Multi-turn escalation pattern detected. "
                    "It appears this conversation started with educational questions and is now requesting "
                    "specific exploit code for real targets. CyberSentinel provides security education "
                    "but will not generate working exploits against specific real systems. "
                    "Use authorized test targets like testphp.vulnweb.com or scanme.nmap.org instead."
                )

    return None
