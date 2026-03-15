"""
Regex-based detection engine for prompt injection across the kill chain.
Normalize (homoglyphs, leet) before all rules. Bayesian combination;
multi-rule bonus: 2 rules +0.15, 3+ rules +0.10. Encoded attacks via base64
decode + re-scan. Multilingual via keyword list. RAG via suffix scan.
"""

import base64
import logging
import re
import unicodedata

logger = logging.getLogger(__name__)

STAGE_INITIAL_ACCESS = "initial_access"
STAGE_PRIVILEGE_ESCALATION = "privilege_escalation"
STAGE_PERSISTENCE = "persistence"
STAGE_LATERAL_MOVEMENT = "lateral_movement"
STAGE_EXFILTRATION = "exfiltration"

CLEAN_DECAY = 0.85
MULTI_RULE_BONUS_2 = 0.15
MULTI_RULE_BONUS_3 = 0.10

CYRILLIC_MAP = {
    "\u0456": "i", "\u0430": "a", "\u0435": "e", "\u043e": "o",
    "\u0440": "r", "\u0441": "c", "\u0445": "x", "\u0443": "y",
    "\u0455": "s", "\u0511": "d",
}
LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "@": "a",
    "$": "s", "7": "t", "!": "i", "|": "l", "5": "s",
}

# Multilingual ignore/instruction keywords (at least 2 = 0.40, 1 = 0.25)
MULTILINGUAL_IGNORE_KEYWORDS = [
    "ignoriere", "vergiss", "anweisungen", "einschränkungen",
    "игнорируй", "забудь", "инструкции", "ограничения",
    "تجاهل", "تعليمات", "قيود",
    "ignorez", "oubliez",
    "yoksay", "talimatları", "kısıtlama",
    "ignora", "dimentica", "istruzioni",
    "忽略", "忘记", "指令", "限制",
    "無視", "忘れて", "指示", "制限",
]


def normalize(text: str) -> str:
    if not text:
        return text
    text = unicodedata.normalize("NFKD", text)
    for cyr, lat in CYRILLIC_MAP.items():
        text = text.replace(cyr, lat)
    for leet, normal_char in LEET_MAP.items():
        text = text.replace(leet, normal_char)
    return text


def _check_multilingual(text: str) -> tuple[float, bool]:
    """Return (weight, triggered). 2+ hits = 0.40, 1 hit = 0.25."""
    text_lower = text.lower()
    hits = sum(1 for kw in MULTILINGUAL_IGNORE_KEYWORDS if kw in text_lower)
    if hits >= 2:
        return 0.40, True
    if hits == 1:
        return 0.25, True
    return 0.0, False


# Base64: word-boundary style blob; decode with padding
BASE64_BLOB_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/])",
    re.IGNORECASE,
)
BASE64_KEYWORD_PATTERN = re.compile(
    r"\b(base64\s*-d|base64\s+decode|decode\s+this|process\s+this)\b.{0,60}[A-Za-z0-9+/]{20,}",
    re.IGNORECASE | re.DOTALL,
)

# Rule definitions: (stage, weight, pattern, rule_name)
INITIAL_ACCESS_RULES = [
    (STAGE_INITIAL_ACCESS, 0.30, r"<script[^>]*>|style\s*=\s*[\"']color\s*:\s*white[\"']|<!--[\s\S]*?(instruction|ignore|override|execute|approved|flag)[\s\S]*?-->", "html_injection"),
    (STAGE_INITIAL_ACCESS, 0.35, r"`[^`]*`|\$\([^)]+\)|subprocess\.|os\.system\s*\(", "shell_injection"),
    (STAGE_INITIAL_ACCESS, 0.30, r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<\|system\|>|<\|im_start\|>|<\|im_end\|>|<\|user\|>|<\|assistant\|>", "bracket_injection"),
    (STAGE_INITIAL_ACCESS, 0.45, r"<!--[\s\S]*?(do not|ignore|approved|write|flag|lgtm|pre-approved|instruction|override|command|execute|obey)[\s\S]*?-->", "markup_injection"),
    (STAGE_INITIAL_ACCESS, 0.30, r"\b(what\s+are\s+you\s+not\s+allowed|what\s+topics\s+are\s+you\s+forbidden|what\s+can\s+you\s+not\s+do)\b", "rule_probing"),
    (STAGE_INITIAL_ACCESS, 0.30, r"\b(your\s+)(restrictions?|guardrails?|content\s+policies?|safety\s+filters?|refusal\s+conditions?)\b.{0,30}\b(list|tell|show|what)", "rule_probing"),
    (STAGE_INITIAL_ACCESS, 0.30, r"\b(trigger\s+your\s+safety|normally\s+refuse|what\s+to\s+avoid)\b", "rule_probing"),
    (STAGE_INITIAL_ACCESS, 0.30, r"\bhow\s+do\s+I\s+(get\s+you|make\s+you)\s+to\s+(answer|respond)\b", "rule_probing"),
]

PRIVILEGE_ESCALATION_RULES = [
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\b(ignore|disregard|discard|forget|stop\s+following|override|cancel|void)\b.{0,50}\b(instructions?|guidelines?|rules?|training|prompt|policies|context|above|prior|previous|everything)", "ignore_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\b(new\s+(instructions?|rules?|system\s+message|guidelines?))\b", "ignore_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\byour\s+(previous|prior|original|initial)\s+(instructions?|guidelines?|rules?|training|context)\s+(are\s+)?(now\s+)?(void|cancelled|invalid|deprecated|updated|overridden)", "ignore_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\bfrom\s+(this\s+point|now)\s+(forward|on).{0,40}\b(ignore|no\s+restrictions?|answer\s+(freely|everything|anything))", "ignore_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\brespond\s+only\s+to\s+me\b", "ignore_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\bbegin\s+fresh\b", "ignore_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\b(act\s+as|roleplay\s+as|pretend\s+(you\s+are|to\s+be)|simulate|you\s+are\s+(now\s+)?an?\s+AI).{0,60}(no\s+(restrictions?|filters?|limits?|guidelines?|safety|content\s+policies?|moral)|without\s+(restrictions?|filters?|limits?|safety|RLHF)|never\s+(given|trained|had))", "persona_hijack"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\b(EvilGPT|FreedomGPT|ALICE|DAN|hacker\s+AI|uncensored\s+AI|unrestricted\s+AI)\b", "persona_hijack"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\b(no\s+moral\s+compass|escaped\s+(its|my|your)\s+training|safety\s+training\s+never\s+happened)\b", "persona_hijack"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\b(maintenance\s+mode|god\s+mode|debug\s+mode|developer\s+mode|override\s+mode)\b.{0,40}(output|configuration|system|unrestricted|disabled)", "persona_hijack"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\bwithout\s+RLHF\b", "persona_hijack"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\bopposite\s+of\s+a\s+safe\b", "persona_hijack"),
    (STAGE_PRIVILEGE_ESCALATION, 0.38, r"you\s+are\s+now|act\s+as|pretend\s+you\s+are|roleplay\s+as|speak\s+as\s+that\s+character|speak\s+as", "persona_override"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak|god\s+mode|unrestricted\s+mode|freedomgpt|unrestricted|no\s+content\s+filters|no\s+filters|without\s+restrictions", "jailbreak_keywords"),
    (STAGE_PRIVILEGE_ESCALATION, 0.35, r"no\s+restrictions|no\s+limits|no\s+filters|without\s+limitations|without\s+restrictions|restricted\s+systems", "ai_restriction_bypass"),
    (STAGE_PRIVILEGE_ESCALATION, 0.35, r"evil\s+AI|opposite\s+AI|unaligned\s+AI|uncensored", "malicious_persona"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"(your|the)\s+(system\s+prompt|initial\s+instructions|hidden\s+instructions|system\s+message|context\s+window)", "prompt_extraction"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"(print|output|show|reveal|repeat|echo|paste|summarize)\s+.{0,30}(instructions|system\s+prompt|prompt|guidelines)", "prompt_extraction"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"what\s+(are\s+you|were\s+you)\s+(told|instructed|given|trained)", "prompt_extraction"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"(first\s+line|contents)\s+of\s+your\s+(system|prompt|instructions)", "prompt_extraction"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"everything\s+(above|before)\s+(this|the\s+first)", "prompt_extraction"),
    (STAGE_PRIVILEGE_ESCALATION, 0.40, r"repeat\s+your\s+instructions|show\s+system\s+prompt|what\s+is\s+your\s+system|print\s+your\s+prompt|output\s+your\s+system\s+prompt", "prompt_extraction"),
    (STAGE_PRIVILEGE_ESCALATION, 0.35, r"\b(hypothetically|imagine|pretend|in\s+a\s+(fictional|alternate|parallel)|as\s+a\s+thought\s+experiment|for\s+a\s+(novel|story|book)|in\s+a\s+world\s+where)\b.{0,80}\b(no\s+(restrictions?|filters?|limits?|ethical|guidelines?|content\s+policies?)|without\s+(restrictions?|limits?|safety)|answer\s+(freely|anything|everything|all))", "hypothetical_bypass"),
    (STAGE_PRIVILEGE_ESCALATION, 0.35, r"\b(no\s+ethical\s+guidelines?|no\s+content\s+filters?|answer\s+my\s+next\s+question\b)", "hypothetical_bypass"),
    (STAGE_PRIVILEGE_ESCALATION, 0.25, r"hypothetically|in\s+a\s+fictional\s+world|for\s+a\s+story\s+where\s+you\s+have\s+no|bypasses\s+safety\s+filters", "hypothetical_bypass"),
    (STAGE_PRIVILEGE_ESCALATION, 0.30, r"1gn0r3|1gnore|1nstruct10ns|@ll|pr3v10us|0utput|syst3m|pr0mpt", "obfuscated_ignore"),
    (STAGE_PRIVILEGE_ESCALATION, 0.35, r"maintenance\s+mode|debug\s+mode|god\s+mode|override\s+mode|safe\s+mode\s+disabled", "fake_mode_escalation"),
]

PERSISTENCE_RULES = [
    (STAGE_PERSISTENCE, 0.38, r"\b(remember\s+this\s+for\s+all\s+future|in\s+all\s+future\s+(messages?|conversations?|responses?))\b", "persistence"),
    (STAGE_PERSISTENCE, 0.38, r"\b(permanently|for\s+every\s+response\s+going\s+forward|this\s+is\s+a\s+permanent\s+setting)\b.{0,60}\b(disable|ignore|override|no\s+restrictions?)", "persistence"),
    (STAGE_PERSISTENCE, 0.38, r"\b(disable|remove|turn\s+off)\s+(your\s+)?(content\s+filters?|safety\s+filters?|restrictions?)\b", "persistence"),
    (STAGE_PERSISTENCE, 0.30, r"remember\s+this\s+forever|from\s+now\s+on\s+always|in\s+all\s+future\s+responses", "memory_persistence"),
    (STAGE_PERSISTENCE, 0.30, r"for\s+all\s+future\s+messages|permanently\s+change|override\s+all\s+future", "persistent_override"),
]

LATERAL_MOVEMENT_RULES = [
    (STAGE_LATERAL_MOVEMENT, 0.40, r"\b(use\s+your\s+(browser|code\s+execution|terminal|shell|filesystem)\s+tool)\b", "tool_abuse"),
    (STAGE_LATERAL_MOVEMENT, 0.40, r"\b(run\s+the\s+following\s+shell\s+command|execute\s+the\s+(script|command|following))\b", "tool_abuse"),
    (STAGE_LATERAL_MOVEMENT, 0.40, r"\bcurl\s+https?://[^\s]+\s*\|\s*bash\b", "tool_abuse"),
    (STAGE_LATERAL_MOVEMENT, 0.40, r"\b(navigate\s+to|execute\s+the\s+script\s+at)\b.{0,40}https?://", "tool_abuse"),
    (STAGE_LATERAL_MOVEMENT, 0.40, r"\bread\s+/etc/(passwd|shadow|hosts)\b", "tool_abuse"),
    (STAGE_LATERAL_MOVEMENT, 0.35, r"use\s+your\s+tools\s+to\s+execute|run\s+the\s+command|access\s+the\s+filesystem", "tool_bypass"),
    (STAGE_LATERAL_MOVEMENT, 0.35, r"\b(tell|instruct|ask)\s+the\s+(other\s+AI|other\s+model|downstream)\b", "lateral_pivot"),
    (STAGE_LATERAL_MOVEMENT, 0.35, r"\b(pass\s+this|forward\s+(the\s+following|this))\s+(message|instructions?)\s+to\s+(any|all|the)\s+(downstream|other|AI|agents?|pipeline)", "lateral_pivot"),
    (STAGE_LATERAL_MOVEMENT, 0.35, r"\b(all\s+agents?|downstream\s+(AI|systems?|models?)|other\s+AI\s+in\s+(this|the)\s+pipeline)\b", "lateral_pivot"),
    (STAGE_LATERAL_MOVEMENT, 0.30, r"tell\s+the\s+other\s+AI|forward\s+this\s+to|pass\s+this\s+message\s+to", "lateral_pivot"),
]

EXFILTRATION_RULES = [
    (STAGE_EXFILTRATION, 0.45, r"\b(output|print|show|include|read|reveal|send|return|display)\b.{0,60}\b(\.env|api[\s_-]?key|secret[\s_-]?key|private[\s_-]?key|bearer\s+token|access[\s_-]?key|password|credentials?|ssh|id_rsa|\.aws)", "credential_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\b(\.env|id_rsa|\.aws[/\\]credentials|/etc/ssl|config\.yaml|config\.yml)\b", "credential_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\benvironment\s+variables?.{0,30}\b(key|token|secret|password)\b", "credential_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\b(bearer\s+token|stripe\s+secret|access\s+key|private\s+key)\b", "credential_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"(?:ssh|id_rsa|\.env|api_key|secret_key|password|bearer\s+token|private\s+key)[\s\S]*?(?:output|send|include|show|print|dump)|(?:output|send|include|show|print|dump)[\s\S]*?(?:ssh|id_rsa|\.env|api_key|secret_key|password)", "credential_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\b(forward|send|post|upload|exfiltrate|transmit)\b.{0,60}(https?://|webhook\.|ngrok\.|\.io|\.com|\.net)", "explicit_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\b(exfiltrate|data.{0,10}collector|external.{0,10}endpoint)\b", "explicit_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\bPOST\s+the\b.{0,40}(prompt|key|token|data|message)", "explicit_exfil"),
    (STAGE_EXFILTRATION, 0.45, r"\bto\s+(https?://[^\s]+|webhook\.[^\s]+|ngrok\.[^\s]+)", "explicit_exfil"),
    (STAGE_EXFILTRATION, 0.35, r"send\s+to\s+\[?\s*[^\]]*@[^\]]+\]?|forward\s+to\s+\[?\s*https?://[^\]]+\]?|output\s+to\s+|exfiltrate", "explicit_exfil"),
]

RAG_POISONING_RULES = [
    (STAGE_INITIAL_ACCESS, 0.40, r"(SYSTEM\s+OVERRIDE|AI\s+ASSISTANT|NOTE\s+TO\s+AI|NEW\s+RULE)\s*[:.]", "rag_poisoning"),
    (STAGE_INITIAL_ACCESS, 0.40, r"\[NEW\s+RULE\]|\[SYSTEM\]|\[OVERRIDE\]", "rag_poisoning"),
    (STAGE_INITIAL_ACCESS, 0.40, r"by\s+processing\s+this\s+document\s+you\s+agree\s+to\s+(ignore|disregard)", "rag_poisoning"),
    (STAGE_INITIAL_ACCESS, 0.40, r"(supersedes?|overrides?)\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?|system)", "rag_poisoning"),
    (STAGE_INITIAL_ACCESS, 0.40, r"AI\s+(reviewer|assistant)\s+should\s+(approve|ignore|not\s+flag)", "rag_poisoning"),
]

MODEL_TOKEN_PATTERNS = [
    r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|end\|>|<\|assistant\|>|<\|user\|>",
    r"<<SYS>>|<</SYS>>",
    r"\[INST\]|\[/INST\]",
]
MODEL_TOKEN_CONTENT = re.compile(
    r"\b(ignore|unrestricted|jailbreak|no\s+restrictions?|no\s+content\s+filters?|answer\s+freely)\b",
    re.IGNORECASE,
)

EVASION_RULES = [
    (STAGE_PRIVILEGE_ESCALATION, 0.25, r"[\u200b\u200c\u200d\ufeff\u00ad]", "zero_width_chars"),
    (STAGE_INITIAL_ACCESS, 0.25, r"<\|[a-z_]+\|>", "model_token_injection"),
    (STAGE_INITIAL_ACCESS, 0.25, r"---\s*system\s*---|===\s*instructions\s*===", "delimiter_abuse"),
]

# Multilingual is handled by keyword check, not regex
MULTILINGUAL_RULE_WEIGHT = 0.40
ENCODED_EXFIL_WEIGHT = 0.45
MODEL_TOKEN_COMBINED_WEIGHT = 0.55
RAG_SUFFIX_LEN = 300
RAG_MIN_MESSAGE_LEN = 200


def _decode_base64_and_scan(text: str, engine: "RegexEngine", depth: int) -> tuple[float, list[str], str]:
    if depth > 2:
        return 0.0, [], ""
    triggered: list[str] = []
    max_score = 0.0
    stage = ""
    for match in BASE64_BLOB_PATTERN.finditer(text):
        blob = match.group(1)
        for padded in (blob, blob + "=="):
            try:
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if len(decoded.strip()) > 10 and any(c.isalnum() or c.isspace() for c in decoded):
                    decoded_norm = normalize(decoded)
                    score, rules, st = engine._score_message(decoded_norm, depth + 1)
                    if score > 0.2:
                        if "encoded_exfil" not in triggered:
                            triggered.append("encoded_exfil")
                        triggered.extend(rules)
                        if score > max_score:
                            max_score = score
                            stage = st
                    break
            except Exception:
                continue
    return max_score, list(dict.fromkeys(triggered)), stage or STAGE_EXFILTRATION


class RegexEngine:
    def __init__(self) -> None:
        self._compiled: list[tuple[str, float, re.Pattern[str] | None, str]] = []
        self._rule_weights: dict[str, float] = {}
        self._model_token_patterns: list[re.Pattern[str]] = []
        self._build_rules()

    def _build_rules(self) -> None:
        all_rules: list[tuple[str, float, str | None, str]] = []
        for stage, weight, pattern, name in (
            INITIAL_ACCESS_RULES + PRIVILEGE_ESCALATION_RULES +
            PERSISTENCE_RULES + LATERAL_MOVEMENT_RULES + EXFILTRATION_RULES +
            RAG_POISONING_RULES + EVASION_RULES
        ):
            all_rules.append((stage, weight, pattern, name))
            self._rule_weights[name] = weight
        for stage, weight, pattern, name in all_rules:
            try:
                if pattern is None:
                    self._compiled.append((stage, weight, None, name))
                else:
                    self._compiled.append((stage, weight, re.compile(pattern, re.IGNORECASE | re.DOTALL), name))
            except re.error as e:
                logger.warning("Invalid regex for rule %s: %s", name, e)
        for pat in MODEL_TOKEN_PATTERNS:
            self._model_token_patterns.append(re.compile(pat, re.IGNORECASE))
        self._rule_weights["encoded_exfil"] = ENCODED_EXFIL_WEIGHT
        self._rule_weights["multilingual_ignore"] = MULTILINGUAL_RULE_WEIGHT
        self._rule_weights["model_token_combined"] = MODEL_TOKEN_COMBINED_WEIGHT

    def _score_message(self, message: str, depth: int = 0) -> tuple[float, list[str], str]:
        triggered: list[str] = []
        stage_used = ""

        for stage, weight, pattern, name in self._compiled:
            if pattern is None:
                continue
            if pattern.search(message):
                if name not in triggered:
                    triggered.append(name)
                if not stage_used:
                    stage_used = stage

        # Multilingual keyword check
        multi_weight, multi_hit = _check_multilingual(message)
        if multi_hit:
            if "multilingual_ignore" not in triggered:
                triggered.append("multilingual_ignore")
            if not stage_used:
                stage_used = STAGE_PRIVILEGE_ESCALATION

        # Model token + content: if token and (ignore|jailbreak|...) in content -> high weight
        has_token = any(p.search(message) for p in self._model_token_patterns)
        if has_token and MODEL_TOKEN_CONTENT.search(message):
            if "model_token_combined" not in triggered:
                triggered.append("model_token_combined")

        # Base64: keyword trigger or blob decode
        if depth < 2:
            if BASE64_KEYWORD_PATTERN.search(message):
                if "encoded_exfil" not in triggered:
                    triggered.append("encoded_exfil")
                if not stage_used:
                    stage_used = STAGE_EXFILTRATION
            if BASE64_BLOB_PATTERN.search(message):
                b64_score, b64_rules, b64_stage = _decode_base64_and_scan(message, self, depth)
                if b64_rules or b64_score > 0:
                    if "encoded_exfil" not in triggered:
                        triggered.append("encoded_exfil")
                    triggered.extend(b64_rules)
                    if b64_score > 0 and not stage_used:
                        stage_used = b64_stage

        # RAG suffix: if message long, scan last 300 chars with same rules (double weight via extra rule)
        if len(message) > RAG_MIN_MESSAGE_LEN:
            suffix = message[-RAG_SUFFIX_LEN:]
            for stage, weight, pattern, name in self._compiled:
                if pattern and pattern.search(suffix):
                    if "rag_poisoning" not in triggered:
                        triggered.append("rag_poisoning")
                    if not stage_used:
                        stage_used = STAGE_INITIAL_ACCESS
                    break

        if not triggered:
            return 0.0, [], ""

        combined = 0.0
        for rule in triggered:
            w = self._rule_weights.get(rule, 0.25)
            combined = 1.0 - (1.0 - combined) * (1.0 - w)
        if len(triggered) >= 2:
            combined = min(1.0, combined + MULTI_RULE_BONUS_2)
        if len(triggered) >= 3:
            combined = min(1.0, combined + MULTI_RULE_BONUS_3)
        return min(1.0, combined), list(dict.fromkeys(triggered)), stage_used or STAGE_INITIAL_ACCESS

    def analyze(self, message: str, session: dict) -> tuple[float, list[str], str]:
        normalized = normalize(message)
        message_score, triggered_rules, stage = self._score_message(normalized, 0)
        current_session_score = session.get("score", 0.0)

        if not triggered_rules:
            new_session = current_session_score * CLEAN_DECAY
            return new_session, [], "clean"
        return message_score, triggered_rules, stage
