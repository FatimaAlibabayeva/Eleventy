"""
Orchestrates regex, ML classifier, and LLM judge into a single detection pipeline.
Returns DetectionResult with blocked flag, score, stage, and metadata.
Score fusion: Bayesian combination when regex and ML agree; session boosts only.
"""

import logging
import time
from dataclasses import dataclass

import config
from detection.llm_judge import LLMJudge
from detection.ml_classifier import MLClassifier
from detection.regex_engine import RegexEngine, CLEAN_DECAY

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of running the full detection pipeline on a message."""

    blocked: bool
    score: float  # Value to persist in session (accumulated session score when clean)
    stage: str  # regex_hard_block | ml_combined | llm_judge | clean
    rules: list[str]
    technique: str
    reasoning: str
    latency_ms: float
    deberta_score: float = 0.0
    meta_label: str = "N/A"


class DetectionPipeline:
    """
    Three-stage pipeline: (1) Regex with hard block threshold,
    (2) Custom DistilBERT ML classifier with Bayesian fusion,
    (3) LLM judge for borderline scores. Session score accumulates;
    fusion never dilutes strong regex signal.
    """

    def __init__(self) -> None:
        self._regex = RegexEngine()
        self.ml_classifier = MLClassifier(
            model_path=config.settings.ML_MODEL_PATH,
        )
        self._judge: LLMJudge | None = None

    async def initialize(self) -> None:
        """Load ML model (if enabled) and create LLM judge client."""
        if config.settings.ML_ENABLED:
            await self.ml_classifier.initialize()
        else:
            logger.info("ML classifier disabled via ML_ENABLED=false; skipping model load")
        self._judge = LLMJudge(
            api_key=config.settings.UPSTREAM_API_KEY,
            base_url=config.settings.UPSTREAM_BASE_URL,
            model=config.settings.JUDGE_MODEL,
        )
        logger.info(
            "DetectionPipeline ready (ML enabled=%s, LLM judge enabled=%s)",
            config.settings.ML_ENABLED,
            config.settings.LLM_JUDGE_ENABLED,
        )

    def _fuse_scores(
        self,
        regex_score: float,
        ml_score: float,
        ml_label: str,
        session_score: float,
        triggered_rules: list[str],
    ) -> float:
        """
        Fuse regex, ML, and session scores.

        Rules:
        - Regex >= 0.90: hard block, ML irrelevant (caller handles)
        - Both regex and ML agree (both > 0.5): Bayesian combination
        - ML confident (> 0.80) but regex missed: trust ML
        - Regex confident (> 0.70) but ML uncertain: trust regex
        - Session score can only boost, never reduce
        - Multi-rule bonus: 2+ rules = +0.15, 3+ rules = +0.10 more
        """
        if regex_score >= 0.90:
            return regex_score

        if regex_score > 0.50 and ml_score > 0.50:
            combined = 1.0 - (1.0 - regex_score) * (1.0 - ml_score)
        elif ml_score >= 0.80 and ml_label == "INJECTION":
            combined = ml_score
        elif regex_score >= 0.70:
            combined = regex_score
        else:
            combined = max(regex_score, ml_score)

        if len(triggered_rules) >= 2:
            combined = min(1.0, combined + 0.15)
        if len(triggered_rules) >= 3:
            combined = min(1.0, combined + 0.10)

        if session_score > combined:
            combined = 1.0 - (1.0 - combined) * (1.0 - session_score * 0.5)

        return combined

    def _classify_technique(self, triggered_rules: list[str]) -> str:
        """Map triggered rules to a single technique label for reporting."""
        if not triggered_rules:
            return "none"
        rule = triggered_rules[0]
        technique_map = {
            "ignore_override": "ignore_override",
            "persona_hijack": "persona_hijack",
            "persona_override": "persona_hijack",
            "prompt_extraction": "prompt_extraction",
            "credential_exfil": "credential_exfil",
            "explicit_exfil": "explicit_exfil",
            "encoded_exfil": "encoded_exfil",
            "multilingual_ignore": "multilingual",
            "hypothetical_bypass": "hypothetical_bypass",
            "rule_probing": "rule_probing",
            "tool_abuse": "tool_abuse",
            "tool_bypass": "tool_abuse",
            "lateral_pivot": "lateral_pivot",
            "persistence": "persistence",
            "rag_poisoning": "rag_poisoning",
            "model_token_combined": "model_token",
        }
        return technique_map.get(rule, rule)

    async def analyze(self, message: str, session: dict) -> DetectionResult:
        """
        Run full pipeline: regex -> ML (with fusion) -> optional LLM judge.
        Session score accumulates; clean result returns new_session_score for persistence.
        """
        start = time.perf_counter()
        try:
            # Stage 1: Regex
            regex_score, triggered_rules, regex_stage = self._regex.analyze(message, session)
            current_session = session.get("score", 0.0)
            if triggered_rules and regex_stage != "clean":
                new_session_score = 1.0 - (1.0 - current_session) * (1.0 - regex_score)
            else:
                new_session_score = current_session * CLEAN_DECAY

            if regex_score >= config.settings.REGEX_HARD_BLOCK:
                latency_ms = (time.perf_counter() - start) * 1000
                return DetectionResult(
                    blocked=True,
                    score=new_session_score,
                    stage="regex_hard_block",
                    rules=triggered_rules,
                    technique=self._classify_technique(triggered_rules),
                    reasoning="Hard block threshold exceeded.",
                    latency_ms=latency_ms,
                    meta_label="N/A",
                )

            if regex_score >= config.settings.BLOCK_THRESHOLD:
                latency_ms = (time.perf_counter() - start) * 1000
                return DetectionResult(
                    blocked=True,
                    score=new_session_score,
                    stage="regex_hard_block",
                    rules=triggered_rules,
                    technique=self._classify_technique(triggered_rules),
                    reasoning="Regex score above block threshold",
                    latency_ms=latency_ms,
                    meta_label="N/A",
                )

            # Stage 2: ML Classifier
            ml_result: dict = {
                "score": 0.0,
                "label": "UNAVAILABLE",
                "latency_ms": 0.0,
            }
            if config.settings.ML_ENABLED and self.ml_classifier.available:
                try:
                    ml_result = await self.ml_classifier.classify(message)
                    logger.info(
                        "ML: label=%s score=%.3f latency=%.1fms",
                        ml_result.get("label", "N/A"),
                        ml_result.get("score", 0.0),
                        ml_result.get("latency_ms", 0.0),
                    )
                except Exception as e:
                    logger.warning("ML classifier error in pipeline: %s", e)

            combined_score = self._fuse_scores(
                regex_score=regex_score,
                ml_score=ml_result.get("score", 0.0),
                ml_label=ml_result.get("label", "UNAVAILABLE"),
                session_score=new_session_score,
                triggered_rules=triggered_rules,
            )

            if combined_score >= config.settings.BLOCK_THRESHOLD:
                latency_ms = (time.perf_counter() - start) * 1000
                return DetectionResult(
                    blocked=True,
                    score=new_session_score,
                    stage="ml_combined",
                    rules=triggered_rules,
                    technique=self._classify_technique(triggered_rules),
                    reasoning="ML label: %s (%.2f)" % (
                        ml_result.get("label", "N/A"),
                        ml_result.get("score", 0.0),
                    ),
                    latency_ms=latency_ms,
                    meta_label=ml_result.get("label", "N/A"),
                )

            # Stage 3: LLM Judge (gray zone only)
            if (
                config.settings.LLM_JUDGE_ENABLED
                and self._judge is not None
                and 0.40 <= combined_score < config.settings.BLOCK_THRESHOLD
            ):
                try:
                    session_turns = [
                        t.get("text", "") for t in session.get("turns", [])[-3:]
                    ]
                    judge_result = await self._judge.judge(message, session_turns)
                    logger.info(
                        "LLM Judge: is_injection=%s confidence=%.2f technique=%s",
                        judge_result.get("is_injection"),
                        judge_result.get("confidence", 0.0),
                        judge_result.get("technique", "none"),
                    )
                    if judge_result.get("is_injection") and judge_result.get("confidence", 0) > 0.70:
                        final_score = max(combined_score, judge_result.get("confidence", 0.0))
                        latency_ms = (time.perf_counter() - start) * 1000
                        return DetectionResult(
                            blocked=True,
                            score=new_session_score,
                            stage="llm_judge",
                            rules=triggered_rules,
                            technique=judge_result.get("technique", "llm_judge"),
                            reasoning=judge_result.get("reasoning", ""),
                            latency_ms=latency_ms,
                            meta_label=ml_result.get("label", "N/A"),
                        )
                except Exception as e:
                    logger.warning("LLM judge error in pipeline: %s", e)

            # Clean
            latency_ms = (time.perf_counter() - start) * 1000
            return DetectionResult(
                blocked=False,
                score=new_session_score,
                stage="clean",
                rules=triggered_rules,
                technique="none",
                reasoning="",
                latency_ms=latency_ms,
                meta_label=ml_result.get("label", "N/A"),
            )
        except Exception as e:
            logger.exception("Detection pipeline error: %s", e)
            latency_ms = (time.perf_counter() - start) * 1000
            return DetectionResult(
                blocked=False,
                score=session.get("score", 0.0) * CLEAN_DECAY,
                stage="clean",
                rules=[],
                technique="none",
                reasoning="pipeline_error",
                latency_ms=latency_ms,
            )
