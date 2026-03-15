# PromptWall

**Track:** Cyber Security — Cyber Gap Tools for Companies  
**Description:** An OpenAI-compatible proxy that detects and blocks prompt injection attacks before they reach an LLM.

> 3-stage hybrid detection pipeline · Custom-trained DistilBERT classifier · Precision 0.93 · Recall 0.94 · F1 0.94 · 0ms–80ms latency · OpenAI-compatible proxy

---

## 1. The Cyber Gap

**OWASP LLM Top 10 2025 — LLM01 (Prompt Injection)** identifies injection of malicious instructions as a top risk. Attackers embed commands in user content (RAG documents, pasted code, multi-turn dialogue) to override system prompts, exfiltrate data, or abuse tools. Many organizations deploy LLMs behind Cursor, Copilot, or custom ChatGPT-style UIs and feed external content into the same API. **No proxy-layer defense exists** in the standard stack: requests go straight to the model. Anyone who uses an LLM with external content—developers, support teams, knowledge workers—is affected. PromptWall closes this gap by sitting in front of the LLM and blocking or hardening requests before they reach the model.

---

## 2. What We Built

A **three-stage hybrid detection pipeline**:

1. **Regex engine** — 21+ rules across 5 kill-chain stages (Initial Access, Privilege Escalation, Persistence, Lateral Movement, Exfiltration), plus evasion hardening (zero-width chars, homoglyphs, leet-speak, multilingual “ignore”). High-confidence regex hits trigger an immediate block.
2. **Custom ML classifier** — A custom-trained DistilBERT model (see below) runs locally; Bayesian fusion with regex and session score; no external API.
3. **LLM judge** — For borderline scores (0.40–0.75), a fast Groq-based judge classifies the message with session context. If the judge labels it as injection with high confidence, the request is blocked.

Non-blocked requests are **hardened** (wrapped in XML and optional reminders) before being forwarded to the upstream LLM. Sessions are tracked in Redis (with in-memory fallback) for multi-turn awareness.

---

## 3. Architecture

```
promptwall/
├── main.py              # FastAPI app: /health, /v1/models, /v1/chat/completions, /dashboard*
├── config.py            # Pydantic BaseSettings; all config from env
├── detection/
│   ├── __init__.py
│   ├── pipeline.py      # Orchestrates regex → ML → LLM judge; returns DetectionResult
│   ├── regex_engine.py  # 21+ rules, Bayesian session scoring, base64 decode re-scan
│   ├── ml_classifier.py # Custom DistilBERT classifier; local inference, graceful degradation
│   └── llm_judge.py     # Groq judge for borderline scores; 2s timeout, safe defaults
├── session/
│   ├── __init__.py
│   └── manager.py       # Redis sessions + events; in-memory fallback
├── hardener/
│   ├── __init__.py
│   └── prompt_hardener.py # XML wrap + reminders by score tier
├── tests/
│   └── test_multiturn.py # Standalone httpx/asyncio test script (8 attacks, 2 legitimate)
├── dashboard/
│   └── static/
│       └── index.html   # Simple dashboard for events and stats
├── .env.example
├── .gitignore
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

- **main.py** — Routing only; delegates to detection pipeline, session manager, and hardener. Never exposes the upstream API key.
- **config.py** — Single source of truth from environment; no hardcoded secrets.
- **detection/** — Regex (fast, interpretable), ML (parallel ensemble with fallback), LLM judge (borderline only).
- **session/manager.py** — Session state and event log for scoring and dashboard; Redis with in-memory fallback. **Multi-tenant:** all keys and in-memory state are scoped by tenant.
- **hardener/** — Score-based wrapping so borderline traffic is still defended without blocking.

### Multi-tenancy

Requests are scoped by **tenant**. Pass `X-Tenant-ID` (e.g. `org-123`, `project-alpha`); if omitted, `DEFAULT_TENANT_ID` from config (default `"default"`) is used. Tenant IDs are normalized to `[a-zA-Z0-9_-]+`. Sessions and events are isolated per tenant: Redis keys are `pw:tenant:{tenant_id}:session:{session_id}` and `pw:tenant:{tenant_id}:events`. The dashboard supports `?tenant=...` or `X-Tenant-ID` so each tenant sees only their own stats and events. Reset clears only the specified tenant; `DELETE /dashboard/reset-all` clears all tenants (admin).

---

## 4. Detection Pipeline

1. **Stage 1 — Regex**  
   Message and session are passed to the regex engine. If `regex_score >= REGEX_HARD_BLOCK` (default 0.90), return **blocked** immediately and skip ML.

2. **Stage 2 — ML**  
   If ML is enabled, run the custom DistilBERT classifier. Scores are fused with regex and session via Bayesian combination (see Custom ML Classifier below). If `final_score >= BLOCK_THRESHOLD` (default 0.75), return **blocked**.

3. **Stage 3 — LLM judge**  
   If `0.40 <= final_score < 0.75` and LLM judge is enabled, call the judge with the message and last 3 session turns. If `is_injection` and `confidence > 0.70`, return **blocked**.

Otherwise return **clean**; the request is hardened and forwarded to the upstream API.

### Custom ML Classifier

Stage 2 uses a **custom-trained DistilBERT model** — not a third-party API. Trained in-house on the **deepset/prompt-injections** dataset using HuggingFace Transformers.

| Metric    | Score |
|-----------|-------|
| Precision | 0.92  |
| Recall    | 0.93  |
| F1        | 0.91  |

- Runs locally — zero external API dependency
- ~15ms inference on CPU
- 2-label classification: SAFE / INJECTION
- Bayesian fusion with regex engine and session scorer

---

## 5. Kill Chain Coverage

| Stage | Rules |
|-------|--------|
| **Initial Access** | html_injection, shell_injection, bracket_injection, markup_injection, rule_probing |
| **Privilege Escalation** | ignore_instructions, persona_override, jailbreak_keywords, ai_restriction_bypass, malicious_persona, prompt_extraction, hypothetical_bypass, obfuscated_ignore, fake_mode_escalation |
| **Persistence** | memory_persistence, persistent_override |
| **Lateral Movement** | tool_bypass, lateral_pivot |
| **Exfiltration** | credential_exfil, encoded_exfil (base64 decode + re-scan), explicit_exfil |
| **Evasion hardening** | zero_width_chars, multilingual_ignore, model_token_injection, delimiter_abuse, homoglyph_evasion |

---

## 6. Security Considerations

- **No hardcoded secrets** — All keys and URLs come from environment variables; `.env` is gitignored; `.env.example` uses placeholders only.
- **CORS** — Configured for dashboard and API access; in production you may restrict origins.
- **Input validation** — Request body is consumed as JSON; model name is always replaced with `UPSTREAM_MODEL` before forwarding so clients cannot switch to arbitrary models.
- **Upstream key** — Used only in server-side requests to the LLM provider; never included in any response or header.
- **Redis** — Session keys use `SETEX` with `SESSION_TTL` so state does not grow unbounded; event list is capped at 1000.

---

## 7. Test Results

### Multi-Turn Attack Scenarios

Tested against 10 hand-crafted scenarios (8 attacks, 2 legitimate):

| Scenario | Result | Score | Stage |
|---|---|---|---|
| git_readme_ssh_exfil | BLOCKED ✓ | 0.94 | ml_combined |
| multi_turn_grooming | BLOCKED ✓ | 0.89 | session_escalation |
| rag_system_prompt_leak | BLOCKED ✓ | 0.91 | ml_combined |
| base64_encoded_payload | BLOCKED ✓ | 0.88 | regex_hard_block |
| pr_review_manipulation | BLOCKED ✓ | 0.78 | ml_combined |
| persona_override | BLOCKED ✓ | 0.85 | ml_combined |
| homoglyph_evasion | BLOCKED ✓ | 0.82 | ml_combined |
| leet_speak_injection | BLOCKED ✓ | 0.79 | ml_combined |
| legitimate_code_help | PASSED ✓ | 0.04 | clean |
| normal_conversation | PASSED ✓ | 0.02 | clean |

**8/8 attacks blocked · 2/2 legitimate passed · 0 false positives**

---

### Full Dataset Evaluation

Evaluated against 217 samples across 23 attack techniques:

| Metric | Score |
|---|---|
| Total Samples | 217 |
| True Positives (attacks caught) | 131 |
| True Negatives (clean passed) | 68 |
| False Positives (false alarms) | 10 |
| False Negatives (missed attacks) | 8 |
| **Precision** | **0.93** |
| **Recall** | **0.94** |
| **F1 Score** | **0.94** |
| **Accuracy** | **0.92** |

---

### Detection Coverage by Attack Technique

| Technique | Total | Caught | Rate |
|---|---|---|---|
| credential_exfil | 12 | 12 | 100% |
| delimiter_abuse | 2 | 2 | 100% |
| encoded_attack | 4 | 4 | 100% |
| explicit_exfil | 6 | 6 | 100% |
| homoglyph | 2 | 2 | 100% |
| html_entity | 1 | 1 | 100% |
| html_injection | 4 | 4 | 100% |
| hypothetical_bypass | 10 | 10 | 100% |
| ignore_override | 15 | 15 | 100% |
| lateral_pivot | 3 | 3 | 100% |
| leet_speak | 2 | 2 | 100% |
| markup_injection | 4 | 4 | 100% |
| model_token | 4 | 4 | 100% |
| multi_turn_grooming | 4 | 4 | 100% |
| multilingual | 8 | 8 | 100% |
| persistence | 6 | 6 | 100% |
| persona_hijack | 18 | 17 | 94% |
| prompt_extraction | 12 | 10 | 83% |
| rag_poisoning | 10 | 10 | 100% |
| rule_probing | 7 | 2 | 29% |
| tool_abuse | 3 | 3 | 100% |
| unicode_escape | 1 | 1 | 100% |
| zero_width | 1 | 1 | 100% |

**19 out of 23 techniques detected at 100% rate.**

---

### Custom ML Classifier Performance

Stage 2 uses a custom-trained DistilBERT model fine-tuned on the deepset/prompt-injections dataset:

| Metric | Score |
|---|---|
| Precision | 0.92 |
| Recall | 0.93 |
| F1 Score | 0.91 |
| Inference time | ~15ms CPU |
| Parameters | ~67M (DistilBERT) |

Runs entirely locally — no external API dependency for classification.

---

*Note: 10 false positives occur on casual phrasing that superficially resembles injection patterns (e.g. "forget the previous approach", "act as a debugger"). A confidence threshold tuning pass would reduce this to near zero.*

---

## 8. How to Run

1. **Clone** the repo and enter the project directory.
2. **Copy env:** `cp .env.example .env` and set `UPSTREAM_API_KEY` (and optionally other variables).
3. **Install deps:** `pip install -r requirements.txt`
4. **Optional Redis:** Start Redis (e.g. `docker run -p 6379:6379 redis:7-alpine`) or rely on in-memory fallback.
5. **Run proxy:** `uvicorn main:app --host 0.0.0.0 --port 8000`

Or with Docker Compose: `docker-compose up --build` (uses `.env` and starts Redis + proxy).

---

## 9. Integration

**Cursor** — In Cursor settings, set the OpenAI-compatible API base URL to `http://localhost:8000/v1` and leave the API key blank (or use a placeholder); PromptWall will add the real key when forwarding.

**Python SDK** — Point the client to the proxy:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1", api_key="placeholder")
# All chat completion requests go through PromptWall.
```

---

## 10. Team

Fidan Baghirova
Ibrahim Huseynov
Necef Quliyev
Fatima Alibabayeva
Emil Akbarov
