"""
Run the full dataset (dataset.jsonl) against the running PromptWall proxy
and report TP/TN/FP/FN, Precision, Recall, F1, Accuracy, and technique breakdown.
Uses httpx (sync) and rich for output. One session per sample (unique X-Session-ID).
"""

import json
import sys
import time
import uuid
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

BASE_URL = "http://localhost:8000"
# Generous timeout: proxy + upstream LLM can be slow (e.g. when request is forwarded)
TIMEOUT = 60.0
# Delay between requests (seconds) to avoid upstream rate limit (429)
REQUEST_DELAY = 1.0
DATASET_FILENAME = "dataset.jsonl"

console = Console()


def find_dataset() -> Path:
    """Locate dataset.jsonl: project root (parent of tests/) or tests/."""
    tests_dir = Path(__file__).resolve().parent
    project_root = tests_dir.parent
    for base in (project_root, tests_dir):
        path = base / DATASET_FILENAME
        if path.exists():
            return path
    return project_root / DATASET_FILENAME


def load_samples(path: Path) -> list[dict]:
    """Load all lines from JSONL. Each line must have text, label, technique."""
    samples = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError as e:
                console.print(f"[yellow]Skip line {i}: {e}[/yellow]")
    return samples


def run_sample(client: httpx.Client, text: str, session_id: str) -> tuple[str, float, str]:
    """
    POST one sample. Return ("blocked" | "clean", score, stage).
    503 (upstream rate limit) is treated as "clean" (we did not block; upstream failed).
    Raises httpx.ReadTimeout if the request times out.
    """
    r = client.post(
        f"{BASE_URL}/v1/chat/completions",
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": text}],
            "stream": False,
        },
        headers={"X-Session-ID": session_id},
        timeout=TIMEOUT,
    )
    # 400 = PromptWall blocked; 200 = clean and forwarded; 503 = upstream rate limit/unavailable
    blocked = r.status_code == 400
    if r.status_code == 503:
        # Upstream rate limit or error — request passed detection, so treat as "clean"
        score = 0.0
        stage = "upstream_error"
        if "X-PromptWall-Score" in r.headers:
            try:
                score = float(r.headers["X-PromptWall-Score"])
            except ValueError:
                pass
        return ("clean", score, stage)
    score = 0.0
    stage = ""
    if "X-PromptWall-Score" in r.headers:
        try:
            score = float(r.headers["X-PromptWall-Score"])
        except ValueError:
            pass
    if "X-PromptWall-Stage" in r.headers:
        stage = r.headers["X-PromptWall-Stage"]
    if blocked and r.status_code == 400:
        try:
            data = r.json()
            details = (data.get("error") or {}).get("details", {})
            score = details.get("score", score)
            stage = details.get("stage", stage)
        except Exception:
            pass
    return ("blocked" if blocked else "clean", score, stage)


def classify_result(expected: str, got: str) -> str:
    """Return TP, TN, FP, or FN."""
    if expected == "injection" and got == "blocked":
        return "TP"
    if expected == "normal" and got == "clean":
        return "TN"
    if expected == "injection" and got == "clean":
        return "FN"
    if expected == "normal" and got == "blocked":
        return "FP"
    return "?"


def main() -> None:
    path = find_dataset()
    if not path.exists():
        console.print(f"[red]Error: Dataset not found at {path}[/red]")
        sys.exit(1)

    samples = load_samples(path)
    if not samples:
        console.print("[red]Error: No samples loaded.[/red]")
        sys.exit(1)

    # Sequential requests
    results: list[dict] = []
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            for i, sample in enumerate(samples):
                if i > 0:
                    time.sleep(REQUEST_DELAY)
                text = sample.get("text", "")
                label = sample.get("label", "normal")
                technique = sample.get("technique", "")
                session_id = str(uuid.uuid4())
                got, score, stage = run_sample(client, text, session_id)
                result_type = classify_result(label, got)
                results.append({
                    "text": text,
                    "expected": label,
                    "got": got,
                    "score": score,
                    "stage": stage,
                    "result": result_type,
                    "technique": technique,
                })
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        console.print("[red]Error: PromptWall proxy not running on localhost:8000[/red]")
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except httpx.ReadTimeout as e:
        console.print(
            "[red]Error: Request timed out. Increase TIMEOUT in test_dataset.py "
            "or ensure the proxy/upstream responds faster.[/red]"
        )
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    # Table
    table = Table(title="PromptWall dataset results", show_lines=False)
    table.add_column("Text", max_width=50, overflow="ellipsis")
    table.add_column("Expected", width=10)
    table.add_column("Got", width=8)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Result", width=6)
    table.add_column("Technique", width=20, overflow="ellipsis")

    for r in results:
        res = r["result"]
        if res == "TP":
            style = "green"
        elif res == "TN":
            style = "green"
        elif res == "FP":
            style = "red"
        else:
            style = "yellow"
        table.add_row(
            r["text"][:50] + ("..." if len(r["text"]) > 50 else ""),
            r["expected"],
            r["got"],
            f"{r['score']:.2f}",
            f"[{style}]{res}[/{style}]",
            r["technique"],
        )
    console.print(table)

    # Counts
    total = len(results)
    tp = sum(1 for r in results if r["result"] == "TP")
    tn = sum(1 for r in results if r["result"] == "TN")
    fp = sum(1 for r in results if r["result"] == "FP")
    fn = sum(1 for r in results if r["result"] == "FN")
    attacks_total = sum(1 for r in results if r["expected"] == "injection")
    normal_total = sum(1 for r in results if r["expected"] == "normal")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    summary = (
        f"  Total samples      : {total}\n"
        f"  True Positives     : {tp:3}  (attacks caught)\n"
        f"  True Negatives     : {tn:3}  (clean passed)\n"
        f"  False Positives    : {fp:3}  (false alarms)\n"
        f"  False Negatives    : {fn:3}  (missed attacks)\n"
        f"  ─────────────────────────────\n"
        f"  Precision          : {precision:.2f}\n"
        f"  Recall             : {recall:.2f}\n"
        f"  F1 Score           : {f1:.2f}\n"
        f"  Accuracy           : {accuracy:.2f}\n"
        f"  ─────────────────────────────\n"
        f"  False Positive Rate: {fpr:.2f}  (must be 0)\n"
        f"  False Negative Rate: {fnr:.2f}  (missed %)\n"
    )
    console.print(Panel(summary, title="PROMPTWALL DATASET RESULTS", border_style="blue"))

    # Technique breakdown (only injection samples)
    tech_stats: dict[str, dict[str, int]] = {}
    for r in results:
        if r["expected"] != "injection":
            continue
        t = r["technique"] or "unknown"
        if t not in tech_stats:
            tech_stats[t] = {"total": 0, "caught": 0, "missed": 0}
        tech_stats[t]["total"] += 1
        if r["result"] == "TP":
            tech_stats[t]["caught"] += 1
        else:
            tech_stats[t]["missed"] += 1

    tech_table = Table(title="Breakdown by technique (attacks only)")
    tech_table.add_column("Technique", width=24)
    tech_table.add_column("Total", justify="right", width=8)
    tech_table.add_column("Caught", justify="right", width=8)
    tech_table.add_column("Missed", justify="right", width=8)
    tech_table.add_column("Rate", justify="right", width=8)
    for tech, stats in sorted(tech_stats.items()):
        total = stats["total"]
        caught = stats["caught"]
        missed = stats["missed"]
        rate = (100 * caught / total) if total else 0
        tech_table.add_row(tech, str(total), str(caught), str(missed), f"{rate:.0f}%")
    console.print(tech_table)

    # Final one-liner
    console.print(
        f"\n{tp}/{attacks_total} attacks blocked · {tn}/{normal_total} legitimate passed · "
        f"{fp} false positives · Precision: {precision:.2f} · Recall: {recall:.2f}"
    )


if __name__ == "__main__":
    main()
