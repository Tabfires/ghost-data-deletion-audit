# Usage Report — final full-dataset run

The run that produced `output.csv` was `python code/main.py`, covering 518 requests in
`dataset/deletion_requests.csv`.

## Where models are used

| Component | Provider / model | Calls | Notes |
| --- | --- | --- | --- |
| Request-intent judge (does the text authorise deletion?) | Ollama (local), `qwen3:14b` | 398 | One call per **unique** request text across test and sample requests. Sample requests are included because every visible request takes part in the workflow-burst allocation. Temperature 0, seed 7, JSON output, thinking disabled, max 60 output tokens. |
| Screenshot text | RapidOCR (ONNX, local) | 11 images | Not a language model, so no tokens. Results are cached. |
| PDF text | pypdf | 4 PDFs | Deterministic parser, no model. |

Everything else (extraction, identity resolution, state reconstruction, workflow allocation,
policy and planning) is deterministic Python with no model calls.

## Token usage (first, uncached execution of the full run)

| Model | Calls | Input tokens | Output tokens | Total tokens |
| --- | --- | --- | --- | --- |
| ollama:qwen3:14b | 398 | 80,837 | 5,968 | 86,805 |
| **Overall** | **398** | **80,837** | **5,968** | **86,805** |

Per request (518 requests in `deletion_requests.csv`):

* average input tokens per request: 156.1
* average output tokens per request: 11.5
* **average total tokens per request: 167.6**
* average per model call: 203.1 input, 15.0 output, 218.1 total

Wall time of the uncached run was 1,002 s, almost all of it local LLM inference on the
workstation. A cached rerun takes about 8 s: all 398 answers are served from
`.cache/intent_llm.json` and no new tokens are spent.

## Cost

| Model | Price (input / output per 1M tokens) | Total cost | Per request |
| --- | --- | --- | --- |
| ollama:qwen3:14b (local) | $0 / $0 (runs on own hardware) | **$0.00** | **$0.0000** |

For reference, the same token volume on the hosted option the code supports
(`INTENT_LLM=anthropic`, `claude-haiku-5-5` at $1 / $5 per 1M tokens) would cost about
80,837 × $1/1M + 5,968 × $5/1M ≈ **$0.11 in total, or $0.0002 per request**.

## Efficiency choices

* Each **unique** request text is judged once (398 calls for 550 visible requests).
* The prompt is short (about 200 tokens) and the output is tiny (a strict JSON object).
* There is a persistent on-disk cache, checkpointed every 25 calls, so interrupted runs resume and
  reruns are free.
* The model is used only where language understanding matters (multilingual intent, negations).
  Structured evidence is parsed deterministically and never sent to a model.
