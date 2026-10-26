"""Does the request text authorise deletion?

Two classifiers:
  * RuleIntent - multilingual keyword rules with explicit non-deletion / negation cues
                 (deterministic baseline, always available).
  * LLMIntent  - an LLM judgement (local Ollama model by default, Anthropic optional)
                 with a strict JSON answer. Results are cached on disk so reruns are
                 deterministic and free.

`IntentClassifier` combines them: the LLM is the primary judge when available and the
rule classifier is the fallback; disagreements are recorded for the evaluation report.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.request

DELETION_CUES = [
    r"\bdelet", r"\berase", r"\berasure", r"\bremove (my|the) (account|profile|personal)", r"\bclose (my|this|the) account",
    r"\bclosed my account", r"account[- ]deletion", r"\bpermanent(ly)? (delete|deletion|account)",
    r"\bwould like it closed", r"\bno longer need this account", r"\bremove my account",
    r"\bremove my profile", r"\bfinish the deletion", r"\bverify that my account was deleted",
    r"\bdeletion (as|was|is)", r"\bprofile is gone", r"\bdisconnected my account", r"\bremov(e|ed|ing)\b",
    r"\bclose (it|the account) (completely|permanently)", r"\baccount (itself )?is gone",
    r"eliminar", r"eliminación", r"exclusão", r"excluir", r"suppression", r"supprimer", r"削除", r"삭제",
    r"löschen", r"löschung", r"cancellare", r"verwijder",
]
NON_DELETION_CUES = [
    r"not asking for deletion", r"not a request to erase", r"do not close", r"don'?t delete", r"without removing",
    r"leave (the|my) (account|profile)", r"keep the account", r"continue using", r"marketing lists only",
    r"stop the promotional", r"reset(ting)? the login", r"send me a copy", r"\bcopy of (last|the information|my data)",
    r"download my account information",
    r"what personal information you hold", r"\bmisspelled\b", r"change the email address", r"out of date",
    r"leave the account active", r"\bstill (use|need|want)\b",
]


class RuleIntent:
    name = "rules"

    def classify(self, text: str) -> dict:
        t = (text or "").lower()
        neg = [c for c in NON_DELETION_CUES if re.search(c, t)]
        pos = [c for c in DELETION_CUES if re.search(c, t)]
        deletion = bool(pos) and not neg
        return {"deletion": deletion, "pos": pos, "neg": neg}


PROMPT = """You are a privacy-operations triage assistant for an online shop.
Decide whether the customer's message AUTHORISES deletion of their account / personal data.
- Requests to delete, erase, close the account permanently, or to verify / finish a deletion they asked for are deletion requests.
- Requests for access, a copy/export, correction, password reset, or marketing opt-out are NOT deletion, even if
  they mention deletion in a negated way ("not asking for deletion", "do not close").
The message may be in any language.
Reply with JSON only: {{"deletion": true|false, "request_type": "<deletion|access|export|correction|marketing_opt_out|account_support|other>"}}

Message:
\"\"\"{text}\"\"\""""


class LLMIntent:
    """LLM judge with a JSON contract. Provider is chosen by environment variables:

    INTENT_LLM=ollama (default) uses OLLAMA_MODEL (default qwen3:14b) at OLLAMA_URL;
    INTENT_LLM=anthropic uses ANTHROPIC_API_KEY and ANTHROPIC_MODEL;
    INTENT_LLM=off disables the LLM.
    """

    def __init__(self, cache_path: str, usage):
        self.provider = os.environ.get("INTENT_LLM", "ollama").lower()
        self.model = (os.environ.get("ANTHROPIC_MODEL", "claude-haiku-5-5") if self.provider == "anthropic"
                      else os.environ.get("OLLAMA_MODEL", "qwen3:14b"))
        self.url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
        self.name = f"{self.provider}:{self.model}"
        self.cache_path = cache_path
        self.usage = usage
        self.cache = json.load(open(cache_path, encoding="utf-8")) if os.path.exists(cache_path) else {}
        self.available = self.provider != "off" and self._probe()

    def _probe(self) -> bool:
        if self.provider == "anthropic":
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        try:
            with urllib.request.urlopen(self.url + "/api/tags", timeout=3) as r:
                tags = json.load(r)
            return any(m.get("name") == self.model for m in tags.get("models", []))
        except Exception:
            return False

    def _key(self, text: str) -> str:
        return hashlib.sha256(f"{self.name}|{PROMPT}|{text}".encode()).hexdigest()

    def classify(self, text: str) -> dict | None:
        key = self._key(text)
        if key in self.cache:
            hit = self.cache[key]
            self.usage.record(self.name, hit.get("in_tokens", 0), hit.get("out_tokens", 0), cached=True)
            return hit["result"]
        if not self.available:
            return None
        prompt = PROMPT.format(text=text)
        for attempt in range(3):
            try:
                raw, tin, tout = (self._anthropic(prompt) if self.provider == "anthropic" else self._ollama(prompt))
                result = json.loads(re.search(r"\{.*\}", raw, re.S).group(0))
                result = {"deletion": bool(result.get("deletion")), "request_type": result.get("request_type", "")}
                self.cache[key] = {"result": result, "in_tokens": tin, "out_tokens": tout}
                self.usage.record(self.name, tin, tout, cached=False)
                if len(self.cache) % 25 == 0:
                    self.save()  # checkpoint long runs
                return result
            except Exception as exc:  # pragma: no cover - network / parsing issues
                print(f"[intent] LLM attempt {attempt + 1} failed: {exc}", file=sys.stderr)
                time.sleep(1)
        return None

    def _ollama(self, prompt: str):
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False, "format": "json", "think": False,
                           "options": {"temperature": 0, "seed": 7, "num_predict": 60}}).encode()
        req = urllib.request.Request(self.url + "/api/generate", body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            d = json.load(r)
        return d.get("response", ""), d.get("prompt_eval_count", 0), d.get("eval_count", 0)

    def _anthropic(self, prompt: str):
        body = json.dumps({"model": self.model, "max_tokens": 60, "temperature": 0,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {
            "content-type": "application/json", "anthropic-version": "2023-06-01",
            "x-api-key": os.environ["ANTHROPIC_API_KEY"]})
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.load(r)
        return d["content"][0]["text"], d["usage"]["input_tokens"], d["usage"]["output_tokens"]

    def save(self):
        if self.cache:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            json.dump(self.cache, open(self.cache_path, "w", encoding="utf-8"), indent=1)


class IntentClassifier:
    def __init__(self, llm: LLMIntent | None):
        self.rules = RuleIntent()
        self.llm = llm
        self.memo: dict[str, dict] = {}
        self.disagreements: list[dict] = []

    def classify(self, req: dict) -> dict:
        text = req["request_text"]
        if text in self.memo:
            return self.memo[text]
        rule = self.rules.classify(text)
        llm = self.llm.classify(text) if self.llm else None
        if llm is None:
            out = {"deletion": rule["deletion"], "by": "rules", "rule": rule}
        else:
            out = {"deletion": llm["deletion"], "by": self.llm.name, "rule": rule, "llm": llm}
            if llm["deletion"] != rule["deletion"] and (rule["pos"] or rule["neg"]):
                # the rule classifier matched an explicit cue (e.g. "removed", "not asking for deletion");
                # an explicit cue outranks the model's holistic reading (see evaluation_report.md, case_25)
                out = {"deletion": rule["deletion"], "by": "rules (explicit cue overrides LLM)", "rule": rule,
                       "llm": llm}
            if llm["deletion"] != rule["deletion"]:
                self.disagreements.append({"case_id": req["case_id"], "text": text, "rule": rule["deletion"],
                                           "llm": llm["deletion"]})
        self.memo[text] = out
        return out

    def is_deletion(self, req: dict) -> bool:
        return self.classify(req)["deletion"]
