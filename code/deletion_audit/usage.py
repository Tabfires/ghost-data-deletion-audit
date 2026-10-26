"""Token usage / cost accounting for every model call made during a run."""
from __future__ import annotations

from collections import defaultdict

# USD per million tokens (input, output). Local models cost nothing per token.
PRICES = {
    "ollama": (0.0, 0.0),
    "anthropic:claude-haiku-5-5": (1.0, 5.0),
    "anthropic:claude-sonnet-5-5": (3.0, 15.0),
}


class Usage:
    def __init__(self):
        self.calls = defaultdict(lambda: {"calls": 0, "cached": 0, "in": 0, "out": 0})

    def record(self, model: str, tin: int, tout: int, cached: bool):
        c = self.calls[model]
        c["calls"] += 1
        c["cached"] += int(cached)
        c["in"] += tin or 0
        c["out"] += tout or 0

    @staticmethod
    def price(model: str) -> tuple[float, float]:
        if model.startswith("ollama"):
            return PRICES["ollama"]
        return PRICES.get(model, (0.0, 0.0))

    def summary(self) -> dict:
        out = {}
        for model, c in self.calls.items():
            pin, pout = self.price(model)
            out[model] = dict(c, cost=(c["in"] * pin + c["out"] * pout) / 1e6)
        return out
