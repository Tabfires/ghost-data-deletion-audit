"""Loading of the tabular inputs and of the normalised evidence store."""
from __future__ import annotations

import csv
import re
import os
from collections import defaultdict
from dataclasses import dataclass, field

from .evidence import extract_file, load_manifest
from .media import extract_media_texts
from .model import Coverage, Observation


def read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@dataclass
class EvidenceStore:
    observations: list[Observation]
    coverage: list[Coverage]
    manifest: dict[str, dict]
    by_resource: dict[str, list[Observation]] = field(default_factory=dict)
    by_token: dict[str, set[str]] = field(default_factory=dict)

    def index(self):
        self.by_resource = defaultdict(list)
        self.by_token = defaultdict(set)
        for o in self.observations:
            self.by_resource[o.resource_id].append(o)
            for t in o.identifiers:
                self.by_token[t].add(o.resource_id)
        for lst in self.by_resource.values():
            lst.sort(key=lambda o: (o.observed_at, o.file_id))
        return self


def catalog_aliases(activity: list[dict]) -> dict[str, str]:
    """Data-catalog rows 'linked <resource> (<alias>) to ...' give the business name of a resource
    (statement number, file name, customer key) as it appears on documents and screens."""
    out = {}
    for a in activity:
        if a["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        m = re.search(r"\b" + re.escape(a["resource_id"]) + r" \(([^)]+)\)", a["details"])
        if m:
            out[m.group(1).strip()] = a["resource_id"]
    return out


def load_evidence(dataset_dir: str, cache_dir: str, aliases: dict[str, str] | None = None) -> EvidenceStore:
    manifest = load_manifest(dataset_dir)
    media = extract_media_texts(dataset_dir, manifest, os.path.join(cache_dir, "media_text.json"))
    obs, cov = [], []
    for row in manifest:
        o, c = extract_file(dataset_dir, row, media, aliases)
        obs += o
        cov += c
    store = EvidenceStore(obs, cov, {r["file_id"]: r for r in manifest}).index()
    store.media_text = media
    return store


@dataclass
class Dataset:
    requests: list[dict]
    identities: dict[str, dict]
    audit_log: list[dict]
    activity: list[dict]
    rules: list[dict]
    evidence: EvidenceStore
    media_text: dict[str, str] = field(default_factory=dict)


def load_dataset(dataset_dir: str, requests_file: str, cache_dir: str) -> Dataset:
    activity = read_csv(os.path.join(dataset_dir, "system_activity.csv"))
    return Dataset(
        requests=read_csv(requests_file),
        identities={r["user_id"]: r for r in read_csv(os.path.join(dataset_dir, "user_identities.csv"))},
        audit_log=read_csv(os.path.join(dataset_dir, "user_audit_log.csv")),
        activity=activity,
        rules=read_csv(os.path.join(dataset_dir, "deletion_rules.csv")),
        evidence=load_evidence(dataset_dir, cache_dir, catalog_aliases(activity)),
    )
