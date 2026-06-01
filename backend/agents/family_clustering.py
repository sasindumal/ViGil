"""
ViGiL — Agent 9: Family Clustering Agent
Groups samples using HDBSCAN based on behavioral/structural embeddings.
"""
from __future__ import annotations

import numpy as np
from loguru import logger

from models import ClusteringResult


def run_family_clustering(
    similarity_matches: list[dict] = None,
    capabilities: list[str] = None,
) -> ClusteringResult:
    """
    In production: cluster against a corpus of known samples.
    Here, we infer cluster membership from similarity scores.
    """
    logger.info("[Clustering] Running family clustering analysis")

    if not similarity_matches:
        return ClusteringResult(
            cluster_id=None,
            cluster_label="unknown",
            related_samples=0,
            is_novel=True,
        )

    # Find best match
    top = max(similarity_matches, key=lambda x: x.get("similarity", 0))
    similarity = top.get("similarity", 0)
    family = top.get("family", "unknown")

    # Thresholds
    if similarity >= 0.85:
        return ClusteringResult(
            cluster_id=f"cluster_{family.lower().replace(' ', '_')}",
            cluster_label=family,
            related_samples=_estimate_related_samples(family),
            is_novel=False,
            nearest_family=family,
        )
    elif similarity >= 0.60:
        return ClusteringResult(
            cluster_id=f"cluster_similar_{family.lower().replace(' ', '_')}",
            cluster_label=f"Similar to {family}",
            related_samples=_estimate_related_samples(family) // 2,
            is_novel=False,
            nearest_family=family,
        )
    else:
        return ClusteringResult(
            cluster_id="cluster_novel_001",
            cluster_label="Novel / Unknown Family",
            related_samples=0,
            is_novel=True,
            nearest_family=family if similarity > 0.3 else None,
        )


def _estimate_related_samples(family: str) -> int:
    """Synthetic related sample counts for demo."""
    family_counts = {
        "RedLine": 2847,
        "Lumma": 1234,
        "AgentTesla": 4521,
        "AsyncRAT": 3102,
        "Emotet": 7823,
        "Cobalt Strike": 1567,
        "Ransomware_Generic": 892,
    }
    return family_counts.get(family, 42)
