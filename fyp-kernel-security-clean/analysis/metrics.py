"""
Shared helper: how good is a ranking at finding the known vulnerable functions?

A ranking is a dict {function node: score}; a higher score = check it earlier.

rank_of()        - position of one function (1 = top). Ties share the average
                   position, e.g. 3 functions tied for 2nd-4th place all get 3.
evaluate()       - for a set of CVEs, each with one or more vulnerable functions:
                     rank      of each CVE = rank of its BEST-ranked function
                               (a tester who checks any one of them finds the bug)
                     recall@K  share of CVEs found within the top K
                     MRR       mean reciprocal rank = average of 1/rank
                               (1.0 = always first, 0.5 = always second, ...)
                   A CVE whose functions are not in the ranking counts as not found.
behind_entry_points() - drop vulnerable functions that are seeds (non_seed scope)
load_ground_truth() - {cve_id: [function nodes]} and {cve_id: split}
"""

import json


def rank_of(scores, node, exclude=()):
    """Average-tie rank of `node` among all scored nodes not in `exclude`"""
    if node not in scores:
        return None
    mine = scores[node]
    higher = equal = 0
    for other, score in scores.items():
        if other in exclude and other != node:
            continue
        if score > mine:
            higher += 1
        elif score == mine:
            equal += 1   # includes the node itself
    return higher + (equal + 1) / 2


def evaluate(scores, cves, exclude=(), ks=(10, 20, 50, 100, 500)):
    """
    cves = {cve_id: [vulnerable function nodes]}.
    `exclude` = nodes left out of the ranking (e.g. seeds), never the targets.
    """
    targets = {node for nodes in cves.values() for node in nodes}
    exclude = set(exclude) - targets
    function_ranks = {node: rank_of(scores, node, exclude) for node in targets}
    ranks = {}
    for cve_id, nodes in cves.items():
        found = [function_ranks[n] for n in nodes if function_ranks[n] is not None]
        ranks[cve_id] = min(found) if found else None
    hits = [r for r in ranks.values() if r is not None]
    count = max(1, len(cves))
    return {
        "ranked_functions": len([n for n in scores if n not in exclude]),
        "ranks": ranks,
        "function_ranks": function_ranks,
        "recall": {k: sum(1 for r in hits if r <= k) / count for k in ks},
        "mrr": sum(1 / r for r in hits) / count,
        "median_rank": sorted(hits)[len(hits) // 2] if hits else None,
    }


def behind_entry_points(cves, seeds):
    """
    For the 'non_seed' scope: drop vulnerable functions that are themselves
    seeds (entry points). Returns (cves with their non-seed functions,
    list of CVEs whose functions are ALL seeds - they cannot be scored here).
    """
    kept, entry_only = {}, []
    for cve_id, nodes in cves.items():
        rest = [n for n in nodes if n not in seeds]
        if rest:
            kept[cve_id] = rest
        else:
            entry_only.append(cve_id)
    return kept, entry_only


def load_ground_truth(path, verified_only=True):
    """Return ({cve_id: [function nodes]}, {cve_id: split})"""
    with open(path, "r") as f:
        data = json.load(f)
    cves, splits = {}, {}
    for cve_id, cve in data.items():
        nodes = [vf["name"] for vf in cve["vulnerable_functions"]
                 if vf.get("verified") or not verified_only]
        if nodes:
            cves[cve_id] = nodes
            splits[cve_id] = cve.get("split", "test")
    return cves, splits
