"""
Shared helper: how good is a ranking at finding the known vulnerable functions?

A ranking is a dict {function node: score}; a higher score = check it earlier.

rank_of()   - position of one function (1 = top). Ties share the average
              position, e.g. 3 functions tied for 2nd-4th place all get 3.
evaluate()  - for a set of vulnerable functions:
                rank       of each vulnerable function
                recall@K   share of vulnerable functions in the top K
                MRR        mean reciprocal rank = average of 1/rank
                           (1.0 = always first, 0.5 = always second, ...)
"""


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


def evaluate(scores, targets, exclude=(), ks=(10, 20, 50, 100)):
    """
    Rank every target function and summarise.
    `exclude` = nodes left out of the ranking (e.g. seeds), never the targets.
    """
    exclude = set(exclude) - set(targets)
    ranks = {t: rank_of(scores, t, exclude) for t in targets}
    found = [r for r in ranks.values() if r is not None]
    total = len([n for n in scores if n not in exclude])
    return {
        "ranked_functions": total,
        "ranks": ranks,
        "recall": {k: sum(1 for r in found if r <= k) / len(targets) for k in ks},
        "mrr": sum(1 / r for r in found) / len(targets),
    }
