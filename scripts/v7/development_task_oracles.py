"""Bounded functional-task Worker oracles. Never native semantics/authority.

The transcript auditor deliberately uses different algorithms, not this module.
"""
import heapq


def expected(kind, value):
    try:
        if kind == 'interval-union':
            if type(value) is not list or len(value) > 32:
                return None
            ranges = []
            for pair in value:
                if (type(pair) is not list or len(pair) != 2 or
                        any(type(n) is not int or not -100 <= n <= 100 for n in pair) or
                        pair[0] >= pair[1]):
                    return None
                ranges.append(pair[:])
            merged = []
            for lo, hi in sorted(ranges):
                if merged and lo <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            return {'intervals': merged, 'covered': sum(b-a for a, b in merged)}
        if kind == 'dependency-order':
            if type(value) is not dict or set(value) != {'nodes', 'edges'}:
                return None
            nodes, edges = value['nodes'], value['edges']
            if (type(nodes) is not list or len(nodes) > 7 or
                    any(type(n) is not str or not n for n in nodes) or
                    len(set(nodes)) != len(nodes) or type(edges) is not list):
                return None
            followers = {n: set() for n in nodes}; degree = dict.fromkeys(nodes, 0)
            for e in edges:
                if type(e) is not list or len(e) != 2 or any(type(n) is not str or n not in degree for n in e):
                    return None
                a, b = e
                if b in followers[a]:
                    return None
                followers[a].add(b); degree[b] += 1
            queue = [n for n in nodes if degree[n] == 0]; heapq.heapify(queue); order = []
            while queue:
                n = heapq.heappop(queue); order.append(n)
                for other in followers[n]:
                    degree[other] -= 1
                    if degree[other] == 0:
                        heapq.heappush(queue, other)
            return {'order': order} if len(order) == len(nodes) else None
        if kind == 'unicode-runs':
            if type(value) is not str or len(value) > 256:
                return None
            runs = []
            for char in value:
                if runs and runs[-1]['text'] == char:
                    runs[-1]['count'] += 1
                else:
                    runs.append({'text': char, 'count': 1})
            return {'runs': runs, 'length': len(value)}
    except (TypeError, ValueError):
        return None
    raise ValueError('unsupported functional task')
