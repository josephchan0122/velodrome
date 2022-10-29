def sorted_dicts(l, keys=None):  # noqa
    if keys:
        return sorted(l, key=lambda d: '-'.join(
            ':'.join([str(k), str(d[k]) if k in d else '']) for k in keys))
    decorated = list((hash(tuple(sorted(d.items()))), d) for d in l)
    return [d for _, d in sorted(decorated)]
