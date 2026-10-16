#!/usr/bin/env python3
"""Reclaim only cache entries scoped to independently confirmed closed PRs."""

import argparse
import json
import os
import re
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self, repo, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("Invalid repository")
        self.repo = repo
        self.token = token

    def request(self, path, method="GET"):
        request = urllib.request.Request(
            f"https://api.github.com/repos/{self.repo}/" + path,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.build_opener(NoRedirects()).open(request, timeout=15) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("API response too large")
        return json.loads(raw) if raw else None


def candidates(api):
    caches = []
    for page in range(1, 11):
        rows = api.request(f"actions/caches?per_page=100&page={page}")["actions_caches"]
        caches.extend(rows)
        if len(rows) < 100:
            break
    else:
        raise ValueError("Cache inventory exceeds bounded scan; no deletions planned")
    closed = {}
    eligible = []
    for cache in caches:
        match = re.fullmatch(r"refs/pull/([1-9][0-9]*)/(?:merge|head)", cache["ref"])
        if not match:
            continue
        number = int(match[1])
        if number not in closed:
            closed[number] = api.request(f"pulls/{number}")["state"] == "closed"
        if closed[number]:
            cache_id = cache["id"]
            if not isinstance(cache_id, int) or isinstance(cache_id, bool) or cache_id < 1:
                raise ValueError("Invalid immutable cache ID")
            size = cache["size_in_bytes"]
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ValueError("Invalid cache size")
            eligible.append((cache_id, number, size))
    return sorted(eligible)


def cleanup(api, apply=False, limit=20):
    selected = candidates(api)[:limit]
    deleted = 0
    if apply:
        for cache_id, number, _ in selected:
            # Do not rely only on the earlier inventory if a PR was reopened.
            if api.request(f"pulls/{number}")["state"] != "closed":
                continue
            api.request(f"actions/caches/{cache_id}", method="DELETE")
            deleted += 1
    return {
        "eligible_in_batch": len(selected),
        "bytes_in_batch": sum(row[2] for row in selected),
        "deleted": deleted,
        "mode": "apply" if apply else "dry-run",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    api = Api(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
    print(json.dumps(cleanup(api, args.apply), sort_keys=True))


if __name__ == "__main__":
    main()
