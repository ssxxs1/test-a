from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse

import requests

from .models import SourceConfig


class FetchError(RuntimeError):
    pass


def _validate_url(url: str, source: SourceConfig) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname not in source.allowed_hosts:
        raise FetchError(f"{source.source_id}: URL outside allowed HTTPS hosts: {url}")


def _extract_repo_identity(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.hostname == "raw.githubusercontent.com":
        parts = parsed.path.strip("/").split("/")
        return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None
    if parsed.hostname == "cdn.jsdelivr.net":
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "gh":
            return f"{parts[1]}/{parts[2].split('@')[0]}"
    return None


def _candidate_urls(source: SourceConfig) -> list[str]:
    urls = [source.url]
    parsed = urlparse(source.url)
    if parsed.hostname == "raw.githubusercontent.com" and "cdn.jsdelivr.net" in source.allowed_hosts:
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 4:
            owner, repo, branch = parts[0], parts[1], parts[2]
            filepath = "/".join(parts[3:])
            query = f"?{parsed.query}" if parsed.query else ""
            urls.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{filepath}{query}")
    return urls


def fetch_source(source: SourceConfig, attempts: int = 3) -> bytes:
    urls = _candidate_urls(source)
    retryable_statuses = {429, 500, 502, 503, 504}
    last_error: Exception | None = None
    max_per_url = 2 if len(urls) > 1 else attempts
    for url in urls:
        _validate_url(url, source)
        origin_identity = _extract_repo_identity(url)
        for attempt in range(max_per_url):
            try:
                current = url
                for _ in range(4):
                    _validate_url(current, source)
                    if origin_identity:
                        curr_identity = _extract_repo_identity(current)
                        if curr_identity and curr_identity != origin_identity:
                            raise FetchError(f"{source.source_id}: redirect changes repo from {origin_identity} to {curr_identity}: {current}")
                    response = requests.get(current, timeout=(5, 20), allow_redirects=False, stream=True, headers={"User-Agent": "test-a-rule-processor/1"})
                    if response.is_redirect:
                        location = response.headers.get("Location")
                        if not location:
                            raise FetchError(f"{source.source_id}: redirect without Location")
                        current = urljoin(current, location)
                        continue
                    if response.status_code in retryable_statuses:
                        raise requests.HTTPError(f"retryable HTTP {response.status_code}")
                    response.raise_for_status()
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > source.max_bytes:
                            raise FetchError(f"{source.source_id}: response exceeds max_bytes")
                        chunks.append(chunk)
                    if not chunks:
                        raise FetchError(f"{source.source_id}: empty response")
                    return b"".join(chunks)
                raise FetchError(f"{source.source_id}: too many redirects")
            except (requests.RequestException, FetchError) as exc:
                last_error = exc
                if isinstance(exc, FetchError) and "outside allowed" in str(exc):
                    break
                if attempt + 1 < max_per_url:
                    time.sleep(1 + attempt)
    raise FetchError(f"{source.source_id}: fetch failed after trying {len(urls)} endpoint(s): {last_error}")
