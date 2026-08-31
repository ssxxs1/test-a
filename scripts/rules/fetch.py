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


def fetch_source(source: SourceConfig, attempts: int = 3) -> bytes:
    url = source.url
    _validate_url(url, source)
    retryable_statuses = {429, 500, 502, 503, 504}
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            current = url
            for _ in range(4):
                _validate_url(current, source)
                response = requests.get(current, timeout=(10, 30), allow_redirects=False, stream=True, headers={"User-Agent": "test-a-rule-processor/1"})
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
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise FetchError(f"{source.source_id}: fetch failed after {attempts} attempts: {last_error}")
