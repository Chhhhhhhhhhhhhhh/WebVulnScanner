"""Crawler parallelism: correctness (same result set) and speed."""

from __future__ import annotations

import threading
import time

import pytest

from scanner.crawler import crawl
from scanner.httpclient import HttpClient


@pytest.fixture()
def fresh_app():
    """Dedicated server so slow-page timings are not shared with other tests."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from vulnapp import make_server

    server = make_server()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/"
    server.shutdown()
    server.server_close()


def test_parallel_crawl_finds_same_pages(fresh_app):
    serial = crawl(HttpClient(allow_private=True, timeout=5), fresh_app,
                   max_pages=25, depth=2, threads=1, log=lambda *_: None)
    parallel = crawl(HttpClient(allow_private=True, timeout=5), fresh_app,
                     max_pages=25, depth=2, threads=4, log=lambda *_: None)
    serial_urls = {p.url for p in serial.pages}
    parallel_urls = {p.url for p in parallel.pages}
    assert serial_urls == parallel_urls
    assert len(parallel.param_urls) == len(serial.param_urls)
    assert {f.signature for f in parallel.forms} == {f.signature for f in serial.forms}
    assert parallel.entry is not None and parallel.entry.url == serial.entry.url


def test_parallel_crawl_is_faster_on_slow_pages(fresh_app):
    # /slow-hub links three pages that sleep 0.35s each; serial >= 1.05s,
    # parallel with 4 workers should land well below 0.8s for that layer
    hub = fresh_app + "slow-hub"
    serial_started = time.monotonic()
    crawl(HttpClient(allow_private=True, timeout=5), hub,
          max_pages=10, depth=1, threads=1, log=lambda *_: None)
    serial_elapsed = time.monotonic() - serial_started

    parallel_started = time.monotonic()
    crawl(HttpClient(allow_private=True, timeout=5), hub,
          max_pages=10, depth=1, threads=4, log=lambda *_: None)
    parallel_elapsed = time.monotonic() - parallel_started

    assert serial_elapsed >= 1.0          # sanity: the slow pages really ran
    assert parallel_elapsed < serial_elapsed * 0.8
