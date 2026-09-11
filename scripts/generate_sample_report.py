"""Generate docs/sample-report.html from the bundled vulnerable test app.

The app binds to 127.0.0.1 only and contains purely fictional data, so the
sample report can be committed without leaking anything.

Usage: python scripts/generate_sample_report.py
"""

from __future__ import annotations

import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from vulnapp import make_server  # noqa: E402

from scanner.report import render_html  # noqa: E402
from scanner.scanner import ScanConfig, Scanner  # noqa: E402


def main() -> int:
    server = make_server()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/"

    config = ScanConfig(threads=4, timeout=5, allow_private=True, max_pages=20, depth=2)
    result = Scanner(config).run(url)

    out_path = os.path.join(ROOT, "docs", "sample-report.html")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(render_html(result))

    server.shutdown()
    server.server_close()
    print(f"Sample report written to {out_path} ({len(result.findings)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
