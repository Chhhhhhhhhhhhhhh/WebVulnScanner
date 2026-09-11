"""Entry point: ``python -m scanner -u https://example.com``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
