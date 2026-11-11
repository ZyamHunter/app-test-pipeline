"""Allow ``python -m bridge`` to behave like the ``gh-bridge`` entry point."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
