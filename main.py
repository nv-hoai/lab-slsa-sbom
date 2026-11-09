"""Small demo application used for the software supply-chain security lab.

The project is intentionally tiny: the point of the lab is the CI/CD
security pipeline (SBOM, Cosign, SLSA provenance), not the application
itself.
"""

from __future__ import annotations

import platform


def build_message(name: str = "Software Supply Chain") -> str:
    """Return a friendly greeting used by the web app and the CLI."""
    return f"Hello, {name}! Running on Python {platform.python_version()}."


def main() -> None:
    print(build_message())


if __name__ == "__main__":
    main()
