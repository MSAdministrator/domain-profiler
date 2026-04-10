"""Command-line interface."""

import fire

from domain_profiler.profiler import Profiler


def main() -> None:
    """Main entry point for the command line interface of domain-profiler project."""
    fire.Fire(Profiler)


if __name__ == "__main__":
    main()