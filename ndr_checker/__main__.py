"""CLI entry point."""

import argparse
import logging
import sys
from pathlib import Path

from .config import load_targets
from .runner import run_all_targets
from .report import format_console_table, write_json_report, write_csv_report, print_summary
from .notify import send_webhook


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="NDR Console Health Checker - Check reachability of NDR consoles over HTTPS"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to YAML config file with targets",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Output directory for JSON/CSV reports (default: output)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers (default: 10)",
    )
    parser.add_argument(
        "--only-client",
        help="Only check targets for this client name",
    )
    parser.add_argument(
        "--tag",
        action="append",
        dest="tags",
        help="Only check targets with this tag (can be repeated)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    try:
        # Load config
        logger.info(f"Loading config from {args.config}")
        targets, defaults = load_targets(args.config)
        logger.info(f"Loaded {len(targets)} target(s)")

        # Run checks
        results, exit_code = run_all_targets(
            targets,
            workers=args.workers,
            retries=defaults.get("retries", 2),
            filter_client=args.only_client,
            filter_tags=args.tags,
        )

        # Print console table
        table = format_console_table(results)
        print(table)

        # Write reports
        write_json_report(results, args.output_dir)
        write_csv_report(results, args.output_dir)

        # Print summary
        print_summary(results)

        # Send webhook notification
        send_webhook(results)

        return exit_code

    except FileNotFoundError as e:
        logger.error(f"Config file not found: {e}")
        return 3
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 3
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
