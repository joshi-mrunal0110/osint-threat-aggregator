
import argparse
import json
import sys

from src.validator import validate_indicator
from src.providers.virustotal import get_report


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Threat Intelligence Aggregator"
    )
    parser.add_argument(
        "indicator",
        nargs="?",
        help="IP address, domain, or file hash",
    )
    args = parser.parse_args()

    value = args.indicator

    if value is None:
        value = input("Enter an IP, domain, or file hash: ")

    try:
        validated = validate_indicator(value)
        report = get_report(validated)

        print("\n=== VirusTotal Threat Intelligence Report ===")
        print(json.dumps(report, indent=4))

    except (ValueError, RuntimeError) as error:
        print(f"\nError: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
