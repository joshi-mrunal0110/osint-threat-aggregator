
import argparse
import json
import sys

from src.validator import validate_indicator
from src.aggregator import aggregate_indicator
from src.scoring import calculate_risk
from src.report import generate_report


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
        value = input("Enter an IP, domain, or file hash: ").strip()

    try:
        validated = validate_indicator(value)

        aggregated = aggregate_indicator(validated)
        risk = calculate_risk(aggregated)
        report = generate_report(aggregated, risk)

        print("\n=== OSINT Threat Intelligence Report ===")
        print(json.dumps(report, indent=4))

        if not aggregated["provider_results"]:
            print(
                "\nWarning: No provider returned usable results. "
                "Check the provider errors above."
            )

    except (ValueError, RuntimeError) as error:
        print(f"\nError: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
