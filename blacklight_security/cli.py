from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from blacklight_security import __version__
from blacklight_security.policy import evaluate_policy
from blacklight_security.registry import scanner_names
from blacklight_security.reporting import render_console, render_json
from blacklight_security.runner import ScanRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blacklight",
        description="Project Blacklight cloud security scanner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Project Blacklight {__version__}",
    )

    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Run deterministic security checks")
    providers = scan.add_subparsers(dest="provider", required=True)

    aws = providers.add_parser("aws", help="Scan AWS resources")
    aws.add_argument(
        "--service",
        choices=["all", *scanner_names("aws")],
        default="all",
        help="AWS service to scan (default: all)",
    )
    aws.add_argument("--profile", help="AWS shared-credentials profile name")
    aws.add_argument("--region", help="AWS region override")
    aws.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        dest="output_format",
    )
    aws.add_argument("--output", type=Path, help="Write the rendered report to a file")
    aws.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 1 when a finding at or above this severity is detected",
    )

    return parser


def _run_aws(args: argparse.Namespace) -> int:
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        result = ScanRunner("aws", session).run(args.service)
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"Blacklight could not load AWS credentials: {error}", file=sys.stderr)
        return 2
    except (BotoCoreError, ClientError) as error:
        print(f"Blacklight could not complete the AWS scan: {error}", file=sys.stderr)
        return 2

    policy = evaluate_policy(result.findings, args.fail_on)
    rendered = (
        render_json(result, policy)
        if args.output_format == "json"
        else render_console(result, policy)
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(rendered)

    if policy.enabled and not policy.passed:
        print(
            f"Blacklight security gate failed: {policy.triggered_count} finding(s) "
            f"at {policy.fail_on} severity or above.",
            file=sys.stderr,
        )
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan" and args.provider == "aws":
        return _run_aws(args)

    parser.error("Unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
