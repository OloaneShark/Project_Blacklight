from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from blacklight_security.registry import scanner_names, scanner_specs
from blacklight_security.reporting import render_console, render_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blacklight",
        description="Project Blacklight cloud security scanner",
    )
    parser.add_argument("--version", action="version", version="Project Blacklight 0.1.0a3")

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

    return parser


def _run_aws(args: argparse.Namespace) -> int:
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        findings = []
        for spec in scanner_specs("aws", args.service):
            findings.extend(spec.scanner_cls(session).scan())
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"Blacklight could not load AWS credentials: {error}", file=sys.stderr)
        return 2
    except (BotoCoreError, ClientError) as error:
        print(f"Blacklight could not complete the AWS scan: {error}", file=sys.stderr)
        return 2

    rendered = render_json(findings) if args.output_format == "json" else render_console(findings)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(rendered)

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
