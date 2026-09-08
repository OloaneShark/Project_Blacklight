from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from blacklight_security.models import Finding, Severity


class LambdaScanner:
    """Deterministic AWS Lambda exposure checks."""

    def __init__(self, session: Any):
        self.lambda_client = session.client("lambda")

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        try:
            pages = self.lambda_client.get_paginator("list_functions").paginate()
            functions = [
                function
                for page in pages
                for function in page.get("Functions", [])
            ]
        except ClientError as error:
            return [self._error("aws-account", "aws.lambda.list_functions", error)]

        if not functions:
            return [
                self._finding(
                    "aws-account",
                    "aws.lambda.function_urls",
                    Severity.INFO,
                    "No Lambda functions were returned",
                    "There are no Lambda functions for Blacklight to evaluate in this region.",
                )
            ]

        for function in functions:
            name = function["FunctionName"]
            findings.append(self._check_function_url(name))

        return findings

    def _check_function_url(self, function_name: str) -> Finding:
        check_id = "aws.lambda.function_url_auth"
        try:
            config = self.lambda_client.get_function_url_config(FunctionName=function_name)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "Unknown")
            if code in {"ResourceNotFoundException", "ResourceNotFound"}:
                return self._finding(
                    function_name,
                    check_id,
                    Severity.PASS,
                    "Lambda function has no Function URL",
                    "No Lambda Function URL is configured for this function.",
                    evidence={"function_url_configured": False},
                )
            return self._error(function_name, check_id, error)

        auth_type = config.get("AuthType")
        function_url = config.get("FunctionUrl")
        if auth_type == "NONE":
            return self._finding(
                function_name,
                check_id,
                Severity.HIGH,
                "Lambda Function URL allows unauthenticated access",
                "The Lambda Function URL uses AuthType NONE and can receive requests without AWS IAM authentication.",
                "Require AWS_IAM authentication unless anonymous public access is explicitly intended and protected by application-level controls.",
                {"auth_type": auth_type, "function_url": function_url},
            )

        return self._finding(
            function_name,
            check_id,
            Severity.PASS,
            "Lambda Function URL requires AWS IAM authentication",
            "The Lambda Function URL uses AWS_IAM authentication.",
            evidence={"auth_type": auth_type, "function_url": function_url},
        )

    def _finding(
        self,
        resource_id: str,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            provider="aws",
            service="lambda",
            resource_type="aws_lambda_function",
            resource_id=resource_id,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
        )

    def _error(self, resource_id: str, check_id: str, error: ClientError) -> Finding:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        return self._finding(
            resource_id,
            check_id,
            Severity.ERROR,
            "Blacklight could not complete this Lambda check",
            f"AWS returned {code} while evaluating Lambda configuration.",
            "Verify the caller has the read permissions required for this check.",
            {"aws_error_code": code},
        )
