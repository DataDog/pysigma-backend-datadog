# pylint: disable=too-many-lines
import re
from sigma.processing.transformations import (
    ChangeLogsourceTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    RuleProcessingCondition,
    RuleProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaRule

import sigma
class AggregateRuleProcessingCondition(RuleProcessingCondition):
    def match(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join(
            [field.lower() for field in rule.detection.condition]
        )
        return any(field in condition_string for field in agg_function_strings)


class DatadogFieldMappingTransformation(FieldMappingTransformation):
    def get_mapping(self, field):
        """
        If a field is not mapped using a Datadog Field Transformation for OOTB facets, included an @ sign to indicate
        the field is a facet. Users should double check that facets output by the pySigma-datadog-facets match the ones
        in their environment. Because facets are arbitrary, users should manually review each facet output from pySigma
        queries.
        """
        mapping = self.mapping.get(field)
        if not mapping:
            return f"@{field}"
        else:
            return mapping


def datadog_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Generic Log Source to Datadog Query Syntax Transformation",
        allowed_backends=frozenset(),
        # The allowed_backends may need to change once our backend is supported in the Sigma library.
        # The allowed_backends field is the set of backends identifiers
        # (from the backends mapping) that are allowed to use this processing pipeline.
        # This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,
        items=[
            # Datadog Supported Logsources
            ProcessingItem(
                identifier=f"dd_mapping_to_cloudtrail",
                transformation=ChangeLogsourceTransformation(
                    product="aws",
                    service="cloudtrail",
                ),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="cloudtrail")
                ],
            ),
            ProcessingItem(
                identifier=f"dd_mapping_to_gcp",
                transformation=ChangeLogsourceTransformation(
                    product="gcp", service="gcp"
                ),
                rule_conditions=[
                    LogsourceCondition(product="gcp", service="gcp.audit")
                ],
            ),
            ProcessingItem(
                identifier=f"dd_mapping_to_azure",
                transformation=ChangeLogsourceTransformation(
                    product="azure", service="azure.*"
                ),
                rule_condition_linking=any,  # Override default AND  condition for rule_conditions to OR
                rule_conditions=[
                    LogsourceCondition(product="azure", service="auditlogs"),
                    LogsourceCondition(product="azure", service="signinlogs"),
                    LogsourceCondition(product="azure", service="azureactivity"),
                    LogsourceCondition(product="azure", service="activitylogs"),
                ],
            ),
        ]
        + [
            # Datadog's OOTB (out of the box) field mapping overrides for each cloud provider are listed in each
            # Processing Item below. Otherwise, all fields are mapped to "@{field} to accommodate DD query syntax.
            # Please check all field mappings to ensure consistency with your environment.
            # More details about Datadog Facets can be found here: https://docs.datadoghq.com/logs/explorer/facets/
            ProcessingItem(
                identifier="azure_field_mapping",
                transformation=DatadogFieldMappingTransformation(
                    {
                        # Azure field mapping overrides
                        "category": "@evt.category",
                        "operationName": "@evt.name",
                        "properties.result": "@evt.outcome",
                        "callerIpAddress": "@network.client.ip",
                        "identity.authorization.evidence.principalId": "@usr.id",
                        "ResultType": "@evt.outcome",
                        "resultType": "@evt.outcome",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="azure")],
            ),
            ProcessingItem(
                identifier="gcp_field_mapping",
                transformation=DatadogFieldMappingTransformation(
                    {
                        # GCP field mapping overrides
                        "data.httpRequest.remoteIp": "@network.client.ip",
                        "data.httpRequest.requestMethod": "@http.method",
                        "data.httpRequest.status": "@http.status_code",
                        "data.protoPayload.authenticationInfo.principalEmail": "@usr.email",
                        "data.protoPayload.status.code": "@evt.status_code",
                        "data.protoPayload.methodName": "@evt.name",
                        "data.protoPayload.requestMetadata.callerIp": "@network.client.ip",
                        "data.protoPayload.requestMetadata.callerSuppliedUserAgent": "@http.useragent",
                        "data.protoPayload.status.message": "@evt.outcome",
                        "data.severity": "@evt.outcome",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="gcp")],
            ),
            ProcessingItem(
                identifier="aws_field_mapping",
                transformation=DatadogFieldMappingTransformation(
                    {
                        # AWS field mapping overrides
                        "eventSource": "@evt.source",
                        "eventName": "@evt.name",
                        "requestID": "@http.request_id",
                        "sourceIPAddress": "@network.client.ip",
                        "src_endpoint.ip": "@network.client.ip",
                        "errorCode": "@error.kind",
                        "errorMessage": "@error.message",
                        "api.response.message": "@error.message",
                        "userAgent": "@http.useragent",
                        "http_request.user_agent": "@http.useragent",
                        "api.operation": "@evt.name",
                        "userIdentity.userName": "@usr.name",
                        "userIdentity.sessionContext.sessionIssuer.userName": "@userIdentity.assumed_role",
                        "recipientAccountId": "@account",
                        "aws_account": "@account",
                        "awsRegion": "@region",
                        "cloud.region": "@region",
                        "answer": "@answer",
                        "userIdentity": "@usr.identity",
                        "eventType": "@evt.type",
                        "userIdentity.arn": "@usr.identity.arn",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="cloudtrail")
                ],
            ),
            ProcessingItem(
                identifier="dd_fails_rule_type_not_supported",
                rule_condition_linking=any,  # Match if any conditions are true
                transformation=RuleFailureTransformation(
                    "Conversion for rule type not yet supported by the Datadog Backend."
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("dd_mapping_to_cloudtrail"),
                    RuleProcessingItemAppliedCondition("dd_mapping_to_gcp"),
                    RuleProcessingItemAppliedCondition("dd_mapping_to_azure"),
                ],
            ),
            ProcessingItem(
                identifier="dd_fails_rule_conditions_not_supported",
                transformation=RuleFailureTransformation(
                    "The Datadog backend currently doesn't support rules with with aggregate function conditions like "
                    "count, min, max, avg, sum, and near as they're deprecated in the Sigma Spec. For more information, "
                    "see: https://sigmahq.github.io/sigma-specification/Sigma_specification.html"
                ),
                rule_conditions=[AggregateRuleProcessingCondition()],
            ),
        ],
    )
