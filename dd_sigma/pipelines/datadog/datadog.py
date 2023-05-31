# pylint: disable=too-many-lines
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


class AggregateRuleProcessingCondition(RuleProcessingCondition):
    def match(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join(
            [field.lower() for field in rule.detection.condition]
        )
        return any(f in condition_string for f in agg_function_strings)


class DatadogFieldMappingTransformation(FieldMappingTransformation):
    def get_mapping(self, field):
        mapping = self.mapping.get(field)
        if not mapping:
            return f"@{field}"


def datadog_aws_pipeline() -> (
    ProcessingPipeline
):  # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Generic Log Source to Datadog Query Syntax Transformation",
        allowed_backends=frozenset(),  # This needs to change to datadog once our backend is supported  ||Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"dd_mapping_to_cloudtrail",
                transformation=ChangeLogsourceTransformation(
                    product="aws", service="cloudtrail"
                ),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="cloudtrail")
                ],
            )
        ]
        + [
            ProcessingItem(
                identifier="dd_aws_field_mapping",
                transformation=DatadogFieldMappingTransformation(
                    {
                        # Field Mapping overrides go here, otherwise fields are mapped to "@{field} to accommodate DD queries"
                        "requestParameters": "requestParameters.attribute",
                    }
                ),
            ),
            ProcessingItem(
                identifier="dd_fails_rule_type_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Conversion for rule type not yet suppported by the Datadog Backend."
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("dd_mapping_to_cloudtrail"),
                ],
            ),
            ProcessingItem(
                identifier="dd_fails_rule_conditions_not_supported",
                transformation=RuleFailureTransformation(
                    "The Datadog backend currently doesn't support rules with with aggregate function conditions like count, min, max, avg, sum, and near."
                ),
                rule_conditions=[AggregateRuleProcessingCondition()],
            ),
        ],
    )
