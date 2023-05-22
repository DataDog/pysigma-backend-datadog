# pylint: disable=too-many-lines
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import logsource_windows_network_connection,logsource_windows_network_connection_initiated, logsource_windows_process_creation, logsource_windows_dns_query

from sigma.rule import SigmaRule

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

dd_product_service_mapping = {
    "aws": "cloudtrail",
    "gcp": "auditlogs",
    "azure": "audit",
}


class DatadogFieldMappingTransformation(FieldMappingTransformation):
    def get_mapping(self, field):
        # if super(self).get_mapping() is None:
        #     return f"@{field}"
        mapping = self.mapping.get(field)
        if not mapping:
            return f"@{field}"

def datadog_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Generic Log Source to Datadog Query Syntax Transformation",
        allowed_backends=frozenset(),             # This needs to change to datadog once our backend is supported  ||Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"dd_mapping_product_{ product }_to_service_{ service }",
                transformation=ChangeLogsourceTransformation(product="dd", service=service),
                rule_conditions=[
                    LogsourceCondition(product=product, service=service)
                ],
            )
            for service, product in dd_product_service_mapping.items()

        ] + [
            ProcessingItem(     # Field mappings
                identifier="dd_aws_field_mapping",
                transformation=DatadogFieldMappingTransformation({
                    # overrides go here, otherwise fields are mapped to "@{field}"
                    "requestParameters": "requestParameters.attribute",
                })
            )
        ],
    )
