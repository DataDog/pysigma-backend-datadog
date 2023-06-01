# pylint: disable=too-many-lines
import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from dd_sigma.backends.datadog.datadog_backend import UnsupportedSyntax
# File for Review
# TODO: Remove once Datadog Backend is published in PySigma
import sys

sys.path.append(".")
from dd_sigma.backends.datadog import DatadogBackend

# from sigma.backends.datadog import DatadogBackend TODO: Reenable this line once our backend is published


def test_datadog_pipeline_aws_simple():
    assert (
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
            title: Basic Sigma Rule Test for AWS
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    eventSource: 'cloudtrail.amazonaws.com'
                    eventName: 'LookupEvents'
                condition: sel
        """
            )
        )
        == ["@eventSource:cloudtrail.amazonaws.com AND @eventName:LookupEvents"]
    )


def test_datadog_multiple_evt_names():
    assert (
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Multiple Event Names
                status: test
                logsource:
                    product: aws
                    service: cloudtrail
                detection:
                    sel:
                        eventSource: 's3.amazonaws.com'
                        eventName:
                            - 'PutBucketLogging'
                            - 'PutBucketWebsite'
                            - 'PutEncryptionConfiguration'
                    condition: sel
            """
            )
        )
        == [
            "@eventSource:s3.amazonaws.com AND (@eventName:PutBucketLogging OR @eventName:PutBucketWebsite OR @eventName:PutEncryptionConfiguration)"
        ]
    )


def test_datadog_unsupported_rule_type():
    with pytest.raises(
        SigmaTransformationError,
        match="Conversion for rule type not yet suppported by the Datadog Backend.",
    ):
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Rule type not supported
                status: test
                logsource:
                    product: windows
                    service: windows
                    category: windows # unsupported rule type
                detection:
                    sel:
                        field: anyfield
                    condition: sel
            """
            )
        )


# This test also accounts for less than operators not appearing in rules as the less than operator is used with aggregate functions.
# Since we can't use aggregate functions, we won't have anything to compare them with.
def test_datadog_pipeline_unsupported_aggregate_conditions_rule_type():
    with pytest.raises(
        SigmaTransformationError,
        match="The Datadog backend currently doesn't support rules with with aggregate function conditions like count, min, max, avg, sum, and near.",
    ):
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Aggregate Rules Not Supported
                status: test
                logsource:
                    product: aws
                    service: cloudtrail
                    category: any
                detection:
                    sel:
                        field: 'suspicious'
                    condition: sel | max() < 3
            """
            )
        )


def test_datadog_pipeline_multiple_filters():
    assert (
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
            title: Test Filters
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                selection:
                    eventName: 'CreateInstanceExportTask'
                    eventSource: 'ec2.amazonaws.com'
                filter1:
                    errorMessage|contains: '*'
                filter2:
                    errorCode|contains: '*'
                filter3:
                    responseElements|contains: 'Failure'
                condition: selection and not 1 of filter*
        """
            )
        )
        == [
            "@eventName:CreateInstanceExportTask AND @eventSource:ec2.amazonaws.com AND NOT (@errorMessage:* OR @errorCode:* OR @responseElements:*Failure*)"
        ]
    )


def test_datadog_pipeline_unsupported_regex():
    with pytest.raises(UnsupportedSyntax):
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Regex Not Supported
                status: test
                logsource:
                    product: aws
                    service: cloudtrail
                    category: any
                detection:
                    sel:
                        fieldA|re: maroon*
                    condition: sel
            """
            )
        )
