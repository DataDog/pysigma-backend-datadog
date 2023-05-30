import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
# from sigma.backends.datadog import DatadogBackend

import sys

from dd_sigma.backends.datadog.datadog_backend import UnsupportedSyntax

sys.path.append(".")

from dd_sigma.backends.datadog import DatadogBackend
from dd_sigma.pipelines.datadog import datadog_aws_pipeline

def test_datadog_pipeline_aws_simple():
    assert DatadogBackend().convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ['@eventSource:cloudtrail.amazonaws.com AND @eventName:LookupEvents']


def test_datadog_multiple_evt_names():
    assert DatadogBackend().convert(
            SigmaCollection.from_yaml("""
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
            """)
        ) == ['@eventSource:s3.amazonaws.com AND (@eventName:PutBucketLogging OR @eventName:PutBucketWebsite OR @eventName:PutEncryptionConfiguration)']


def test_datadog_unsupported_rule_type():
    with pytest.raises(SigmaTransformationError, match="Conversion for rule type not yet suppported by the Datadog Backend."):
        DatadogBackend().convert(
            SigmaCollection.from_yaml("""
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
            """)
        )

def test_datadog_pipeline_unsupported_aggregate_conditions_rule_type():
    with pytest.raises(SigmaTransformationError, match="The Datadog backend currently doesn't support rules with with aggregate function conditions like count, min, max, avg, sum, and near."):
        DatadogBackend().convert(
            SigmaCollection.from_yaml("""
                title: Aggregate Rules Not Supported
                status: test
                logsource:
                    product: aws
                    service: cloudtrail
                    category: any
                detection:
                    sel:
                        field: maroon
                    condition: sel | max() = 10
            """)
        )



def test_datadog_pipeline_multiple_filters():
    assert DatadogBackend().convert(
        SigmaCollection.from_yaml("""
            title: Basic Sigma Rule Test for AWS
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
        """)
    ) == ['@eventName:CreateInstanceExportTask AND @eventSource:ec2.amazonaws.com AND @filter1:errorMessage\\|contains AND @filter2:errorCode\\|contains AND @filter3:responseElements\
\|contains AND - ()']

def test_datadog_pipeline_unsupported_regex():
    with pytest.raises(UnsupportedSyntax):
        DatadogBackend().convert(
            SigmaCollection.from_yaml("""
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
            """)
        )
