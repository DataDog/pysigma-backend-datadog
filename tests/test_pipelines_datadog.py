import pytest
from sigma.collection import SigmaCollection
# from sigma.backends.datadog import DatadogBackend

import sys
sys.path.append(".")

from dd_sigma.backends.datadog import DatadogBackend
from dd_sigma.pipelines.datadog import datadog_pipeline

# from sigma.pipelines.datadog import # TODO: import pipeline functions
# TODO: import tests for all implemented pipelines and contained transformations
def test_datadog_pipeline_simple():
    assert DatadogBackend().convert(
        SigmaCollection.from_yaml("""
            title: Basic Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    eventSource: 'cloudtrail.amazonaws.com'
                    eventName: 'LookupEvents'
                condition: sel
        """)
    ) == ['@eventSource:cloudtrail.amazonaws.com @eventName:LookupEvents']
