import pytest
from sigma.collection import SigmaCollection
# from sigma.backends.datadog import DatadogBackend

import sys

sys.path.append(".")

from dd_sigma.backends.datadog import DatadogBackend


@pytest.mark.smoke
def test_always_passes():
    assert True


@pytest.fixture
def datadog_backend():
    return DatadogBackend()


#
def test_datadog_and_expression(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['@fieldA:valueA AND @fieldB:valueB']


#
def test_datadog_or_expression(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['@fieldA:valueA OR @fieldB:valueB']


#
def test_datadog_and_or_expression(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['(@fieldA:valueA1 OR @fieldA:valueA2) AND (@fieldB:valueB1 OR @fieldB:valueB2)']


#
def test_datadog_or_and_expression(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['@fieldA:valueA1 AND @fieldB:valueB1 OR @fieldA:valueA2 AND @fieldB:valueB2']


#
def test_datadog_in_expression(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['@fieldA:valueA OR @fieldA:valueB OR @fieldA:valueC*']


def test_datadog_cidr_query(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Cidr Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['@field:192.168.*']


def test_datadog_field_name_with_whitespace(datadog_backend: DatadogBackend):
    assert datadog_backend.convert(
        SigmaCollection.from_yaml("""
            title: Blank Space Test
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['@field\\ name:value']  # double slash is escaping the escape


#
def test_datadog_siem_rule(datadog_backend: DatadogBackend):
    """Test for NDJSON output with embedded query string query."""
    rule = SigmaCollection.from_yaml("""
            title: Test
            id: c277adc0-f0c4-42e1-af9d-fab062992156
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    result = datadog_backend.convert(rule, output_format="siem_rule")
    assert result[0] == {'product': ['security_monitoring'], 'name': 'SIGMA Threshold Detection - Test', 'ruleId': 'c277adc0-f0c4-42e1-af9d-fab062992156', 'tags': [], 'source': "SigmaLogSource(category=None, product='aws', service='cloudtrail', source=None)", 'queries': [{'name': '', 'query': '@fieldA:valueA AND @fieldB:valueB', 'groupByFields': [], 'distinctFields': [], 'aggregation': ''}], 'options': {'detectionMethod': 'threshold', 'evaluationWindow': 300, 'keepAlive': 3600, 'maxSignalDuration': 7200}, 'cases': [{'condition': '', 'name': '', 'status': 'low', 'notifications': []}]}
