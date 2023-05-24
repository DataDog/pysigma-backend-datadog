import pytest
from sigma.collection import SigmaCollection
# from sigma.backends.datadog import DatadogBackend

import sys
sys.path.append(".")

@pytest.mark.smoke
def test_always_passes():
    assert True

# @pytest.mark.smoke
# def test_always_fails():
#     assert False

from dd_sigma.backends.datadog import DatadogBackend
#
# @pytest.fixture
# def datadog_backend():
#     return DatadogBackend()
#
# # TODO: implement tests for some basic queries and their expected results.
# def test_datadog_and_expression(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA: valueA
#                     fieldB: valueB
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_or_expression(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel1:
#                     fieldA: valueA
#                 sel2:
#                     fieldB: valueB
#                 condition: 1 of sel*
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_and_or_expression(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA1
#                         - valueA2
#                     fieldB:
#                         - valueB1
#                         - valueB2
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_or_and_expression(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel1:
#                     fieldA: valueA1
#                     fieldB: valueB1
#                 sel2:
#                     fieldA: valueA2
#                     fieldB: valueB2
#                 condition: 1 of sel*
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_in_expression(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA:
#                         - valueA
#                         - valueB
#                         - valueC*
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_regex_query(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA|re: foo.*bar
#                     fieldB: foo
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_cidr_query(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field|cidr: 192.168.0.0/16
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']
#
# def test_datadog_field_name_with_whitespace(datadog_backend : DatadogBackend):
#     assert datadog_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field name: value
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']
#
# # TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# # implemented with custom code, deferred expressions etc.
#
#
#
# def test_datadog_format1_output(datadog_backend : DatadogBackend):
#     """Test for output format format1."""
#     # TODO: implement a test for the output format
#     pass
#
# def test_datadog_format2_output(datadog_backend : DatadogBackend):
#     """Test for output format format2."""
#     # TODO: implement a test for the output format
#     pass
#
#
