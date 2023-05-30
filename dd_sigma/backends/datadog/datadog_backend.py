# pylint: disable=too-many-lines
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend

from sigma.processing.pipeline import ProcessingPipeline
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression, SigmaRegularExpression

import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Optional, Any

# Todo: Remove once Datadog Pipeline is published
import sys
sys.path.append(".")

from dd_sigma.pipelines.datadog.datadog import datadog_aws_pipeline

# Empty class for unsupported syntax like RegEx which raises an exception
class UnsupportedSyntax(Exception):
    ...

class DatadogBackend(TextQueryBackend):
    """Generates a Datdog query using Datadog Query Syntax here:  https://docs.datadoghq.com/logs/explorer/search_syntax/"""
    name: ClassVar[str] = "Datadog Backend"
    formats: Dict[str, str] = {
        "default": "Datadog query syntax"
    }
    requires_pipeline : bool = True
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = datadog_aws_pipeline()
    # The backend generates grouping if required
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "-"
    eq_token : ClassVar[str] = ":"  # Token inserted between field and value (without separator)


    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.


    ## Values
    str_quote       : ClassVar[str] = ''      # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = '\\'    # Escaping character for special characters inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = ' + - = && || > < ! ( ) { } [ ] ^ “ ” ~ * ? : " '    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "{field}:{value}*"
    endswith_expression   : ClassVar[str] = "{field}:*{value}"
    contains_expression   : ClassVar[str] = "{field}:*{value}*"
    icontains_token: ClassVar[str] = "{field}:*{value}*"

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "({field})"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "- ({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field contains all (value list)"
    # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = ":"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    # and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = "OR "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}


    def convert_condition_field_eq_val_re(self, cond: SigmaRegularExpression, state : Any) -> None:
        """
        This function unconditionally raises an exception because Datadog's rule syntax does not support
        full regular expressions.
        In the future we can convert to the supported glob syntax in some cases.
        """
        raise UnsupportedSyntax("Regular expressions are not currently supported in Datadog's rule query format")

    def finalize_query_siem_rule(self, rule: SigmaRule, query: str,  index: int, state: ConversionState) -> Dict:
        """
        Generation of Datadog Cloud SIEM Detection Rules.

        For more details on Cloud SIEM Detection rules, see:
        https://docs.datadoghq.com/security/cloud_siem/log_detection_rules?tab=threshold
        For best practices for writing Datadog security rules see:
        https://www.datadoghq.com/blog/writing-datadog-security-detection-rules/
        """
        siem_rule = {
            "product": ["security_monitoring"],
            "name": f"SIGMA Threshold Detection - {rule.title}",
            "ruleId": str(rule.id),
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "source": f"{rule.logsource}",
            "queries": [
                {
                    "name": "",
                    "query": query,
                    "groupByFields": [],
                    "distinctFields": [],
                    "aggregation": ""
                }
            ],
            "options": {
                "detectionMethod": "threshold",
                "evaluationWindow": 300,
                "keepAlive": 3600,
                "maxSignalDuration": 7200
            },
            "cases": [
                {
                    "condition": "",
                    "name": "",
                    "status": str(rule.level.name).lower() if rule.level is not None else "low",
                    "notifications": []
                }
            ],
        }
        return siem_rule

    def finalize_output_siem_rule(self, queries: List[Dict]) -> Dict:
        return list(queries)
