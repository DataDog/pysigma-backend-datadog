# pySigma Datadog Backend

![Tests](https://github.com/SigmaHQ/pySigma-backend-datadog/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/b4bb678c2533ee5dd3f4d06fa43198dc/raw/pySigma-backend-datadog.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## Overview
This repository contains the Datadog backend package (`sigma.backends.datadog`) for pySigma. This package contains the DatadogBackend class, which can be used to convert Sigma rules to Datadog rules and queries that will work with [Datadog’s Log Management](https://www.datadoghq.com/product/log-management/) and [Datadog's Cloud SIEM](https://www.datadoghq.com/product/cloud-siem/)  products.

Further, this repository also adds the `datadog_pipeline` as part of the sigma.pipelines.datadog package. This defines Datadog’s default log processing pipeline for Sigma rule conversion, which performs field mappings and contains error-handling logic.

## Output Format
**Disclaimer**: Users should **always** verify the output of the conversion tool to ensure rule and query accuracy before using in their environment.

The Datadog pySigma backend supports the following output format options:

- `default`: queries outputted using the Datadog Query Syntax to reflect a detection.
     - Note: Queries using the default output will only reflect the detection of the rule. Users may want to add the a log source to speed up the query slightly.

- `siem_rule`: Rule that are converted from the Sigma format to a Datadog format

The `siem-rule` output format will convert a rule in Sigma format to the Datadog Detection Rule format which will have a `default type: log_detection`, which indicates that the rule is a  security rule with a [threshold detection method](https://docs.datadoghq.com/security/cloud_siem/log_detection_rules/?tab=threshold#detection-methods) indicated by `detectionMethod: threshold` in the rule output.

Either output option can be used for log search, custom alerts, dashboards, and reporting.

## Supported Rule Types:
Currently, the Datadog pySigma backend supports logs from the following sources which are [cloud rules currently supported in the Sigma Rules Repository](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud). Log sources were chosen based on support for existing Sigma Rules which can be specified in the `logsource.service` field of a Sigma Rule. Please see this [ReadMe.md](https://github.com/SigmaHQ/sigma/tree/master#examples) from SigmaHQ for example rules.
- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)
- Azure Logs:
  - [Audit Logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins)
  - [Sign-in Logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins)
  -[ Azure Activity Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=powershell)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)

## Installation
1. Clone `pysigma-datadog-backend` repository
2. Clone the [Sigma Rules Repository](https://github.com/SigmaHQ/sigma) 
3. Create and activate a Python [virtual environment](https://docs.python.org/3/library/venv.html) using the following commands:
```
python3 -m venv .venv
. .venv/bin/activate
```
4. Run `pip install sigma-cli` and follow instructions in the [sigma-cli repository](https://github.com/SigmaHQ/sigma-cli)
5. Install the datadog backend `sigma plugin install datadog`
6. Using the `sigma-cli`, run the following command to convert a Sigma rule to a Datadog Cloud SIEM rule 
   `sigma convert -t datadog ../../andrea.piazza/sigma/sigma/rules/cloud/aws -f siem_rule`
7. Run this command to convert a Sigma rule into a Datadog Query `sigma convert -t datadog ../../{your.user}/sigma/sigma/rules/cloud/aws`
8. Use a text editor to view the **/scripts/local_pysigma_dd_conversion.py script** within the `pysigma-datadog-backend` repo. Modify the `sigma_rules_to_convert` list to indicate the rules that should be converted using the path in your file system to the Sigma Rules Repository cloned in Step 1.

As an example:

To convert [AWS Cloudtrail Disable Logging Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_cloudtrail_disable_logging.yml), [Azure Blocked Account Attempt Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_blocked_account_attempt.yml), and [GCP Bucket Enumeration Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gcp/gcp_bucket_enumeration.yml) to Datadog Rules locally, modify the `sigma_rules_to_convert` List using [this script](https://github.com/DataDog/pysigma-backend-datadog/tree/main/scripts) with the path from the [Sigma Rules Repository](https://github.com/SigmaHQ/sigma/tree/master/rules) cloned in step 2.
```agsl
sigma_rules_to_convert = [
  r"/Users/user.name/sigma/sigma/rules/cloud/aws/aws_cloudtrail_disable_logging.yml",
  r"/Users/user.name/sigma/sigma/rules/cloud/azure/azure_blocked_account_attempt.yml",
  r"/Users/user.name/sigma/sigma/rules/cloud/gcp/gcp_bucket_enumeration.yml"
]
```
6. Run the script with the command `python3 scripts/local_pysigma_dd_conversion.py` which will output either a Datadog query using the `default` output, or a Datadog Cloud SIEM detection rule using the `siem_rule` output.

## Importing Sigma Rules to Datadog:
The pipeline for the Datadog pySigma Backend converts fields from Sigma Rules into predefined [log facets](https://docs.datadoghq.com/logs/explorer/facets/).  The current field mappings can be found in each Processing Item for the corresponding log source in the [Datadog pySigma Pipeline](https://github.com/DataDog/pysigma-backend-datadog/blob/main/dd_sigma/pipelines/datadog/datadog_pipeline.py#L93).

If a field is not listed in the pipeline, the field will automatically be prefixed with an `@` sign and the detection engineer should update the field mappings in the query match what’s in their environment. This is also true for queries generated using the default output.

To check field mappings in the Datadog UI:
- Hover over “Logs” and click “Configuration”.
- Search for logsource that you're looking for field mappings
- Click the expand the arrow next to value in the “Pipeline Name” column

The “Remapper” rows define how fields from each log source gets mapped to Datadog facets.

To create a new Detection Rule from a converted Sigma rule, make  a `POST` request to `/api/v2/security_monitoring/rules` via the [Datadog API](https://docs.datadoghq.com/api/latest/security-monitoring/#create-a-detection-rule).

## Maintainers
- Datadog Cloud SIEM | Email: [team-cloudsiembackend@datadoghq.com]()

## Limitations
- The [Datadog Query Syntax](https://docs.datadoghq.com/tracing/trace_explorer/query_syntax/) does not currently support Sigma Rules that use [RegEx modifers](https://patzke.org/introducing-sigma-value-modifiers.html)

  - The following field on a Sigma Rule containing a modifier would throw an error using the Datadog Backend Conversion tool:
  ```agsl
    selection:
    field|re: "reg.*ex"
  ```
- We currently do not support importing Sigma rules using the Datadog UI.
