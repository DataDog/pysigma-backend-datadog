# pylint: disable=too-many-lines
import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError, SigmaFeatureNotSupportedByBackendError


from sigma.backends.datadog import DatadogBackend

def test_aws_field_transformations():
    assert (
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Datadog AWS Field Transformation Test
                status: test
                logsource:
                    product: aws
                    service: cloudtrail
                detection:
                    sel:
                        eventSource: "test"
                        eventName: "test"
                        requestID: "test"
                        sourceIPAddress: "test"
                        src_endpoint: "test"
                        errorCode: "test"
                        errorMessage: "test"
                        apiresponse: "test"
                        userAgent: "test"
                        http_request: "test"
                        apioperation: "test"
                        userIdentityuserName: "test"
                        userIdentity.sessionContext.sessionIssuer.userName: "test"
                        recipientAccountId: "test"
                        aws_account: "test"
                        awsRegion: "test"
                        cloudregion: "test"
                        answer: "test"
                        userIdentity: "test"
                        eventType: "test"
                        userIdentityarn: "test"
                    condition: sel
            """
            )
        )
        == [
            "@evt.source:test AND @evt.name:test AND @http.request_id:test AND @network.client.ip:test AND @src_endpoint:test AND @error.kind:test AND @error.message:test AND @apiresponse:test AND @http.useragent:test AND @http_request:test AND @apioperation:test AND @userIdentityuserName:test AND @userIdentity.assumed_role:test AND @account:test AND @account:test AND @region:test AND @cloudregion:test AND @answer:test AND @usr.identity:test AND @evt.type:test AND @userIdentityarn:test"
        ]
    )


def test_gcp_field_transformations():
    assert (
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                    title: Test GCP Field Transformations test
                    status: test
                    logsource:
                        product: gcp
                        service: gcp.audit
                    detection:
                        selection:
                            data.httpRequest.remoteIp: "123.345.789"
                            data.httpRequest.requestMethod: "test"
                            data.httpRequest.status: "test"
                            data.protoPayload.authenticationInfo.principalEmail: "test"
                            data.protoPayload.status.code: "test"
                            data.protoPayload.methodName: "test"
                            data.protoPayload.requestMetadata.callerIp: "test"
                            data.protoPayload.requestMetadata.callerSuppliedUserAgent: "test"
                            data.protoPayload.status.message: "test"
                            data.severity: "test"
                            gcp.audit.method_name:
                                - storage.buckets.list
                                - storage.buckets.listChannels
                        condition: selection
                """
            )
        )
        == [
            "@network.client.ip:123.345.789 AND @http.method:test AND @http.status_code:test AND @usr.email:test AND @evt.status_code:test AND @evt.name:test AND @network.client.ip:test AND @http.useragent:test AND @evt.outcome:test AND @evt.outcome:test AND (@gcp.audit.method_name:storage.buckets.list OR @gcp.audit.method_name:storage.buckets.listChannels)"
        ]
        == [
            "@network.client.ip:123.345.789 AND @http.method:test AND @http.status_code:test AND @usr.email:test AND @evt.status_code:test AND @evt.name:test AND @network.client.ip:test AND @http.useragent:test AND @evt.outcome:test AND @evt.outcome:test AND (@gcp.audit.method_name:storage.buckets.list OR @gcp.audit.method_name:storage.buckets.listChannels)"
        ]
    )


def test_datadog_azure_transformations_test():
    assert (
        DatadogBackend().convert(
            SigmaCollection.from_yaml(
                """
                        title: Basic Sigma Rule Test for Azure
                        status: test
                        logsource:
                            product: azure
                            service: signinlogs
                        detection:
                            selection:
                                operationName: 'multiFactorAuthentication'
                                ResultType: 'Test Result'
                                category: 'test'
                                properties.result: 'test'
                                callerIpAddress: 'test'
                                identity.authorization.evidence.principalId: '1234' 
                                resultType: 'test'
                            condition: selection
                    """
            )
        )
        == [
            "@evt.name:multiFactorAuthentication AND @evt.outcome:Test\\ Result AND @evt.category:test AND @evt.outcome:test AND @network.client.ip:test AND @usr.id:1234 AND @evt.outcome:test"
        ]
    )


def test_datadog_multiple_evt_names_aws():
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
            "@evt.source:s3.amazonaws.com AND (@evt.name:PutBucketLogging OR @evt.name:PutBucketWebsite OR @evt.name:PutEncryptionConfiguration)"
        ]
    )


def test_datadog_unsupported_rule_type():
    with pytest.raises(
        SigmaTransformationError,
        match="Conversion for rule type not yet supported by the Datadog Backend.",
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
                        responseElements|contains: 'Failure'
                    condition: selection and not 1 of filter*
            """
            )
        )
        == [
            "(@evt.name:CreateInstanceExportTask AND @evt.source:ec2.amazonaws.com) AND (NOT (@error.message:* OR @responseElements:*Failure*))"
        ]
    )


def test_datadog_pipeline_unsupported_regex():
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
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
