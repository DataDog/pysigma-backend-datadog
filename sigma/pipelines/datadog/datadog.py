# pylint: disable=too-many-lines
from sigma.pipelines.common import logsource_windows
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import logsource_windows_network_connection,logsource_windows_network_connection_initiated, logsource_windows_process_creation, logsource_windows_dns_query

from sigma.rule import SigmaRule

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

dd_category_service_mapping = {
    "aws": "cloudtrail",
    "gcp": "auditlogs",
    "azure": "audit",
}


def get_ip_attributes(ip_attribute_list):
    for ip_attribute in ip_attribute_list:
        return ip_attribute_list[ip_attribute]



def datadog_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Generic Log Source to Datadog Query Syntax Transformation",
        allowed_backends=frozenset(),             # This needs to change to datadog once our backend is supported  ||Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"dd_mapping_category_{ category }_to_service_{ service }",
                transformation=ChangeLogsourceTransformation(product="dd", service=service),
                rule_conditions=[
                    LogsourceCondition(category=category, service=service)
                ],
            )
            for service, category in dd_category_service_mapping.items()

        ] + [
            ProcessingItem(     # Field mappings
                identifier="dd_aws_field_mapping",
                transformation=FieldMappingTransformation({
                    "FunctionVersion": "aws.function_version",
                    "InvokedFunctionArn": "aws.invoked_function_arn",
                    "S3Bucket": "s3.bucket",
                    "S3Key": "s3.key",
                    "AwsRegion": "awsRegion",
                    "EventCategory": "eventCategory",
                    "EventId": "eventID",
                    "EventName": "eventName",
                    "EventSource": "eventSource",
                    "EventTime": "eventTime",
                    "EventType": "eventType",
                    "EventVersion": "eventVersion",
                    "HttpRequestId": "http.request_id",
                    "HttpUserAgent": "http.useragent",
                    "UserAgentBrowser": "http.useragent_details.browser.family",
                    "UserAgentDeviceCategory": "http.useragent_details.device.category",
                    "UserAgentDeviceFamily": "http.useragent_details.device.family",
                    "UserAgentOS": "http.useragent_details.os.family",
                    "ManagementEvent": "managementEvent",
                    "NetworkClientDomain": "network.client.geopip.as.domain",
                    "NetworkClientName": "network.client.geopip.as.name",
                    "NetworkClientNumber": "network.client.geopip.as.number",
                    "NetworkClientRoute": "network.client.geopip.as.route",
                    "NetworkClientType": "network.client.geopip.as.type",
                    "NetworkClientCity": "network.client.geoip.city.name",
                    "NetworkClientContinentCode": "network.client.geoip.continent.code",
                    "NetworkClientContinentName": "network.client.geoip.continent.name",
                    "NetworkClientCountryIsoCode": "network.client.geoip.country.iso_code",
                    "NetworkClientCountryName": "network.client.geoip.country.name",
                    "NetworkClientIpAddress": "network.client.geoip.ipAddress",
                    "NetworkClientLatitude": "network.client.geoip.location.latitude",
                    "NetworkClientLongitude": "network.client.geoip.location.longitude",
                    "NetworkClientSubdivisionIsoCode": "network.client.geoip.subdivision.iso_code",
                    "NetworkClientSubdivisionName": "network.client.geoip.subdivision.name",
                    "NetworkClientTimezone": "network.client.geoip.timezone",
                    "NetworkClientIp": "network.client.ip.ip",
                    "NetworkClientIsPrivate": "network.client.is_private_network_ip",
                    "IpAttributes": "network.ip.attributes",
                    "IpAddressList": "network.ip.list",
                    "ReadOnly": "readOnly",
                    "RecipientAccountId": "recipientAccountId",
                    "RequestParameters": "requestParameters",
                    "Service": "service",
                    "TlsCipherSuite": "tlsDetails.cipherSuite",
                    "TlsClientProvidedHostHeader": "tlsDetails.clientProvidedHostHeader",
                    "TlsVersion": "tlsDetails.tlsVersion",
                    "UserAccessKey": "userIdentity.accessKeyId",
                    "UserAccountId": "userIdentity.accountId",
                    "UserArn": "userIdentity.arn",
                    "UserAssumedRole": "userIdentity.assumed_role",
                    "UserPrincipalId": "userIdentity.principalId",
                    "UserSessionName": "userIdentity.session_name",
                    "UserSessionCreationDate": "userIdentity.sessionContext.attributes.creationDate",
                    "UserSessionMfaAuthenticated": "userIdentity.sessionContext.attributes.mfaAuthenticated",
                    "UserSessionIssuerAccountId": "userIdentity.sessionContext.sessionIssuer.accountId",
                    "UserSessionIssuerArn": "userIdentity.sessionContext.sessionIssuer.arn",
                    "UserSessionIssuerPrincipalId": "userIdentity.sessionContext.sessionIssuer.principalId",
                    "UserSessionIssuerType": "userIdentity.sessionContext.sessionIssuer.type",
                    "UserSessionIssuerUsername": "userIdentity.sessionContext.sessionIssuer.userName",
                    "UserIdentityType": "userIdentity.type",
                })
            ),
            ProcessingItem(     # Field mappings
                identifier="dd_azure_field_mapping",
                transformation=FieldMappingTransformation({
                    "CorrelationId": "correlationId",
                    "Duration": "duration",
                    "EventCategory": "evt.category",
                    "EventName":"evt.name",
                    "EventOutcome": "evt.outcome",
                    "AuthorizationAction": "identity.authorization.action",
                    "IdentityPrincipalType": "identity.authorization.evidence.principalType",
                    "IdentityRole": "identity.authorization.evidence.role",
                    "IdentityRoleAssignment": "identity.authorization.evidence.roleAssignmentId",
                    "IdentityRoleAssignmentScope": "identity.authorization.evidence.roleAssignmentScope",
                    "IdentityRoleType": "identity.authorization.evidence.role",
                    "IdentityRoleDefinitionId": "identity.authorization.evidence.roleDefinitionId",
                })
            ),
        ],
    )
