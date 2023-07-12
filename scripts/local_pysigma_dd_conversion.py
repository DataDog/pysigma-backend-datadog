from sigma.collection import SigmaCollection

from sigma.backends.datadog import DatadogBackend


# Create the Datadog Pipeline and Backend
datadog_backend = DatadogBackend()

# Load rules from the Sigma repository which can be cloned from https://github.com/SigmaHQ/sigma
# Add the path to the rule that should be converted to the following list:
sigma_rules_to_convert = [
    r"/Users/{your.username}/sigma/sigma/rules/{path/to/rule/to/be/converted}",
    r"/Users/{your.username}/sigma/sigma/rules/cloud/azure/azure_blocked_account_attempt.yml", # example rule path
]

sigma_rule_collection = SigmaCollection.load_ruleset(sigma_rules_to_convert)

# Print converted Datadog rule using the `convert_rule` method from the `datadog_backend` from sigma rule reflected in
# the `sigma_rules_to_convert` list.
# To convert to a Datadog Cloud SIEM rule, use the "siem_rule" output format
# To convert a Sigma Rule into a Datadog Query, use the "default" output format.

for sigma_rule in sigma_rule_collection.rules:
    print(sigma_rule.title + " conversion:")
    print(datadog_backend.convert_rule(sigma_rule, "siem_rule")[0])
    print("/n")
