from .datadog import datadog_pipeline
# TODO: add all pipelines that should be exposed to the user of your backend in the import statement above.

pipelines = {
    "datadog_pipeline": datadog_pipeline,   # TODO: adapt identifier to something approproiate
}