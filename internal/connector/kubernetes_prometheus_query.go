package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusQueryObject(object *kubernetesObject, spec *yaml.Node) {
	if object.Kind != "Prometheus" {
		return
	}
	query := yamlMappingValue(spec, "query")
	object.PrometheusQueryDeclared = yamlValueDeclared(query)
	object.PrometheusQueryObjectValid = !object.PrometheusQueryDeclared || query.Kind == yaml.MappingNode
	object.PrometheusQueryMaxConcurrency, object.PrometheusQueryMaxConcDeclared, object.PrometheusQueryMaxConcValid = yamlIntegerValue(yamlMappingValue(query, "maxConcurrency"))
	object.PrometheusQueryMaxSamples, object.PrometheusQueryMaxSamplesDeclared, object.PrometheusQueryMaxSamplesValid = yamlIntegerValue(yamlMappingValue(query, "maxSamples"))
	timeout := yamlScalarValue(yamlMappingValue(query, "timeout"))
	object.PrometheusQueryTimeoutDeclared = timeout != ""
	object.PrometheusQueryTimeoutSeconds, object.PrometheusQueryTimeoutValid = parsePrometheusRetentionDuration(timeout)
	lookback := yamlScalarValue(yamlMappingValue(query, "lookbackDelta"))
	object.PrometheusQueryLookbackDeclared = lookback != ""
	object.PrometheusQueryLookbackSeconds, object.PrometheusQueryLookbackValid = parsePrometheusRetentionDuration(lookback)
}

func populateKubernetesPrometheusQueryMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_query_declared"] = strconv.FormatBool(object.PrometheusQueryDeclared)
	resource.Metadata["prometheus_query_object_valid"] = strconv.FormatBool(object.PrometheusQueryObjectValid)
	resource.Metadata["prometheus_query_max_concurrency"] = strconv.Itoa(object.PrometheusQueryMaxConcurrency)
	resource.Metadata["prometheus_query_max_concurrency_declared"] = strconv.FormatBool(object.PrometheusQueryMaxConcDeclared)
	resource.Metadata["prometheus_query_max_concurrency_valid"] = strconv.FormatBool(object.PrometheusQueryMaxConcValid && object.PrometheusQueryMaxConcurrency > 0)
	resource.Metadata["prometheus_query_max_samples"] = strconv.Itoa(object.PrometheusQueryMaxSamples)
	resource.Metadata["prometheus_query_max_samples_declared"] = strconv.FormatBool(object.PrometheusQueryMaxSamplesDeclared)
	resource.Metadata["prometheus_query_max_samples_valid"] = strconv.FormatBool(object.PrometheusQueryMaxSamplesValid && object.PrometheusQueryMaxSamples > 0)
	resource.Metadata["prometheus_query_timeout_seconds"] = strconv.FormatInt(object.PrometheusQueryTimeoutSeconds, 10)
	resource.Metadata["prometheus_query_timeout_declared"] = strconv.FormatBool(object.PrometheusQueryTimeoutDeclared)
	resource.Metadata["prometheus_query_timeout_valid"] = strconv.FormatBool(object.PrometheusQueryTimeoutValid)
	resource.Metadata["prometheus_query_lookback_seconds"] = strconv.FormatInt(object.PrometheusQueryLookbackSeconds, 10)
	resource.Metadata["prometheus_query_lookback_declared"] = strconv.FormatBool(object.PrometheusQueryLookbackDeclared)
	resource.Metadata["prometheus_query_lookback_valid"] = strconv.FormatBool(object.PrometheusQueryLookbackValid)
	resource.Metadata["prometheus_scrape_interval_seconds"] = strconv.FormatInt(object.PrometheusScrapeIntervalSeconds, 10)
	resource.Metadata["prometheus_scrape_interval_declared"] = strconv.FormatBool(object.PrometheusScrapeIntervalDeclared)
	resource.Metadata["prometheus_scrape_interval_valid"] = strconv.FormatBool(object.PrometheusScrapeIntervalValid)
	invalidCount := 0
	for _, invalid := range []bool{
		object.PrometheusQueryDeclared && !object.PrometheusQueryObjectValid,
		object.PrometheusQueryMaxConcDeclared && (!object.PrometheusQueryMaxConcValid || object.PrometheusQueryMaxConcurrency <= 0),
		object.PrometheusQueryMaxSamplesDeclared && (!object.PrometheusQueryMaxSamplesValid || object.PrometheusQueryMaxSamples <= 0),
		object.PrometheusQueryTimeoutDeclared && !object.PrometheusQueryTimeoutValid,
		object.PrometheusQueryLookbackDeclared && !object.PrometheusQueryLookbackValid,
	} {
		if invalid {
			invalidCount++
		}
	}
	resource.Metadata["prometheus_query_invalid_setting_count"] = strconv.Itoa(invalidCount)
	lookbackBelowScrape := object.PrometheusQueryLookbackDeclared && object.PrometheusQueryLookbackValid && object.PrometheusScrapeIntervalDeclared && object.PrometheusScrapeIntervalValid && object.PrometheusQueryLookbackSeconds < object.PrometheusScrapeIntervalSeconds
	resource.Metadata["prometheus_query_lookback_below_scrape_interval"] = strconv.FormatBool(lookbackBelowScrape)
}
