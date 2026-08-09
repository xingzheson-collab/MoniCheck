package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusScrapeTimingObject(object *kubernetesObject, spec *yaml.Node) {
	interval := parseKubernetesDurationSetting(yamlMappingValue(spec, "scrapeInterval"))
	timeout := parseKubernetesDurationSetting(yamlMappingValue(spec, "scrapeTimeout"))
	object.PrometheusScrapeIntervalSeconds = interval.Seconds
	object.PrometheusScrapeIntervalDeclared = interval.Declared
	object.PrometheusScrapeIntervalValid = interval.Valid
	object.PrometheusScrapeTimeoutSeconds = timeout.Seconds
	object.PrometheusScrapeTimeoutDeclared = timeout.Declared
	object.PrometheusScrapeTimeoutValid = timeout.Valid
	for _, setting := range []kubernetesDurationSetting{interval, timeout} {
		if setting.Declared && !setting.Valid {
			object.PrometheusScrapeTimingInvalid++
		}
	}
	object.PrometheusScrapeTimingConflict = interval.Valid && timeout.Valid && timeout.Seconds > interval.Seconds
}

func parseKubernetesMonitorScrapeTiming(spec *yaml.Node, kind string) kubernetesMonitorScrapeTiming {
	result := kubernetesMonitorScrapeTiming{}
	add := func(intervalNode, timeoutNode *yaml.Node) {
		interval := parseKubernetesDurationSetting(intervalNode)
		timeout := parseKubernetesDurationSetting(timeoutNode)
		for _, setting := range []kubernetesDurationSetting{interval, timeout} {
			if setting.Declared && !setting.Valid {
				result.InvalidSettingCount++
			}
		}
		if interval.Valid && timeout.Valid && timeout.Seconds > interval.Seconds {
			result.TimeoutExceedsIntervalCount++
		}
		if !interval.Declared && timeout.Valid {
			result.TimeoutWithoutIntervalValues = append(result.TimeoutWithoutIntervalValues, timeout.Seconds)
		}
	}
	switch kind {
	case "ServiceMonitor", "PodMonitor":
		field := "endpoints"
		if kind == "PodMonitor" {
			field = "podMetricsEndpoints"
		}
		endpoints := yamlMappingValue(spec, field)
		if endpoints != nil && endpoints.Kind == yaml.SequenceNode {
			for _, endpoint := range endpoints.Content {
				add(yamlMappingValue(endpoint, "interval"), yamlMappingValue(endpoint, "scrapeTimeout"))
			}
		}
	case "Probe":
		add(yamlMappingValue(spec, "interval"), yamlMappingValue(spec, "scrapeTimeout"))
	case "ScrapeConfig":
		add(yamlMappingValue(spec, "scrapeInterval"), yamlMappingValue(spec, "scrapeTimeout"))
	}
	return result
}

func parseKubernetesDurationSetting(node *yaml.Node) kubernetesDurationSetting {
	if node == nil || node.Tag == "!!null" {
		return kubernetesDurationSetting{}
	}
	setting := kubernetesDurationSetting{Declared: true}
	if node.Kind != yaml.ScalarNode {
		return setting
	}
	setting.Seconds, setting.Valid = parsePrometheusRetentionDuration(node.Value)
	return setting
}

func populateKubernetesPrometheusScrapeTimingMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_scrape_timeout_seconds"] = strconv.FormatInt(object.PrometheusScrapeTimeoutSeconds, 10)
	resource.Metadata["prometheus_scrape_timeout_declared"] = strconv.FormatBool(object.PrometheusScrapeTimeoutDeclared)
	resource.Metadata["prometheus_scrape_timeout_valid"] = strconv.FormatBool(object.PrometheusScrapeTimeoutValid)
	resource.Metadata["prometheus_scrape_timing_invalid_setting_count"] = strconv.Itoa(object.PrometheusScrapeTimingInvalid)
	resource.Metadata["prometheus_scrape_timeout_exceeds_interval"] = strconv.FormatBool(object.PrometheusScrapeTimingConflict)
}

func populateKubernetesMonitorScrapeTimingMetadata(resource *model.Resource, timing kubernetesMonitorScrapeTiming) {
	resource.Metadata["monitor_scrape_timing_invalid_setting_count"] = strconv.Itoa(timing.InvalidSettingCount)
	resource.Metadata["monitor_scrape_timeout_exceeds_interval_count"] = strconv.Itoa(timing.TimeoutExceedsIntervalCount)
	values := make([]string, 0, len(timing.TimeoutWithoutIntervalValues))
	for _, value := range timing.TimeoutWithoutIntervalValues {
		values = append(values, strconv.FormatInt(value, 10))
	}
	resource.Metadata["monitor_scrape_timeout_without_interval_seconds"] = strings.Join(values, ",")
}

func kubernetesMetadataInt64List(value string) []int64 {
	result := make([]int64, 0)
	for _, item := range strings.Split(value, ",") {
		parsed, err := strconv.ParseInt(strings.TrimSpace(item), 10, 64)
		if err == nil && parsed > 0 {
			result = append(result, parsed)
		}
	}
	return result
}
