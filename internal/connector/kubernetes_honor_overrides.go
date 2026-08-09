package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusHonorObject(object *kubernetesObject, spec *yaml.Node) {
	object.PrometheusOverrideHonorLabels = yamlBoolValue(yamlMappingValue(spec, "overrideHonorLabels"))
	object.PrometheusOverrideHonorTimestamps = yamlBoolValue(yamlMappingValue(spec, "overrideHonorTimestamps"))
}

func parseKubernetesMonitorHonorSettings(spec *yaml.Node, kind string) (int, int) {
	honorLabels := 0
	honorTimestamps := 0
	add := func(node *yaml.Node, timestampsSupported bool) {
		if yamlBoolValue(yamlMappingValue(node, "honorLabels")) {
			honorLabels++
		}
		if timestampsSupported && yamlBoolValue(yamlMappingValue(node, "honorTimestamps")) {
			honorTimestamps++
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
				add(endpoint, true)
			}
		}
	case "ScrapeConfig":
		add(spec, false)
	}
	return honorLabels, honorTimestamps
}

func populateKubernetesPrometheusHonorMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_override_honor_labels"] = strconv.FormatBool(object.PrometheusOverrideHonorLabels)
	resource.Metadata["prometheus_override_honor_timestamps"] = strconv.FormatBool(object.PrometheusOverrideHonorTimestamps)
}

func populateKubernetesMonitorHonorMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["monitor_honor_labels_count"] = strconv.Itoa(object.MonitorHonorLabelsCount)
	resource.Metadata["monitor_explicit_honor_timestamps_count"] = strconv.Itoa(object.MonitorExplicitHonorTimestampsCount)
}
