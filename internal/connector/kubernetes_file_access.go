package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

var kubernetesArbitraryFileKeys = map[string]bool{
	"bearerTokenFile": true,
	"caFile":          true,
	"certFile":        true,
	"keyFile":         true,
}

func populateKubernetesPrometheusFileAccessObject(object *kubernetesObject, spec *yaml.Node) {
	config := yamlMappingValue(spec, "arbitraryFSAccessThroughSMs")
	object.PrometheusArbitraryFSAccessDenied = yamlBoolValue(yamlMappingValue(config, "deny"))
}

func parseKubernetesMonitorArbitraryFileReferences(spec *yaml.Node, kind string) int {
	if kind != "ServiceMonitor" && kind != "PodMonitor" && kind != "Probe" {
		return 0
	}
	return countKubernetesArbitraryFileReferences(spec)
}

func countKubernetesArbitraryFileReferences(node *yaml.Node) int {
	if node == nil {
		return 0
	}
	count := 0
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index].Value
			value := node.Content[index+1]
			if kubernetesArbitraryFileKeys[key] && yamlScalarValue(value) != "" {
				count++
			}
			count += countKubernetesArbitraryFileReferences(value)
		}
		return count
	}
	for _, child := range node.Content {
		count += countKubernetesArbitraryFileReferences(child)
	}
	return count
}

func populateKubernetesPrometheusFileAccessMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_arbitrary_fs_access_denied"] = strconv.FormatBool(object.PrometheusArbitraryFSAccessDenied)
}

func populateKubernetesMonitorFileAccessMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["monitor_arbitrary_file_reference_count"] = strconv.Itoa(object.MonitorArbitraryFileReferenceCount)
}
