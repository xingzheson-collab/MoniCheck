package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesTerminationSummary struct {
	Declared bool
	Valid    bool
	Seconds  int64
}

func parseKubernetesTerminationGrace(spec *yaml.Node) kubernetesTerminationSummary {
	node := yamlMappingValue(spec, "terminationGracePeriodSeconds")
	summary := kubernetesTerminationSummary{Declared: yamlValueDeclared(node)}
	if !summary.Declared || node.Kind != yaml.ScalarNode {
		return summary
	}
	value, err := strconv.ParseInt(strings.TrimSpace(node.Value), 10, 64)
	if err == nil && value >= 0 {
		summary.Valid = true
		summary.Seconds = value
	}
	return summary
}
