package connector

import (
	"strings"

	"gopkg.in/yaml.v3"
	k8sresource "k8s.io/apimachinery/pkg/api/resource"
)

type kubernetesResourceQuantity struct {
	declared bool
	valid    bool
	positive bool
	quantity k8sresource.Quantity
}

type kubernetesResourceRequirementsSummary struct {
	Declared      bool
	ObjectValid   bool
	InvalidCount  int
	CPURequest    kubernetesResourceQuantity
	MemoryRequest kubernetesResourceQuantity
	CPULimit      kubernetesResourceQuantity
	MemoryLimit   kubernetesResourceQuantity
}

func parseKubernetesResourceRequirementsSummary(spec *yaml.Node) kubernetesResourceRequirementsSummary {
	summary := kubernetesResourceRequirementsSummary{}
	resources := yamlMappingValue(spec, "resources")
	summary.Declared = yamlValueDeclared(resources)
	if !summary.Declared {
		return summary
	}
	summary.ObjectValid = resources.Kind == yaml.MappingNode
	if !summary.ObjectValid {
		summary.InvalidCount++
		return summary
	}

	requests, requestsValid := kubernetesResourceList(resources, "requests", &summary.InvalidCount)
	limits, limitsValid := kubernetesResourceList(resources, "limits", &summary.InvalidCount)
	summary.CPURequest = parseKubernetesResourceQuantity(requests, requestsValid, "cpu", &summary.InvalidCount)
	summary.MemoryRequest = parseKubernetesResourceQuantity(requests, requestsValid, "memory", &summary.InvalidCount)
	summary.CPULimit = parseKubernetesResourceQuantity(limits, limitsValid, "cpu", &summary.InvalidCount)
	summary.MemoryLimit = parseKubernetesResourceQuantity(limits, limitsValid, "memory", &summary.InvalidCount)

	for _, pair := range [][2]kubernetesResourceQuantity{{summary.CPURequest, summary.CPULimit}, {summary.MemoryRequest, summary.MemoryLimit}} {
		if pair[0].valid && pair[1].valid && pair[0].quantity.Cmp(pair[1].quantity) > 0 {
			summary.InvalidCount++
		}
	}
	return summary
}

func kubernetesResourceList(resources *yaml.Node, field string, invalidCount *int) (*yaml.Node, bool) {
	value := yamlMappingValue(resources, field)
	if !yamlValueDeclared(value) {
		return nil, true
	}
	if value.Kind != yaml.MappingNode {
		*invalidCount++
		return nil, false
	}
	return value, true
}

func parseKubernetesResourceQuantity(values *yaml.Node, listValid bool, field string, invalidCount *int) kubernetesResourceQuantity {
	if !listValid || values == nil {
		return kubernetesResourceQuantity{}
	}
	node := yamlMappingValue(values, field)
	setting := kubernetesResourceQuantity{declared: yamlValueDeclared(node)}
	if !setting.declared {
		return setting
	}
	if node.Kind != yaml.ScalarNode {
		*invalidCount++
		return setting
	}
	quantity, err := k8sresource.ParseQuantity(strings.TrimSpace(node.Value))
	if err != nil || quantity.Sign() < 0 {
		*invalidCount++
		return setting
	}
	setting.valid = true
	setting.positive = quantity.Sign() > 0
	setting.quantity = quantity
	return setting
}
