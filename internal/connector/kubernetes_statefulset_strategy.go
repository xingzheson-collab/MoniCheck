package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesStatefulSetStrategySummary struct {
	PodManagementDeclared  bool
	PodManagementValid     bool
	PodManagementPolicy    string
	UpdateDeclared         bool
	UpdateObjectValid      bool
	UpdateTypeValid        bool
	UpdateType             string
	RollingDeclared        bool
	RollingValid           bool
	MaxUnavailableDeclared bool
	MaxUnavailableValid    bool
	MaxUnavailableValue    int64
	MaxUnavailablePercent  bool
	InvalidCount           int
}

func parseKubernetesStatefulSetStrategy(spec *yaml.Node) kubernetesStatefulSetStrategySummary {
	summary := kubernetesStatefulSetStrategySummary{
		PodManagementPolicy: "Parallel",
		UpdateType:          "RollingUpdate",
		MaxUnavailableValue: 1,
	}
	parseKubernetesPodManagementPolicy(&summary, yamlMappingValue(spec, "podManagementPolicy"))
	parseKubernetesStatefulSetUpdateStrategy(&summary, yamlMappingValue(spec, "updateStrategy"))
	return summary
}

func parseKubernetesPodManagementPolicy(summary *kubernetesStatefulSetStrategySummary, node *yaml.Node) {
	summary.PodManagementDeclared = yamlValueDeclared(node)
	if !summary.PodManagementDeclared {
		summary.PodManagementValid = true
		return
	}
	if node.Kind != yaml.ScalarNode {
		summary.InvalidCount++
		return
	}
	value := strings.TrimSpace(node.Value)
	if value != "Parallel" && value != "OrderedReady" {
		summary.InvalidCount++
		return
	}
	summary.PodManagementValid = true
	summary.PodManagementPolicy = value
}

func parseKubernetesStatefulSetUpdateStrategy(summary *kubernetesStatefulSetStrategySummary, node *yaml.Node) {
	summary.UpdateDeclared = yamlValueDeclared(node)
	if !summary.UpdateDeclared {
		summary.UpdateObjectValid = true
		summary.UpdateTypeValid = true
		summary.RollingValid = true
		summary.MaxUnavailableValid = true
		return
	}
	summary.UpdateObjectValid = node.Kind == yaml.MappingNode
	if !summary.UpdateObjectValid {
		summary.InvalidCount++
		return
	}

	typeNode := yamlMappingValue(node, "type")
	if !yamlValueDeclared(typeNode) {
		summary.UpdateTypeValid = true
	} else if typeNode.Kind == yaml.ScalarNode {
		value := strings.TrimSpace(typeNode.Value)
		if value == "RollingUpdate" || value == "OnDelete" {
			summary.UpdateTypeValid = true
			summary.UpdateType = value
		} else {
			summary.InvalidCount++
		}
	} else {
		summary.InvalidCount++
	}

	rolling := yamlMappingValue(node, "rollingUpdate")
	summary.RollingDeclared = yamlValueDeclared(rolling)
	if !summary.RollingDeclared {
		summary.RollingValid = true
		summary.MaxUnavailableValid = true
		return
	}
	if rolling.Kind != yaml.MappingNode {
		summary.InvalidCount++
		return
	}
	summary.RollingValid = true
	if summary.UpdateTypeValid && summary.UpdateType == "OnDelete" {
		summary.RollingValid = false
		summary.InvalidCount++
		return
	}
	if yamlValueDeclared(yamlMappingValue(rolling, "partition")) {
		summary.InvalidCount++
	}
	maxUnavailable := yamlMappingValue(rolling, "maxUnavailable")
	summary.MaxUnavailableDeclared = yamlValueDeclared(maxUnavailable)
	if !summary.MaxUnavailableDeclared {
		summary.MaxUnavailableValid = true
		return
	}
	value, percent, valid := parseKubernetesMaxUnavailable(maxUnavailable)
	summary.MaxUnavailableValid = valid
	if !valid {
		summary.InvalidCount++
		return
	}
	summary.MaxUnavailableValue = value
	summary.MaxUnavailablePercent = percent
}

func parseKubernetesMaxUnavailable(node *yaml.Node) (int64, bool, bool) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return 0, false, false
	}
	value := strings.TrimSpace(node.Value)
	percent := strings.HasSuffix(value, "%")
	if percent {
		value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed <= 0 || (percent && parsed > 100) {
		return 0, percent, false
	}
	return parsed, percent, true
}

func kubernetesEffectiveMaxUnavailable(value int64, percent bool, replicas int) int64 {
	if !percent {
		return value
	}
	if replicas <= 0 {
		return 0
	}
	return (value*int64(replicas) + 99) / 100
}
