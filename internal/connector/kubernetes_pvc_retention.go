package connector

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesPVCRetentionSummary struct {
	Declared            bool
	ObjectValid         bool
	WhenDeletedValid    bool
	WhenDeleted         string
	WhenScaledValid     bool
	WhenScaled          string
	InvalidSettingCount int
}

func parseKubernetesPVCRetentionPolicy(node *yaml.Node) kubernetesPVCRetentionSummary {
	summary := kubernetesPVCRetentionSummary{Declared: yamlValueDeclared(node), WhenDeleted: "Retain", WhenScaled: "Retain"}
	if !summary.Declared {
		summary.ObjectValid = true
		summary.WhenDeletedValid = true
		summary.WhenScaledValid = true
		return summary
	}
	summary.ObjectValid = node.Kind == yaml.MappingNode
	if !summary.ObjectValid {
		summary.InvalidSettingCount++
		return summary
	}
	summary.WhenDeleted, summary.WhenDeletedValid = parseKubernetesPVCRetentionValue(yamlMappingValue(node, "whenDeleted"))
	summary.WhenScaled, summary.WhenScaledValid = parseKubernetesPVCRetentionValue(yamlMappingValue(node, "whenScaled"))
	if !summary.WhenDeletedValid {
		summary.InvalidSettingCount++
	}
	if !summary.WhenScaledValid {
		summary.InvalidSettingCount++
	}
	return summary
}

func parseKubernetesPVCRetentionValue(node *yaml.Node) (string, bool) {
	if !yamlValueDeclared(node) {
		return "Retain", true
	}
	if node.Kind != yaml.ScalarNode {
		return "", false
	}
	value := strings.TrimSpace(node.Value)
	if value != "Retain" && value != "Delete" {
		return "", false
	}
	return value, true
}
