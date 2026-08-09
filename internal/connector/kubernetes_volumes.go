package connector

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesVolumeSummary struct {
	VolumesDeclared            bool
	VolumeMountsDeclared       bool
	InvalidSettingCount        int
	VolumeCount                int
	VolumeMountCount           int
	HostPathVolumeCount        int
	WritableHostPathMountCount int
	BidirectionalMountCount    int
}

func parseKubernetesVolumes(spec *yaml.Node) kubernetesVolumeSummary {
	summary := kubernetesVolumeSummary{}
	hostPathVolumes := parseKubernetesVolumeDefinitions(yamlMappingValue(spec, "volumes"), &summary)
	parseKubernetesVolumeMounts(yamlMappingValue(spec, "volumeMounts"), hostPathVolumes, &summary)
	return summary
}

func parseKubernetesVolumeDefinitions(node *yaml.Node, summary *kubernetesVolumeSummary) map[string]bool {
	hostPathVolumes := map[string]bool{}
	summary.VolumesDeclared = yamlValueDeclared(node)
	if !summary.VolumesDeclared {
		return hostPathVolumes
	}
	if node.Kind != yaml.SequenceNode {
		summary.InvalidSettingCount++
		return hostPathVolumes
	}
	seenNames := map[string]bool{}
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			summary.InvalidSettingCount++
			continue
		}
		name := kubernetesVolumeScalar(item, "name")
		valid := name != "" && !seenNames[name]
		if name != "" {
			seenNames[name] = true
		}
		sourceCount := 0
		var sourceName string
		var sourceNode *yaml.Node
		for index := 0; index+1 < len(item.Content); index += 2 {
			key := item.Content[index]
			if key.Kind != yaml.ScalarNode || key.Value == "name" {
				continue
			}
			sourceCount++
			sourceName = key.Value
			sourceNode = item.Content[index+1]
		}
		if sourceCount != 1 || sourceNode == nil || sourceNode.Kind != yaml.MappingNode {
			valid = false
		}
		if sourceName == "hostPath" {
			path := yamlMappingValue(sourceNode, "path")
			if path == nil || path.Kind != yaml.ScalarNode || strings.TrimSpace(path.Value) == "" {
				valid = false
			}
		}
		if !valid {
			summary.InvalidSettingCount++
			continue
		}
		summary.VolumeCount++
		if sourceName == "hostPath" {
			summary.HostPathVolumeCount++
			hostPathVolumes[name] = true
		}
	}
	return hostPathVolumes
}

func parseKubernetesVolumeMounts(node *yaml.Node, hostPathVolumes map[string]bool, summary *kubernetesVolumeSummary) {
	summary.VolumeMountsDeclared = yamlValueDeclared(node)
	if !summary.VolumeMountsDeclared {
		return
	}
	if node.Kind != yaml.SequenceNode {
		summary.InvalidSettingCount++
		return
	}
	seenPaths := map[string]bool{}
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			summary.InvalidSettingCount++
			continue
		}
		name := kubernetesVolumeScalar(item, "name")
		mountPath := kubernetesVolumeScalar(item, "mountPath")
		valid := name != "" && mountPath != "" && !seenPaths[mountPath]
		if mountPath != "" {
			seenPaths[mountPath] = true
		}
		readOnly, readOnlyDeclared, readOnlyValid := parseKubernetesBooleanSetting(yamlMappingValue(item, "readOnly"))
		if readOnlyDeclared && !readOnlyValid {
			valid = false
		}
		propagation := kubernetesVolumeScalar(item, "mountPropagation")
		if yamlValueDeclared(yamlMappingValue(item, "mountPropagation")) && propagation != "None" && propagation != "HostToContainer" && propagation != "Bidirectional" {
			valid = false
		}
		if !valid {
			summary.InvalidSettingCount++
			continue
		}
		summary.VolumeMountCount++
		if hostPathVolumes[name] && (!readOnlyDeclared || !readOnly) {
			summary.WritableHostPathMountCount++
		}
		if propagation == "Bidirectional" {
			summary.BidirectionalMountCount++
		}
	}
}

func kubernetesVolumeScalar(node *yaml.Node, key string) string {
	value := yamlMappingValue(node, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(value.Value)
}
