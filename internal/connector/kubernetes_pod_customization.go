package connector

import (
	"net"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

var kubernetesCommonReservedPodLabels = map[string]bool{
	"app.kubernetes.io/instance":   true,
	"app.kubernetes.io/managed-by": true,
	"app.kubernetes.io/name":       true,
	"app.kubernetes.io/version":    true,
}

type kubernetesPodCustomizationSummary struct {
	PodMetadataDeclared             bool
	PodMetadataObjectValid          bool
	PodMetadataLabelCount           int
	PodMetadataAnnotationCount      int
	ReservedLabelOverrideCount      int
	ReservedAnnotationOverrideCount int
	HostAliasesDeclared             bool
	HostAliasCount                  int
	HostAliasHostnameCount          int
	LoopbackHostAliasCount          int
	InvalidSettingCount             int
}

func parseKubernetesPodCustomization(spec *yaml.Node, legacyReservedLabel string) kubernetesPodCustomizationSummary {
	summary := kubernetesPodCustomizationSummary{}
	parseKubernetesPodMetadata(yamlMappingValue(spec, "podMetadata"), legacyReservedLabel, &summary)
	parseKubernetesHostAliases(yamlMappingValue(spec, "hostAliases"), &summary)
	return summary
}

func parseKubernetesPodMetadata(node *yaml.Node, legacyReservedLabel string, summary *kubernetesPodCustomizationSummary) {
	summary.PodMetadataDeclared = yamlValueDeclared(node)
	if !summary.PodMetadataDeclared {
		return
	}
	if node.Kind != yaml.MappingNode {
		summary.InvalidSettingCount++
		return
	}
	summary.PodMetadataObjectValid = true
	if name := yamlMappingValue(node, "name"); yamlValueDeclared(name) {
		if name.Kind != yaml.ScalarNode || len(validation.IsDNS1123Subdomain(strings.TrimSpace(name.Value))) > 0 {
			summary.InvalidSettingCount++
		}
	}
	parseKubernetesPodMetadataMap(yamlMappingValue(node, "labels"), true, legacyReservedLabel, summary)
	parseKubernetesPodMetadataMap(yamlMappingValue(node, "annotations"), false, legacyReservedLabel, summary)
}

func parseKubernetesPodMetadataMap(node *yaml.Node, labels bool, legacyReservedLabel string, summary *kubernetesPodCustomizationSummary) {
	if !yamlValueDeclared(node) {
		return
	}
	if node.Kind != yaml.MappingNode {
		summary.InvalidSettingCount++
		return
	}
	seen := map[string]bool{}
	for index := 0; index+1 < len(node.Content); index += 2 {
		keyNode, valueNode := node.Content[index], node.Content[index+1]
		if keyNode.Kind != yaml.ScalarNode || valueNode.Kind != yaml.ScalarNode {
			summary.InvalidSettingCount++
			continue
		}
		key := strings.TrimSpace(keyNode.Value)
		value := strings.TrimSpace(valueNode.Value)
		if key == "" || seen[key] || len(validation.IsQualifiedName(key)) > 0 || labels && len(validation.IsValidLabelValue(value)) > 0 {
			summary.InvalidSettingCount++
			continue
		}
		seen[key] = true
		if labels {
			summary.PodMetadataLabelCount++
			if kubernetesCommonReservedPodLabels[key] || key == legacyReservedLabel {
				summary.ReservedLabelOverrideCount++
			}
		} else {
			summary.PodMetadataAnnotationCount++
			if key == "kubectl.kubernetes.io/default-container" {
				summary.ReservedAnnotationOverrideCount++
			}
		}
	}
}

func parseKubernetesHostAliases(node *yaml.Node, summary *kubernetesPodCustomizationSummary) {
	summary.HostAliasesDeclared = yamlValueDeclared(node)
	if !summary.HostAliasesDeclared {
		return
	}
	if node.Kind != yaml.SequenceNode {
		summary.InvalidSettingCount++
		return
	}
	seenHostnames := map[string]bool{}
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			summary.InvalidSettingCount++
			continue
		}
		ipNode := yamlMappingValue(item, "ip")
		hostnames := yamlMappingValue(item, "hostnames")
		if ipNode == nil || ipNode.Kind != yaml.ScalarNode || hostnames == nil || hostnames.Kind != yaml.SequenceNode || len(hostnames.Content) == 0 {
			summary.InvalidSettingCount++
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(ipNode.Value))
		if ip == nil {
			summary.InvalidSettingCount++
			continue
		}
		validHostnames := 0
		itemInvalid := false
		for _, hostnameNode := range hostnames.Content {
			if hostnameNode.Kind != yaml.ScalarNode {
				itemInvalid = true
				continue
			}
			hostname := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostnameNode.Value)), ".")
			if hostname == "" || seenHostnames[hostname] || len(validation.IsDNS1123Subdomain(hostname)) > 0 {
				itemInvalid = true
				continue
			}
			seenHostnames[hostname] = true
			validHostnames++
		}
		if itemInvalid || validHostnames != len(hostnames.Content) {
			summary.InvalidSettingCount++
			continue
		}
		summary.HostAliasCount++
		summary.HostAliasHostnameCount += validHostnames
		if ip.IsLoopback() {
			summary.LoopbackHostAliasCount++
		}
	}
}
