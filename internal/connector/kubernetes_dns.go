package connector

import (
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesDNSSettingsSummary struct {
	DNSPolicyDeclared    bool
	DNSPolicyValid       bool
	DNSPolicy            string
	DNSConfigDeclared    bool
	DNSConfigObjectValid bool
	DNSNameserverCount   int
	InvalidCount         int
	ServiceLinksDeclared bool
	ServiceLinksValid    bool
	ServiceLinksEnabled  bool
}

func parseKubernetesDNSSettings(spec *yaml.Node, hostNetwork bool) kubernetesDNSSettingsSummary {
	summary := kubernetesDNSSettingsSummary{}
	parseKubernetesDNSPolicy(&summary, yamlMappingValue(spec, "dnsPolicy"), hostNetwork)
	parseKubernetesDNSConfig(&summary, yamlMappingValue(spec, "dnsConfig"))
	value, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(spec, "enableServiceLinks"))
	summary.ServiceLinksDeclared = declared
	summary.ServiceLinksValid = valid
	summary.ServiceLinksEnabled = valid && value
	if declared && !valid {
		summary.InvalidCount++
	}
	if summary.DNSPolicyValid && summary.DNSPolicy == "None" && summary.DNSNameserverCount == 0 {
		summary.InvalidCount++
	}
	return summary
}

func parseKubernetesDNSPolicy(summary *kubernetesDNSSettingsSummary, node *yaml.Node, hostNetwork bool) {
	summary.DNSPolicyDeclared = yamlValueDeclared(node)
	if !summary.DNSPolicyDeclared {
		summary.DNSPolicyValid = true
		if hostNetwork {
			summary.DNSPolicy = "ClusterFirstWithHostNet"
		} else {
			summary.DNSPolicy = "ClusterFirst"
		}
		return
	}
	if node.Kind != yaml.ScalarNode {
		summary.InvalidCount++
		return
	}
	value := strings.TrimSpace(node.Value)
	switch value {
	case "ClusterFirst", "ClusterFirstWithHostNet", "Default", "None":
		summary.DNSPolicyValid = true
		summary.DNSPolicy = value
	default:
		summary.InvalidCount++
	}
}

func parseKubernetesDNSConfig(summary *kubernetesDNSSettingsSummary, node *yaml.Node) {
	summary.DNSConfigDeclared = yamlValueDeclared(node)
	if !summary.DNSConfigDeclared {
		return
	}
	summary.DNSConfigObjectValid = node.Kind == yaml.MappingNode
	if !summary.DNSConfigObjectValid {
		summary.InvalidCount++
		return
	}
	parseKubernetesDNSNameservers(summary, yamlMappingValue(node, "nameservers"))
	parseKubernetesDNSScalarSequence(summary, yamlMappingValue(node, "searches"), 32)
	parseKubernetesDNSOptions(summary, yamlMappingValue(node, "options"))
}

func parseKubernetesDNSNameservers(summary *kubernetesDNSSettingsSummary, node *yaml.Node) {
	if !yamlValueDeclared(node) {
		return
	}
	if node.Kind != yaml.SequenceNode || len(node.Content) > 3 {
		summary.InvalidCount++
		return
	}
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode || net.ParseIP(strings.TrimSpace(item.Value)) == nil {
			summary.InvalidCount++
			continue
		}
		summary.DNSNameserverCount++
	}
}

func parseKubernetesDNSScalarSequence(summary *kubernetesDNSSettingsSummary, node *yaml.Node, limit int) {
	if !yamlValueDeclared(node) {
		return
	}
	if node.Kind != yaml.SequenceNode || len(node.Content) > limit {
		summary.InvalidCount++
		return
	}
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode || strings.TrimSpace(item.Value) == "" {
			summary.InvalidCount++
		}
	}
}

func parseKubernetesDNSOptions(summary *kubernetesDNSSettingsSummary, node *yaml.Node) {
	if !yamlValueDeclared(node) {
		return
	}
	if node.Kind != yaml.SequenceNode {
		summary.InvalidCount++
		return
	}
	seen := map[string]bool{}
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			summary.InvalidCount++
			continue
		}
		name := yamlMappingValue(item, "name")
		trimmedName := ""
		if name != nil && name.Kind == yaml.ScalarNode {
			trimmedName = strings.TrimSpace(name.Value)
		}
		if trimmedName == "" || seen[trimmedName] {
			summary.InvalidCount++
			continue
		}
		seen[trimmedName] = true
		value := yamlMappingValue(item, "value")
		if yamlValueDeclared(value) && value.Kind != yaml.ScalarNode {
			summary.InvalidCount++
		}
	}
}
