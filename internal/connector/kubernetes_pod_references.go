package connector

import (
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

type kubernetesPodReferenceSummary struct {
	SecretsDeclared               bool
	SecretCount                   int
	ConfigMapsDeclared            bool
	ConfigMapCount                int
	InvalidSettingCount           int
	GeneratedVolumeCollisionCount int
	ServiceAccountNameDeclared    bool
	ServiceAccountNameValid       bool
	CustomServiceAccount          bool
}

func parseKubernetesPodReferences(spec *yaml.Node) kubernetesPodReferenceSummary {
	summary := kubernetesPodReferenceSummary{}
	secretNames := parseKubernetesNamedReferences(yamlMappingValue(spec, "secrets"), &summary.SecretsDeclared, &summary.SecretCount, &summary.InvalidSettingCount)
	configMapNames := parseKubernetesNamedReferences(yamlMappingValue(spec, "configMaps"), &summary.ConfigMapsDeclared, &summary.ConfigMapCount, &summary.InvalidSettingCount)
	parseKubernetesServiceAccountName(yamlMappingValue(spec, "serviceAccountName"), &summary)

	generatedVolumeNames := make(map[string]bool, len(secretNames)+len(configMapNames))
	for name := range secretNames {
		generatedVolumeNames["secret-"+name] = true
	}
	for name := range configMapNames {
		generatedVolumeNames["configmap-"+name] = true
	}
	summary.GeneratedVolumeCollisionCount = countKubernetesGeneratedVolumeCollisions(yamlMappingValue(spec, "volumes"), generatedVolumeNames)
	return summary
}

func parseKubernetesNamedReferences(node *yaml.Node, declared *bool, count *int, invalidCount *int) map[string]bool {
	names := map[string]bool{}
	*declared = yamlValueDeclared(node)
	if !*declared {
		return names
	}
	if node.Kind != yaml.SequenceNode {
		*invalidCount++
		return names
	}
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			*invalidCount++
			continue
		}
		name := strings.TrimSpace(item.Value)
		if name == "" || names[name] || len(validation.IsDNS1123Subdomain(name)) > 0 {
			*invalidCount++
			continue
		}
		names[name] = true
		*count++
	}
	return names
}

func parseKubernetesServiceAccountName(node *yaml.Node, summary *kubernetesPodReferenceSummary) {
	summary.ServiceAccountNameDeclared = yamlValueDeclared(node)
	if !summary.ServiceAccountNameDeclared || node.Kind != yaml.ScalarNode {
		return
	}
	name := strings.TrimSpace(node.Value)
	summary.ServiceAccountNameValid = name != "" && len(validation.IsDNS1123Subdomain(name)) == 0
	summary.CustomServiceAccount = summary.ServiceAccountNameValid && name != "default"
}

func countKubernetesGeneratedVolumeCollisions(volumes *yaml.Node, generatedNames map[string]bool) int {
	if volumes == nil || volumes.Kind != yaml.SequenceNode || len(generatedNames) == 0 {
		return 0
	}
	count := 0
	for _, volume := range volumes.Content {
		if volume.Kind != yaml.MappingNode {
			continue
		}
		nameNode := yamlMappingValue(volume, "name")
		if nameNode != nil && nameNode.Kind == yaml.ScalarNode && generatedNames[strings.TrimSpace(nameNode.Value)] {
			count++
		}
	}
	return count
}
