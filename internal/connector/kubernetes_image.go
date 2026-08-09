package connector

import (
	"strings"

	registryreference "github.com/distribution/reference"
	"gopkg.in/yaml.v3"
)

type kubernetesImageSettingsSummary struct {
	ImageDeclared                 bool
	ImageValid                    bool
	ImageDigestPinned             bool
	ImageLatestTag                bool
	ImagePullPolicyDeclared       bool
	ImagePullPolicyValid          bool
	ImagePullPolicy               string
	LegacyImageFieldCount         int
	ShadowedLegacyImageFieldCount int
	ImagePullSecretsDeclared      bool
	ImagePullSecretCount          int
	InvalidCount                  int
}

func parseKubernetesImageSettings(spec *yaml.Node) kubernetesImageSettingsSummary {
	summary := kubernetesImageSettingsSummary{}
	parseKubernetesImageReference(&summary, yamlMappingValue(spec, "image"))
	parseKubernetesImagePullPolicy(&summary, yamlMappingValue(spec, "imagePullPolicy"))
	parseKubernetesLegacyImageFields(&summary, spec)
	parseKubernetesImagePullSecrets(&summary, yamlMappingValue(spec, "imagePullSecrets"))
	return summary
}

func parseKubernetesImageReference(summary *kubernetesImageSettingsSummary, node *yaml.Node) {
	summary.ImageDeclared = yamlValueDeclared(node)
	if !summary.ImageDeclared {
		return
	}
	if node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "" {
		summary.InvalidCount++
		return
	}
	reference, err := registryreference.ParseNormalizedNamed(strings.TrimSpace(node.Value))
	if err != nil {
		summary.InvalidCount++
		return
	}
	summary.ImageValid = true
	_, summary.ImageDigestPinned = reference.(registryreference.Digested)
	if tagged, ok := reference.(registryreference.Tagged); ok {
		summary.ImageLatestTag = tagged.Tag() == "latest"
	} else if !summary.ImageDigestPinned {
		summary.ImageLatestTag = true
	}
}

func parseKubernetesImagePullPolicy(summary *kubernetesImageSettingsSummary, node *yaml.Node) {
	summary.ImagePullPolicyDeclared = yamlValueDeclared(node)
	if !summary.ImagePullPolicyDeclared {
		return
	}
	if node.Kind != yaml.ScalarNode {
		summary.InvalidCount++
		return
	}
	value := strings.TrimSpace(node.Value)
	if value != "Always" && value != "IfNotPresent" && value != "Never" {
		summary.InvalidCount++
		return
	}
	summary.ImagePullPolicyValid = true
	summary.ImagePullPolicy = value
}

func parseKubernetesLegacyImageFields(summary *kubernetesImageSettingsSummary, spec *yaml.Node) {
	for _, field := range []string{"baseImage", "tag", "sha"} {
		node := yamlMappingValue(spec, field)
		if !yamlValueDeclared(node) {
			continue
		}
		summary.LegacyImageFieldCount++
		if summary.ImageDeclared {
			summary.ShadowedLegacyImageFieldCount++
		}
		if node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "" {
			summary.InvalidCount++
		}
	}
}

func parseKubernetesImagePullSecrets(summary *kubernetesImageSettingsSummary, node *yaml.Node) {
	summary.ImagePullSecretsDeclared = yamlValueDeclared(node)
	if !summary.ImagePullSecretsDeclared {
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
		summary.ImagePullSecretCount++
	}
}
