package connector

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesRuntimeSummary struct {
	ListenLocalEnabled                bool
	ListenLocalDeclared               bool
	ListenLocalValid                  bool
	LogLevel                          string
	LogLevelDeclared                  bool
	LogLevelValid                     bool
	LogFormat                         string
	LogFormatDeclared                 bool
	LogFormatValid                    bool
	ContainersDeclared                bool
	SidecarContainerCount             int
	ContainerInvalidCount             int
	InitContainersDeclared            bool
	InitContainerInvalidCount         int
	ManagedContainerOverrideCount     int
	ManagedInitContainerOverrideCount int
}

func parseKubernetesRuntime(spec *yaml.Node, managedContainerNames, managedInitContainerNames map[string]bool) kubernetesRuntimeSummary {
	summary := kubernetesRuntimeSummary{}
	summary.ListenLocalEnabled, summary.ListenLocalDeclared, summary.ListenLocalValid = parseKubernetesBooleanSetting(yamlMappingValue(spec, "listenLocal"))
	summary.LogLevel, summary.LogLevelDeclared, summary.LogLevelValid = parseKubernetesEnumSetting(yamlMappingValue(spec, "logLevel"), map[string]bool{"debug": true, "info": true, "warn": true, "error": true})
	summary.LogFormat, summary.LogFormatDeclared, summary.LogFormatValid = parseKubernetesEnumSetting(yamlMappingValue(spec, "logFormat"), map[string]bool{"logfmt": true, "json": true})
	containers := yamlMappingValue(spec, "containers")
	summary.ContainersDeclared = yamlValueDeclared(containers)
	if summary.ContainersDeclared {
		summary.SidecarContainerCount, summary.ManagedContainerOverrideCount, summary.ContainerInvalidCount = parseKubernetesRuntimeContainerList(containers, managedContainerNames)
	}
	initContainers := yamlMappingValue(spec, "initContainers")
	summary.InitContainersDeclared = yamlValueDeclared(initContainers)
	if summary.InitContainersDeclared {
		_, summary.ManagedInitContainerOverrideCount, summary.InitContainerInvalidCount = parseKubernetesRuntimeContainerList(initContainers, managedInitContainerNames)
	}
	return summary
}

func parseKubernetesRuntimeContainerList(containers *yaml.Node, managedNames map[string]bool) (additionalCount, managedOverrideCount, invalidCount int) {
	if containers.Kind != yaml.SequenceNode {
		return 0, 0, 1
	}
	seenNames := map[string]bool{}
	for _, container := range containers.Content {
		if container.Kind != yaml.MappingNode {
			invalidCount++
			continue
		}
		nameNode := yamlMappingValue(container, "name")
		if nameNode == nil || nameNode.Kind != yaml.ScalarNode || strings.TrimSpace(nameNode.Value) == "" {
			invalidCount++
			continue
		}
		name := strings.TrimSpace(nameNode.Value)
		if seenNames[name] {
			invalidCount++
			continue
		}
		seenNames[name] = true
		if managedNames[name] {
			managedOverrideCount++
		} else {
			additionalCount++
		}
	}
	return additionalCount, managedOverrideCount, invalidCount
}

func parseKubernetesEnumSetting(node *yaml.Node, allowed map[string]bool) (value string, declared bool, valid bool) {
	declared = yamlValueDeclared(node)
	if !declared || node.Kind != yaml.ScalarNode {
		return "", declared, false
	}
	value = strings.ToLower(strings.TrimSpace(node.Value))
	if value == "" {
		return "", true, true
	}
	return value, true, allowed[value]
}
