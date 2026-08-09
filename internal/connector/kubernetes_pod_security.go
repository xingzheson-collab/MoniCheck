package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesPodSecuritySummary struct {
	InvalidCount             int
	RootUserCount            int
	NonRootDisabledCount     int
	PrivilegedCount          int
	HostProcessCount         int
	PrivilegeEscalationCount int
	UnconfinedSeccompCount   int
	CapabilityAdditionCount  int
	WritableRootFSCount      int
}

func parseKubernetesPodSecuritySummary(spec *yaml.Node) kubernetesPodSecuritySummary {
	summary := kubernetesPodSecuritySummary{}
	podContext := yamlMappingValue(spec, "securityContext")
	if yamlValueDeclared(podContext) {
		if podContext.Kind != yaml.MappingNode {
			summary.InvalidCount++
		} else {
			parseKubernetesSecurityContext(&summary, podContext, false)
		}
	}
	for _, field := range []string{"containers", "initContainers"} {
		containers := yamlMappingValue(spec, field)
		if !yamlValueDeclared(containers) {
			continue
		}
		if containers.Kind != yaml.SequenceNode {
			if field == "initContainers" {
				summary.InvalidCount++
			}
			continue
		}
		for _, container := range containers.Content {
			if container.Kind != yaml.MappingNode {
				if field == "initContainers" {
					summary.InvalidCount++
				}
				continue
			}
			securityContext := yamlMappingValue(container, "securityContext")
			if !yamlValueDeclared(securityContext) {
				continue
			}
			if securityContext.Kind != yaml.MappingNode {
				summary.InvalidCount++
				continue
			}
			parseKubernetesSecurityContext(&summary, securityContext, true)
		}
	}
	return summary
}

func parseKubernetesSecurityContext(summary *kubernetesPodSecuritySummary, context *yaml.Node, container bool) {
	if value, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(context, "runAsNonRoot")); declared {
		if !valid {
			summary.InvalidCount++
		} else if !value {
			summary.NonRootDisabledCount++
		}
	}
	if value, declared, valid := parseKubernetesNonNegativeInt64(yamlMappingValue(context, "runAsUser")); declared {
		if !valid {
			summary.InvalidCount++
		} else if value == 0 {
			summary.RootUserCount++
		}
	}
	parseKubernetesSeccompContext(summary, yamlMappingValue(context, "seccompProfile"))
	parseKubernetesHostProcessContext(summary, yamlMappingValue(context, "windowsOptions"))
	if !container {
		return
	}
	if value, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(context, "privileged")); declared {
		if !valid {
			summary.InvalidCount++
		} else if value {
			summary.PrivilegedCount++
		}
	}
	if value, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(context, "allowPrivilegeEscalation")); declared {
		if !valid {
			summary.InvalidCount++
		} else if value {
			summary.PrivilegeEscalationCount++
		}
	}
	if value, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(context, "readOnlyRootFilesystem")); declared {
		if !valid {
			summary.InvalidCount++
		} else if !value {
			summary.WritableRootFSCount++
		}
	}
	capabilities := yamlMappingValue(context, "capabilities")
	if yamlValueDeclared(capabilities) {
		if capabilities.Kind != yaml.MappingNode {
			summary.InvalidCount++
		} else if additions := yamlMappingValue(capabilities, "add"); yamlValueDeclared(additions) {
			if additions.Kind != yaml.SequenceNode {
				summary.InvalidCount++
			} else if len(additions.Content) > 0 {
				valid := true
				for _, addition := range additions.Content {
					if addition.Kind != yaml.ScalarNode || strings.TrimSpace(addition.Value) == "" {
						valid = false
						break
					}
				}
				if valid {
					summary.CapabilityAdditionCount++
				} else {
					summary.InvalidCount++
				}
			}
		}
	}
}

func parseKubernetesSeccompContext(summary *kubernetesPodSecuritySummary, seccomp *yaml.Node) {
	if !yamlValueDeclared(seccomp) {
		return
	}
	if seccomp.Kind != yaml.MappingNode {
		summary.InvalidCount++
		return
	}
	typeNode := yamlMappingValue(seccomp, "type")
	if typeNode == nil || typeNode.Kind != yaml.ScalarNode {
		summary.InvalidCount++
		return
	}
	switch strings.TrimSpace(typeNode.Value) {
	case "RuntimeDefault", "Localhost":
	case "Unconfined":
		summary.UnconfinedSeccompCount++
	default:
		summary.InvalidCount++
	}
}

func parseKubernetesHostProcessContext(summary *kubernetesPodSecuritySummary, windowsOptions *yaml.Node) {
	if !yamlValueDeclared(windowsOptions) {
		return
	}
	if windowsOptions.Kind != yaml.MappingNode {
		summary.InvalidCount++
		return
	}
	if value, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(windowsOptions, "hostProcess")); declared {
		if !valid {
			summary.InvalidCount++
		} else if value {
			summary.HostProcessCount++
		}
	}
}

func parseKubernetesNonNegativeInt64(node *yaml.Node) (value int64, declared bool, valid bool) {
	declared = yamlValueDeclared(node)
	if !declared || node.Kind != yaml.ScalarNode {
		return 0, declared, false
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(node.Value), 10, 64)
	if err != nil || parsed < 0 {
		return 0, true, false
	}
	return parsed, true, true
}
