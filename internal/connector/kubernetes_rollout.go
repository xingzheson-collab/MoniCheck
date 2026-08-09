package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesRolloutSummary struct {
	MinReadySeconds               int64
	MinReadySecondsDeclared       bool
	MinReadySecondsValid          bool
	AffinityDeclared              bool
	AffinityValid                 bool
	PodAntiAffinityDeclared       bool
	PodAntiAffinityTermCount      int
	TopologySpreadDeclared        bool
	TopologySpreadCount           int
	SchedulingInvalidSettingCount int
}

func parseKubernetesRollout(spec *yaml.Node) kubernetesRolloutSummary {
	summary := kubernetesRolloutSummary{}
	summary.MinReadySeconds, summary.MinReadySecondsDeclared, summary.MinReadySecondsValid = parseKubernetesNonNegativeInt32(yamlMappingValue(spec, "minReadySeconds"))
	affinity := yamlMappingValue(spec, "affinity")
	summary.AffinityDeclared = yamlValueDeclared(affinity)
	if summary.AffinityDeclared {
		summary.AffinityValid = affinity.Kind == yaml.MappingNode
		if !summary.AffinityValid {
			summary.SchedulingInvalidSettingCount++
		} else {
			podAntiAffinity := yamlMappingValue(affinity, "podAntiAffinity")
			summary.PodAntiAffinityDeclared = yamlValueDeclared(podAntiAffinity)
			if summary.PodAntiAffinityDeclared {
				if podAntiAffinity.Kind != yaml.MappingNode {
					summary.SchedulingInvalidSettingCount++
				} else {
					for _, field := range []string{"requiredDuringSchedulingIgnoredDuringExecution", "preferredDuringSchedulingIgnoredDuringExecution"} {
						terms := yamlMappingValue(podAntiAffinity, field)
						if !yamlValueDeclared(terms) {
							continue
						}
						if terms.Kind != yaml.SequenceNode {
							summary.SchedulingInvalidSettingCount++
							continue
						}
						for _, term := range terms.Content {
							if term.Kind != yaml.MappingNode {
								summary.SchedulingInvalidSettingCount++
								continue
							}
							summary.PodAntiAffinityTermCount++
						}
					}
				}
			}
		}
	}
	topologySpread := yamlMappingValue(spec, "topologySpreadConstraints")
	summary.TopologySpreadDeclared = yamlValueDeclared(topologySpread)
	if !summary.TopologySpreadDeclared {
		return summary
	}
	if topologySpread.Kind != yaml.SequenceNode {
		summary.SchedulingInvalidSettingCount++
		return summary
	}
	for _, constraint := range topologySpread.Content {
		if !validKubernetesTopologySpreadConstraint(constraint) {
			summary.SchedulingInvalidSettingCount++
			continue
		}
		summary.TopologySpreadCount++
	}
	return summary
}

func parseKubernetesNonNegativeInt32(node *yaml.Node) (value int64, declared bool, valid bool) {
	declared = yamlValueDeclared(node)
	if !declared || node.Kind != yaml.ScalarNode {
		return 0, declared, false
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(node.Value), 10, 32)
	if err != nil || parsed < 0 {
		return 0, true, false
	}
	return parsed, true, true
}

func validKubernetesTopologySpreadConstraint(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	maxSkew, declared, valid := parseKubernetesNonNegativeInt32(yamlMappingValue(node, "maxSkew"))
	if !declared || !valid || maxSkew == 0 {
		return false
	}
	topologyKey := yamlMappingValue(node, "topologyKey")
	if topologyKey == nil || topologyKey.Kind != yaml.ScalarNode || strings.TrimSpace(topologyKey.Value) == "" {
		return false
	}
	whenUnsatisfiable := yamlMappingValue(node, "whenUnsatisfiable")
	if whenUnsatisfiable == nil || whenUnsatisfiable.Kind != yaml.ScalarNode {
		return false
	}
	switch strings.TrimSpace(whenUnsatisfiable.Value) {
	case "DoNotSchedule", "ScheduleAnyway":
		return true
	default:
		return false
	}
}
