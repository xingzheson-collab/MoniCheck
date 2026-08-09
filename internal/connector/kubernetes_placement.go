package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

type kubernetesPlacementSummary struct {
	NodeSelectorDeclared               bool
	NodeSelectorValid                  bool
	NodeSelectorCount                  int
	SchedulerNameDeclared              bool
	SchedulerNameValid                 bool
	CustomScheduler                    bool
	PriorityClassNameDeclared          bool
	PriorityClassNameValid             bool
	TolerationsDeclared                bool
	TolerationCount                    int
	TolerationInvalidSettingCount      int
	BroadTolerationCount               int
	IndefiniteNoExecuteTolerationCount int
}

func parseKubernetesPlacement(spec *yaml.Node) kubernetesPlacementSummary {
	summary := kubernetesPlacementSummary{}
	parseKubernetesNodeSelector(&summary, yamlMappingValue(spec, "nodeSelector"))
	parseKubernetesSchedulerName(&summary, yamlMappingValue(spec, "schedulerName"))
	parseKubernetesPriorityClassName(&summary, yamlMappingValue(spec, "priorityClassName"))
	parseKubernetesTolerations(&summary, yamlMappingValue(spec, "tolerations"))
	return summary
}

func parseKubernetesPriorityClassName(summary *kubernetesPlacementSummary, node *yaml.Node) {
	summary.PriorityClassNameDeclared = yamlValueDeclared(node)
	if !summary.PriorityClassNameDeclared || node.Kind != yaml.ScalarNode {
		return
	}
	name := strings.TrimSpace(node.Value)
	summary.PriorityClassNameValid = name != "" && len(validation.IsDNS1123Subdomain(name)) == 0
}

func parseKubernetesNodeSelector(summary *kubernetesPlacementSummary, node *yaml.Node) {
	summary.NodeSelectorDeclared = yamlValueDeclared(node)
	if !summary.NodeSelectorDeclared || node.Kind != yaml.MappingNode {
		return
	}
	seen := map[string]bool{}
	valid := true
	for index := 0; index+1 < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]
		if keyNode.Kind != yaml.ScalarNode || valueNode.Kind != yaml.ScalarNode {
			valid = false
			continue
		}
		key := strings.TrimSpace(keyNode.Value)
		value := strings.TrimSpace(valueNode.Value)
		if key == "" || seen[key] || len(validation.IsQualifiedName(key)) > 0 || len(validation.IsValidLabelValue(value)) > 0 {
			valid = false
			continue
		}
		seen[key] = true
		summary.NodeSelectorCount++
	}
	summary.NodeSelectorValid = valid
}

func parseKubernetesSchedulerName(summary *kubernetesPlacementSummary, node *yaml.Node) {
	summary.SchedulerNameDeclared = yamlValueDeclared(node)
	if !summary.SchedulerNameDeclared || node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "" {
		return
	}
	summary.SchedulerNameValid = true
	summary.CustomScheduler = strings.TrimSpace(node.Value) != "default-scheduler"
}

func parseKubernetesTolerations(summary *kubernetesPlacementSummary, node *yaml.Node) {
	summary.TolerationsDeclared = yamlValueDeclared(node)
	if !summary.TolerationsDeclared {
		return
	}
	if node.Kind != yaml.SequenceNode {
		summary.TolerationInvalidSettingCount++
		return
	}
	for _, item := range node.Content {
		valid, broad, indefiniteNoExecute := parseKubernetesToleration(item)
		if !valid {
			summary.TolerationInvalidSettingCount++
			continue
		}
		summary.TolerationCount++
		if broad {
			summary.BroadTolerationCount++
		}
		if indefiniteNoExecute {
			summary.IndefiniteNoExecuteTolerationCount++
		}
	}
}

func parseKubernetesToleration(node *yaml.Node) (valid bool, broad bool, indefiniteNoExecute bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return false, false, false
	}
	key, keyDeclared, keyValid := kubernetesOptionalScalar(node, "key")
	value, valueDeclared, valueValid := kubernetesOptionalScalar(node, "value")
	operator, operatorDeclared, operatorValid := kubernetesOptionalScalar(node, "operator")
	effect, effectDeclared, effectValid := kubernetesOptionalScalar(node, "effect")
	if !keyValid || !valueValid || !operatorValid || !effectValid {
		return false, false, false
	}
	if !operatorDeclared || operator == "" {
		operator = "Equal"
	}
	if !effectDeclared {
		effect = ""
	}
	if effect != "" && effect != "NoSchedule" && effect != "PreferNoSchedule" && effect != "NoExecute" {
		return false, false, false
	}
	if !keyDeclared {
		key = ""
	}
	if !valueDeclared {
		value = ""
	}
	switch operator {
	case "Equal":
		if key == "" {
			return false, false, false
		}
	case "Exists":
		if value != "" {
			return false, false, false
		}
	case "Gt", "Lt":
		if key == "" || !validKubernetesTolerationInteger(value) {
			return false, false, false
		}
	default:
		return false, false, false
	}
	_, secondsDeclared, secondsValid := parseKubernetesPlacementNonNegativeInt64(yamlMappingValue(node, "tolerationSeconds"))
	if secondsDeclared && (!secondsValid || effect != "NoExecute") {
		return false, false, false
	}
	broad = key == "" && operator == "Exists"
	indefiniteNoExecute = (effect == "" || effect == "NoExecute") && !secondsDeclared
	return true, broad, indefiniteNoExecute
}

func kubernetesOptionalScalar(node *yaml.Node, key string) (value string, declared bool, valid bool) {
	child := yamlMappingValue(node, key)
	declared = yamlValueDeclared(child)
	if !declared {
		return "", false, true
	}
	if child.Kind != yaml.ScalarNode {
		return "", true, false
	}
	return strings.TrimSpace(child.Value), true, true
}

func parseKubernetesPlacementNonNegativeInt64(node *yaml.Node) (value int64, declared bool, valid bool) {
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

func validKubernetesTolerationInteger(value string) bool {
	parsed, err := strconv.ParseInt(value, 10, 64)
	return err == nil && value == strconv.FormatInt(parsed, 10)
}
