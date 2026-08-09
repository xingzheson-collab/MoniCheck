package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusNamespaceBoundaryObject(object *kubernetesObject, spec *yaml.Node) {
	object.PrometheusIgnoreNamespaceSelectors = yamlBoolValue(yamlMappingValue(spec, "ignoreNamespaceSelectors"))
	populateKubernetesNamespaceEnforcementObject(object, spec)
}

func populateKubernetesPrometheusNamespaceBoundaryMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_ignore_namespace_selectors"] = strconv.FormatBool(object.PrometheusIgnoreNamespaceSelectors)
	resource.Metadata["prometheus_enforced_namespace_label_declared"] = strconv.FormatBool(object.PrometheusEnforcedNamespaceLabel != "")
	resource.Metadata["prometheus_namespace_enforcement_exclusion_count"] = strconv.Itoa(len(object.PrometheusNamespaceLabelExclusions))
}

func populateKubernetesThanosRulerNamespaceBoundaryMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_enforced_namespace_label_declared"] = strconv.FormatBool(object.PrometheusEnforcedNamespaceLabel != "")
	resource.Metadata["thanos_ruler_namespace_enforcement_exclusion_count"] = strconv.Itoa(len(object.PrometheusNamespaceLabelExclusions))
}

func kubernetesMonitorHasBroadNamespaceSelector(resource model.Resource) bool {
	kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
	if kind != "ServiceMonitor" && kind != "PodMonitor" && kind != "Probe" {
		return false
	}
	return strings.TrimSpace(resource.Metadata["namespace_selector"]) == "*"
}

type kubernetesNamespaceEnforcementState int

const (
	kubernetesNamespaceUnprotected kubernetesNamespaceEnforcementState = iota
	kubernetesNamespaceEnforced
	kubernetesNamespaceExcluded
)

func populateKubernetesNamespaceEnforcementObject(object *kubernetesObject, spec *yaml.Node) {
	object.PrometheusEnforcedNamespaceLabel = yamlScalarValue(yamlMappingValue(spec, "enforcedNamespaceLabel"))
	object.PrometheusNamespaceLabelExclusions = parseKubernetesObjectReferences(yamlMappingValue(spec, "excludedFromEnforcement"))
	object.PrometheusNamespaceLabelExclusions = append(object.PrometheusNamespaceLabelExclusions, parseKubernetesDeprecatedRuleExclusions(yamlMappingValue(spec, "prometheusRulesExcludedFromEnforce"))...)
}

func parseKubernetesObjectReferences(node *yaml.Node) []kubernetesObjectReference {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	result := make([]kubernetesObjectReference, 0, len(node.Content))
	for _, item := range node.Content {
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		reference := kubernetesObjectReference{
			Group:     yamlScalarValue(yamlMappingValue(item, "group")),
			Resource:  yamlScalarValue(yamlMappingValue(item, "resource")),
			Namespace: yamlScalarValue(yamlMappingValue(item, "namespace")),
			Name:      yamlScalarValue(yamlMappingValue(item, "name")),
		}
		if reference.Namespace != "" && reference.Name != "" && reference.Resource != "" {
			result = append(result, reference)
		}
	}
	return result
}

func parseKubernetesDeprecatedRuleExclusions(node *yaml.Node) []kubernetesObjectReference {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	result := make([]kubernetesObjectReference, 0, len(node.Content))
	for _, item := range node.Content {
		namespace := yamlScalarValue(yamlMappingValue(item, "ruleNamespace"))
		name := yamlScalarValue(yamlMappingValue(item, "ruleName"))
		if namespace != "" && name != "" {
			result = append(result, kubernetesObjectReference{Group: "monitoring.coreos.com", Resource: "prometheusrules", Namespace: namespace, Name: name})
		}
	}
	return result
}

func kubernetesNamespaceEnforcementFor(object kubernetesObject, kind string, objectName string, namespace string) kubernetesNamespaceEnforcementState {
	if strings.TrimSpace(object.PrometheusEnforcedNamespaceLabel) == "" {
		return kubernetesNamespaceUnprotected
	}
	name := strings.TrimSpace(objectName)
	if slash := strings.Index(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	for _, reference := range object.PrometheusNamespaceLabelExclusions {
		if kubernetesObjectReferenceMatches(reference, kind, namespace, name) {
			return kubernetesNamespaceExcluded
		}
	}
	return kubernetesNamespaceEnforced
}

func kubernetesObjectReferenceMatches(reference kubernetesObjectReference, kind string, namespace string, name string) bool {
	if reference.Namespace != namespace || reference.Name != name {
		return false
	}
	group := strings.ToLower(strings.TrimSpace(reference.Group))
	if group != "" && group != "monitoring.coreos.com" {
		return false
	}
	expected := map[string]string{
		"ServiceMonitor": "servicemonitors",
		"PodMonitor":     "podmonitors",
		"Probe":          "probes",
		"ScrapeConfig":   "scrapeconfigs",
		"PrometheusRule": "prometheusrules",
	}[kind]
	resource := strings.ToLower(strings.TrimSpace(reference.Resource))
	return expected != "" && (resource == expected || resource == strings.TrimSuffix(expected, "s") || resource == strings.ToLower(kind))
}
