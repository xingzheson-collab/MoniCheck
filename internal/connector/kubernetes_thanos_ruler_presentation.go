package connector

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	prommodel "github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerPresentationObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerPresentationMetadata = true
	parseThanosRulerPortName(object, yamlMappingValue(spec, "portName"))
	parseThanosRulerPrefix(object, yamlMappingValue(spec, "externalPrefix"), true)
	parseThanosRulerPrefix(object, yamlMappingValue(spec, "routePrefix"), false)
	parseThanosRulerAlertQueryURL(object, yamlMappingValue(spec, "alertQueryUrl"))
	externalLabels := parseThanosRulerExternalLabels(object, yamlMappingValue(spec, "labels"))
	parseThanosRulerAlertDropLabels(object, yamlMappingValue(spec, "alertDropLabels"), externalLabels)
	parseThanosRulerHostUsers(object, yamlMappingValue(spec, "hostUsers"))
}

func parseThanosRulerPortName(object *kubernetesObject, node *yaml.Node) {
	object.ThanosRulerPortNameDeclared = yamlValueDeclared(node)
	if !object.ThanosRulerPortNameDeclared {
		return
	}
	object.ThanosRulerPortNameValid = node.Kind == yaml.ScalarNode && len(validation.IsValidPortName(strings.TrimSpace(node.Value))) == 0
	if !object.ThanosRulerPortNameValid {
		object.ThanosRulerPresentationInvalidSettingCount++
	}
}

func parseThanosRulerPrefix(object *kubernetesObject, node *yaml.Node, external bool) {
	declared := yamlValueDeclared(node)
	valid := false
	if declared && node.Kind == yaml.ScalarNode {
		valid = validThanosRulerWebPrefix(strings.TrimSpace(node.Value), external)
	}
	if external {
		object.ThanosRulerExternalPrefixDeclared = declared
		object.ThanosRulerExternalPrefixValid = valid
	} else {
		object.ThanosRulerRoutePrefixDeclared = declared
		object.ThanosRulerRoutePrefixValid = valid
	}
	if declared && !valid {
		object.ThanosRulerPresentationInvalidSettingCount++
	}
}

func validThanosRulerWebPrefix(value string, allowAbsolute bool) bool {
	if value == "" {
		return true
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.IsAbs() {
		scheme := strings.ToLower(parsed.Scheme)
		return allowAbsolute && (scheme == "http" || scheme == "https") && parsed.Host != ""
	}
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && parsed.Host == ""
}

func parseThanosRulerAlertQueryURL(object *kubernetesObject, node *yaml.Node) {
	object.ThanosRulerAlertQueryURLDeclared = yamlValueDeclared(node)
	if !object.ThanosRulerAlertQueryURLDeclared {
		return
	}
	if node.Kind != yaml.ScalarNode {
		object.ThanosRulerPresentationInvalidSettingCount++
		return
	}
	parsed, err := url.ParseRequestURI(strings.TrimSpace(node.Value))
	if err != nil || parsed.User != nil || parsed.Host == "" {
		object.ThanosRulerPresentationInvalidSettingCount++
		return
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		object.ThanosRulerPresentationInvalidSettingCount++
		return
	}
	object.ThanosRulerAlertQueryURLValid = true
	object.ThanosRulerAlertQueryURLScheme = scheme
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if address := net.ParseIP(host); address != nil {
		object.ThanosRulerAlertQueryURLLoopback = address.IsLoopback()
	} else {
		object.ThanosRulerAlertQueryURLLoopback = host == "localhost" || strings.HasSuffix(host, ".localhost")
	}
}

func parseThanosRulerExternalLabels(object *kubernetesObject, node *yaml.Node) map[string]bool {
	labels := map[string]bool{}
	object.ThanosRulerExternalLabelsDeclared = yamlValueDeclared(node)
	if !object.ThanosRulerExternalLabelsDeclared {
		return labels
	}
	if node.Kind != yaml.MappingNode {
		object.ThanosRulerExternalLabelInvalidCount++
		object.ThanosRulerPresentationInvalidSettingCount++
		return labels
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		keyNode, valueNode := node.Content[index], node.Content[index+1]
		if keyNode.Kind != yaml.ScalarNode || valueNode.Kind != yaml.ScalarNode {
			object.ThanosRulerExternalLabelInvalidCount++
			continue
		}
		key := strings.TrimSpace(keyNode.Value)
		if key == "" || !prommodel.LabelName(key).IsValid() || !prommodel.LabelValue(valueNode.Value).IsValid() {
			object.ThanosRulerExternalLabelInvalidCount++
			continue
		}
		labels[key] = true
		object.ThanosRulerExternalLabelCount++
		if key == "thanos_ruler_replica" {
			object.ThanosRulerReplicaLabelOverride = true
		}
	}
	object.ThanosRulerPresentationInvalidSettingCount += object.ThanosRulerExternalLabelInvalidCount
	return labels
}

func parseThanosRulerAlertDropLabels(object *kubernetesObject, node *yaml.Node, externalLabels map[string]bool) {
	object.ThanosRulerAlertDropLabelsDeclared = yamlValueDeclared(node)
	if !object.ThanosRulerAlertDropLabelsDeclared {
		return
	}
	if node.Kind != yaml.SequenceNode {
		object.ThanosRulerAlertDropLabelInvalidCount++
		object.ThanosRulerPresentationInvalidSettingCount++
		return
	}
	seen := map[string]bool{}
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			object.ThanosRulerAlertDropLabelInvalidCount++
			continue
		}
		name := strings.TrimSpace(item.Value)
		if name == "" || !prommodel.LabelName(name).IsValid() {
			object.ThanosRulerAlertDropLabelInvalidCount++
			continue
		}
		if seen[name] {
			object.ThanosRulerAlertDropLabelDuplicateCount++
			continue
		}
		seen[name] = true
		object.ThanosRulerAlertDropLabelCount++
		if externalLabels[name] {
			object.ThanosRulerDroppedExternalLabelCount++
		}
	}
	object.ThanosRulerPresentationInvalidSettingCount += object.ThanosRulerAlertDropLabelInvalidCount + object.ThanosRulerAlertDropLabelDuplicateCount
}

func parseThanosRulerHostUsers(object *kubernetesObject, node *yaml.Node) {
	object.ThanosRulerHostUsersDeclared = yamlValueDeclared(node)
	if !object.ThanosRulerHostUsersDeclared {
		return
	}
	if node.Kind != yaml.ScalarNode {
		object.ThanosRulerPresentationInvalidSettingCount++
		return
	}
	value, err := strconv.ParseBool(strings.TrimSpace(node.Value))
	if err != nil {
		object.ThanosRulerPresentationInvalidSettingCount++
		return
	}
	object.ThanosRulerHostUsersValid = true
	object.ThanosRulerUserNamespaceIsolationEnabled = !value
}

func populateKubernetesThanosRulerPresentationMetadata(resource *model.Resource, object kubernetesObject) {
	metadata := resource.Metadata
	metadata["thanos_ruler_presentation_metadata"] = strconv.FormatBool(object.ThanosRulerPresentationMetadata)
	metadata["thanos_ruler_port_name_declared"] = strconv.FormatBool(object.ThanosRulerPortNameDeclared)
	metadata["thanos_ruler_port_name_valid"] = strconv.FormatBool(object.ThanosRulerPortNameValid)
	metadata["thanos_ruler_external_prefix_declared"] = strconv.FormatBool(object.ThanosRulerExternalPrefixDeclared)
	metadata["thanos_ruler_external_prefix_valid"] = strconv.FormatBool(object.ThanosRulerExternalPrefixValid)
	metadata["thanos_ruler_route_prefix_declared"] = strconv.FormatBool(object.ThanosRulerRoutePrefixDeclared)
	metadata["thanos_ruler_route_prefix_valid"] = strconv.FormatBool(object.ThanosRulerRoutePrefixValid)
	metadata["thanos_ruler_alert_query_url_declared"] = strconv.FormatBool(object.ThanosRulerAlertQueryURLDeclared)
	metadata["thanos_ruler_alert_query_url_valid"] = strconv.FormatBool(object.ThanosRulerAlertQueryURLValid)
	metadata["thanos_ruler_alert_query_url_scheme"] = object.ThanosRulerAlertQueryURLScheme
	metadata["thanos_ruler_alert_query_url_loopback"] = strconv.FormatBool(object.ThanosRulerAlertQueryURLLoopback)
	metadata["thanos_ruler_external_labels_declared"] = strconv.FormatBool(object.ThanosRulerExternalLabelsDeclared)
	metadata["thanos_ruler_external_label_count"] = strconv.Itoa(object.ThanosRulerExternalLabelCount)
	metadata["thanos_ruler_external_label_invalid_count"] = strconv.Itoa(object.ThanosRulerExternalLabelInvalidCount)
	metadata["thanos_ruler_replica_label_override"] = strconv.FormatBool(object.ThanosRulerReplicaLabelOverride)
	metadata["thanos_ruler_alert_drop_labels_declared"] = strconv.FormatBool(object.ThanosRulerAlertDropLabelsDeclared)
	metadata["thanos_ruler_alert_drop_label_count"] = strconv.Itoa(object.ThanosRulerAlertDropLabelCount)
	metadata["thanos_ruler_alert_drop_label_invalid_count"] = strconv.Itoa(object.ThanosRulerAlertDropLabelInvalidCount)
	metadata["thanos_ruler_alert_drop_label_duplicate_count"] = strconv.Itoa(object.ThanosRulerAlertDropLabelDuplicateCount)
	metadata["thanos_ruler_dropped_external_label_count"] = strconv.Itoa(object.ThanosRulerDroppedExternalLabelCount)
	metadata["thanos_ruler_host_users_declared"] = strconv.FormatBool(object.ThanosRulerHostUsersDeclared)
	metadata["thanos_ruler_host_users_valid"] = strconv.FormatBool(object.ThanosRulerHostUsersValid)
	metadata["thanos_ruler_user_namespace_isolation_enabled"] = strconv.FormatBool(object.ThanosRulerUserNamespaceIsolationEnabled)
	metadata["thanos_ruler_presentation_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerPresentationInvalidSettingCount)
}
