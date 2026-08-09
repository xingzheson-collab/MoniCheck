package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerSecurityObject(object *kubernetesObject, spec *yaml.Node) {
	object.AlertmanagerSecurityMetadata = true
	object.AlertmanagerHostNetworkEnabled, object.AlertmanagerHostNetworkDeclared, object.AlertmanagerHostNetworkValid = parseKubernetesBooleanSetting(yamlMappingValue(spec, "hostNetwork"))
	object.AlertmanagerAutomountTokenEnabled, object.AlertmanagerAutomountTokenDeclared, object.AlertmanagerAutomountTokenValid = parseKubernetesBooleanSetting(yamlMappingValue(spec, "automountServiceAccountToken"))

	clusterTLS := yamlMappingValue(spec, "clusterTLS")
	object.AlertmanagerClusterTLSDeclared = yamlValueDeclared(clusterTLS)
	if !object.AlertmanagerClusterTLSDeclared {
		return
	}
	if clusterTLS.Kind != yaml.MappingNode {
		object.AlertmanagerClusterTLSInvalidSettingCount = 1
		return
	}
	server := yamlMappingValue(clusterTLS, "server")
	client := yamlMappingValue(clusterTLS, "client")
	serverValid := yamlValueDeclared(server) && server.Kind == yaml.MappingNode
	clientValid := yamlValueDeclared(client) && client.Kind == yaml.MappingNode
	if !serverValid {
		object.AlertmanagerClusterTLSInvalidSettingCount++
	}
	if !clientValid {
		object.AlertmanagerClusterTLSInvalidSettingCount++
	}
	object.AlertmanagerClusterTLSComplete = serverValid && clientValid
	supported, evaluable := kubernetesPrometheusVersionAtLeast(object.AlertmanagerVersion, 0, 24)
	object.AlertmanagerClusterTLSVersionEvaluable = evaluable
	object.AlertmanagerClusterTLSVersionUnsupported = object.AlertmanagerClusterTLSComplete && evaluable && !supported
}

func populateKubernetesAlertmanagerSecurityMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_security_metadata"] = strconv.FormatBool(object.AlertmanagerSecurityMetadata)
	resource.Metadata["alertmanager_host_network_declared"] = strconv.FormatBool(object.AlertmanagerHostNetworkDeclared)
	resource.Metadata["alertmanager_host_network_valid"] = strconv.FormatBool(object.AlertmanagerHostNetworkValid)
	resource.Metadata["alertmanager_host_network_enabled"] = strconv.FormatBool(object.AlertmanagerHostNetworkEnabled)
	resource.Metadata["alertmanager_automount_token_declared"] = strconv.FormatBool(object.AlertmanagerAutomountTokenDeclared)
	resource.Metadata["alertmanager_automount_token_valid"] = strconv.FormatBool(object.AlertmanagerAutomountTokenValid)
	resource.Metadata["alertmanager_automount_token_enabled"] = strconv.FormatBool(object.AlertmanagerAutomountTokenEnabled)
	resource.Metadata["alertmanager_cluster_tls_declared"] = strconv.FormatBool(object.AlertmanagerClusterTLSDeclared)
	resource.Metadata["alertmanager_cluster_tls_complete"] = strconv.FormatBool(object.AlertmanagerClusterTLSComplete)
	resource.Metadata["alertmanager_cluster_tls_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerClusterTLSInvalidSettingCount)
	resource.Metadata["alertmanager_cluster_tls_version_evaluable"] = strconv.FormatBool(object.AlertmanagerClusterTLSVersionEvaluable)
	resource.Metadata["alertmanager_cluster_tls_version_unsupported"] = strconv.FormatBool(object.AlertmanagerClusterTLSVersionUnsupported)
}

func parseKubernetesBooleanSetting(node *yaml.Node) (value bool, declared bool, valid bool) {
	declared = yamlValueDeclared(node)
	if !declared || node.Kind != yaml.ScalarNode {
		return false, declared, false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(node.Value))
	if err != nil {
		return false, true, false
	}
	return parsed, true, true
}
