package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerWebObject(object *kubernetesObject, spec *yaml.Node) {
	object.AlertmanagerWebMetadata = true
	web := yamlMappingValue(spec, "web")
	object.AlertmanagerWebDeclared = yamlValueDeclared(web)
	if object.AlertmanagerWebDeclared {
		object.AlertmanagerWebObjectValid = web.Kind == yaml.MappingNode
		if !object.AlertmanagerWebObjectValid {
			object.AlertmanagerWebInvalidSettingCount = 1
		} else {
			object.AlertmanagerWebGetConcurrency, object.AlertmanagerWebGetConcurrencyDeclared, object.AlertmanagerWebGetConcurrencyValid = parseAlertmanagerUint32(yamlMappingValue(web, "getConcurrency"))
			object.AlertmanagerWebTimeoutSeconds, object.AlertmanagerWebTimeoutDeclared, object.AlertmanagerWebTimeoutValid = parseAlertmanagerUint32(yamlMappingValue(web, "timeout"))
			if object.AlertmanagerWebGetConcurrencyDeclared && !object.AlertmanagerWebGetConcurrencyValid {
				object.AlertmanagerWebInvalidSettingCount++
			}
			if object.AlertmanagerWebTimeoutDeclared && !object.AlertmanagerWebTimeoutValid {
				object.AlertmanagerWebInvalidSettingCount++
			}
			tlsConfig := yamlMappingValue(web, "tlsConfig")
			object.AlertmanagerWebTLSDeclared = yamlValueDeclared(tlsConfig)
			if object.AlertmanagerWebTLSDeclared && tlsConfig.Kind != yaml.MappingNode {
				object.AlertmanagerWebInvalidSettingCount++
			}
			httpConfig := yamlMappingValue(web, "httpConfig")
			object.AlertmanagerWebHTTPConfigDeclared = yamlValueDeclared(httpConfig)
			if object.AlertmanagerWebHTTPConfigDeclared && httpConfig.Kind != yaml.MappingNode {
				object.AlertmanagerWebInvalidSettingCount++
			}
		}
	}
	externalURL := yamlScalarValue(yamlMappingValue(spec, "externalUrl"))
	object.AlertmanagerExternalURLDeclared = externalURL != ""
	if object.AlertmanagerExternalURLDeclared {
		object.AlertmanagerExternalURLScheme, object.AlertmanagerExternalURLValid = safeRemoteWriteURLMetadata(externalURL)
	}
}

func populateKubernetesAlertmanagerWebMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_web_metadata"] = strconv.FormatBool(object.AlertmanagerWebMetadata)
	resource.Metadata["alertmanager_web_declared"] = strconv.FormatBool(object.AlertmanagerWebDeclared)
	resource.Metadata["alertmanager_web_object_valid"] = strconv.FormatBool(object.AlertmanagerWebObjectValid)
	resource.Metadata["alertmanager_web_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerWebInvalidSettingCount)
	resource.Metadata["alertmanager_web_get_concurrency_declared"] = strconv.FormatBool(object.AlertmanagerWebGetConcurrencyDeclared)
	resource.Metadata["alertmanager_web_get_concurrency_valid"] = strconv.FormatBool(object.AlertmanagerWebGetConcurrencyValid)
	resource.Metadata["alertmanager_web_get_concurrency"] = strconv.FormatUint(object.AlertmanagerWebGetConcurrency, 10)
	resource.Metadata["alertmanager_web_timeout_declared"] = strconv.FormatBool(object.AlertmanagerWebTimeoutDeclared)
	resource.Metadata["alertmanager_web_timeout_valid"] = strconv.FormatBool(object.AlertmanagerWebTimeoutValid)
	resource.Metadata["alertmanager_web_timeout_seconds"] = strconv.FormatUint(object.AlertmanagerWebTimeoutSeconds, 10)
	resource.Metadata["alertmanager_web_timeout_enabled"] = strconv.FormatBool(object.AlertmanagerWebTimeoutValid && object.AlertmanagerWebTimeoutSeconds > 0)
	resource.Metadata["alertmanager_web_tls_declared"] = strconv.FormatBool(object.AlertmanagerWebTLSDeclared)
	resource.Metadata["alertmanager_web_http_config_declared"] = strconv.FormatBool(object.AlertmanagerWebHTTPConfigDeclared)
	resource.Metadata["alertmanager_external_url_declared"] = strconv.FormatBool(object.AlertmanagerExternalURLDeclared)
	resource.Metadata["alertmanager_external_url_valid"] = strconv.FormatBool(object.AlertmanagerExternalURLValid)
	resource.Metadata["alertmanager_external_url_scheme"] = object.AlertmanagerExternalURLScheme
}

func parseAlertmanagerUint32(node *yaml.Node) (value uint64, declared bool, valid bool) {
	declared = yamlValueDeclared(node)
	if !declared || node.Kind != yaml.ScalarNode {
		return 0, declared, false
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(node.Value), 10, 32)
	if err != nil {
		return 0, true, false
	}
	return parsed, true, true
}
