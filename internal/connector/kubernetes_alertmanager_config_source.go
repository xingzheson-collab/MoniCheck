package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerConfigSourceObject(object *kubernetesObject, spec *yaml.Node) {
	object.AlertmanagerConfigSourceMetadata = true
	configSecret := yamlMappingValue(spec, "configSecret")
	object.AlertmanagerConfigSecretDeclared = yamlValueDeclared(configSecret)
	if object.AlertmanagerConfigSecretDeclared {
		object.AlertmanagerConfigSecretValid = configSecret.Kind == yaml.ScalarNode
		object.AlertmanagerConfigSecretConfigured = object.AlertmanagerConfigSecretValid && strings.TrimSpace(configSecret.Value) != ""
	}

	configuration := yamlMappingValue(spec, "alertmanagerConfiguration")
	object.AlertmanagerConfigurationDeclared = yamlValueDeclared(configuration)
	if object.AlertmanagerConfigurationDeclared && configuration.Kind == yaml.MappingNode {
		name := yamlMappingValue(configuration, "name")
		object.AlertmanagerConfigurationValid = name != nil && name.Kind == yaml.ScalarNode && strings.TrimSpace(name.Value) != ""
		if object.AlertmanagerConfigurationValid {
			object.AlertmanagerConfigurationName = strings.TrimSpace(name.Value)
		}
	}
	object.AlertmanagerConfigSourceConflict = object.AlertmanagerConfigSecretConfigured && object.AlertmanagerConfigurationValid

	serviceName := yamlMappingValue(spec, "serviceName")
	object.AlertmanagerServiceNameDeclared = yamlValueDeclared(serviceName)
	if object.AlertmanagerServiceNameDeclared {
		object.AlertmanagerServiceNameValid = serviceName.Kind == yaml.ScalarNode
		object.AlertmanagerServiceNameConfigured = object.AlertmanagerServiceNameValid && strings.TrimSpace(serviceName.Value) != ""
		if object.AlertmanagerServiceNameConfigured {
			object.AlertmanagerServiceName = strings.TrimSpace(serviceName.Value)
		}
	}
	portName := yamlMappingValue(spec, "portName")
	object.AlertmanagerPortNameDeclared = yamlValueDeclared(portName)
	if object.AlertmanagerPortNameDeclared {
		object.AlertmanagerPortNameValid = portName.Kind == yaml.ScalarNode
		object.AlertmanagerPortNameConfigured = object.AlertmanagerPortNameValid && strings.TrimSpace(portName.Value) != ""
	}
}

func populateKubernetesAlertmanagerConfigSourceMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_config_source_metadata"] = strconv.FormatBool(object.AlertmanagerConfigSourceMetadata)
	resource.Metadata["alertmanager_config_secret_declared"] = strconv.FormatBool(object.AlertmanagerConfigSecretDeclared)
	resource.Metadata["alertmanager_config_secret_configured"] = strconv.FormatBool(object.AlertmanagerConfigSecretConfigured)
	resource.Metadata["alertmanager_config_secret_valid"] = strconv.FormatBool(object.AlertmanagerConfigSecretValid)
	resource.Metadata["alertmanager_configuration_declared"] = strconv.FormatBool(object.AlertmanagerConfigurationDeclared)
	resource.Metadata["alertmanager_configuration_valid"] = strconv.FormatBool(object.AlertmanagerConfigurationValid)
	resource.Metadata["alertmanager_configuration_found"] = strconv.FormatBool(object.AlertmanagerConfigurationFound)
	resource.Metadata["alertmanager_config_source_conflict"] = strconv.FormatBool(object.AlertmanagerConfigSourceConflict)
	resource.Metadata["alertmanager_service_name_declared"] = strconv.FormatBool(object.AlertmanagerServiceNameDeclared)
	resource.Metadata["alertmanager_service_name_configured"] = strconv.FormatBool(object.AlertmanagerServiceNameConfigured)
	resource.Metadata["alertmanager_service_name_valid"] = strconv.FormatBool(object.AlertmanagerServiceNameValid)
	resource.Metadata["alertmanager_port_name_declared"] = strconv.FormatBool(object.AlertmanagerPortNameDeclared)
	resource.Metadata["alertmanager_port_name_configured"] = strconv.FormatBool(object.AlertmanagerPortNameConfigured)
	resource.Metadata["alertmanager_port_name_valid"] = strconv.FormatBool(object.AlertmanagerPortNameValid)
	resource.Metadata["alertmanager_shared_service_count"] = strconv.Itoa(object.AlertmanagerSharedServiceCount)
}
