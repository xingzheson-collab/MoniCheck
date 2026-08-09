package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerSecretConfigObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerSecretConfigMetadata = true
	for _, pair := range []struct {
		selector string
		file     string
	}{
		{selector: "objectStorageConfig", file: "objectStorageConfigFile"},
		{selector: "tracingConfig", file: "tracingConfigFile"},
		{selector: "alertRelabelConfigs", file: "alertRelabelConfigFile"},
	} {
		selectorDeclared := parseKubernetesSecretKeySelector(yamlMappingValue(spec, pair.selector), &object.ThanosRulerSecretConfigInvalidSettingCount)
		fileDeclared := parseKubernetesFileConfiguration(yamlMappingValue(spec, pair.file), &object.ThanosRulerSecretConfigInvalidSettingCount)
		if selectorDeclared {
			object.ThanosRulerSecretSelectorDeclaredCount++
		}
		if fileDeclared {
			object.ThanosRulerFileConfigDeclaredCount++
		}
		if selectorDeclared && fileDeclared {
			object.ThanosRulerShadowedSecretConfigCount++
		}
	}
	for _, selector := range []string{"queryConfig", "alertmanagersConfig"} {
		if parseKubernetesSecretKeySelector(yamlMappingValue(spec, selector), &object.ThanosRulerSecretConfigInvalidSettingCount) {
			object.ThanosRulerSecretSelectorDeclaredCount++
		}
	}
	if yamlValueDeclared(yamlMappingValue(spec, "queryConfig")) && yamlSequenceLength(yamlMappingValue(spec, "queryEndpoints")) > 0 {
		object.ThanosRulerShadowedSecretConfigCount++
	}
	if yamlValueDeclared(yamlMappingValue(spec, "alertmanagersConfig")) && yamlSequenceLength(yamlMappingValue(spec, "alertmanagersUrl")) > 0 {
		object.ThanosRulerShadowedSecretConfigCount++
	}
}

func parseKubernetesSecretKeySelector(node *yaml.Node, invalidCount *int) bool {
	declared := yamlValueDeclared(node)
	if !declared {
		return false
	}
	if node.Kind != yaml.MappingNode {
		*invalidCount++
		return true
	}
	name := yamlMappingValue(node, "name")
	key := yamlMappingValue(node, "key")
	nameValue := strings.TrimSpace(yamlScalarValue(name))
	keyValue := strings.TrimSpace(yamlScalarValue(key))
	if name == nil || name.Kind != yaml.ScalarNode || nameValue == "" || len(validation.IsDNS1123Subdomain(nameValue)) > 0 {
		*invalidCount++
	}
	if key == nil || key.Kind != yaml.ScalarNode || keyValue == "" || len(validation.IsConfigMapKey(keyValue)) > 0 {
		*invalidCount++
	}
	if optional := yamlMappingValue(node, "optional"); yamlValueDeclared(optional) {
		if _, _, valid := parseKubernetesBooleanSetting(optional); !valid {
			*invalidCount++
		}
	}
	return true
}

func parseKubernetesFileConfiguration(node *yaml.Node, invalidCount *int) bool {
	declared := yamlValueDeclared(node)
	if declared && (node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "") {
		*invalidCount++
	}
	return declared
}

func populateKubernetesThanosRulerSecretConfigMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_secret_config_metadata"] = strconv.FormatBool(object.ThanosRulerSecretConfigMetadata)
	resource.Metadata["thanos_ruler_secret_selector_declared_count"] = strconv.Itoa(object.ThanosRulerSecretSelectorDeclaredCount)
	resource.Metadata["thanos_ruler_secret_config_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerSecretConfigInvalidSettingCount)
	resource.Metadata["thanos_ruler_shadowed_secret_config_count"] = strconv.Itoa(object.ThanosRulerShadowedSecretConfigCount)
	resource.Metadata["thanos_ruler_file_config_declared_count"] = strconv.Itoa(object.ThanosRulerFileConfigDeclaredCount)
}
