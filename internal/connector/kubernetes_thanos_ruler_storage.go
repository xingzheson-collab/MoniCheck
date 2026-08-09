package connector

import (
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

var thanosRulerRetentionPattern = regexp.MustCompile(`^[0-9]+(?:ms|s|m|h|d|w|y)$`)

func populateKubernetesThanosRulerStorageObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerStorageMetadata = true
	storage := yamlMappingValue(spec, "storage")
	object.ThanosRulerStorageDeclared = yamlValueDeclared(storage)
	object.ThanosRulerStorageObjectValid = !object.ThanosRulerStorageDeclared || storage.Kind == yaml.MappingNode
	if !object.ThanosRulerStorageObjectValid {
		object.ThanosRulerStorageInvalidSettingCount++
	}

	emptyDir := yamlMappingValue(storage, "emptyDir")
	ephemeral := yamlMappingValue(storage, "ephemeral")
	pvc := yamlMappingValue(storage, "volumeClaimTemplate")
	emptyDirDeclared := yamlValueDeclared(emptyDir)
	ephemeralDeclared := yamlValueDeclared(ephemeral)
	pvcDeclared := yamlValueDeclared(pvc)
	for _, option := range []struct {
		node     *yaml.Node
		declared bool
	}{
		{emptyDir, emptyDirDeclared},
		{ephemeral, ephemeralDeclared},
		{pvc, pvcDeclared},
	} {
		if option.declared {
			object.ThanosRulerStorageOptionCount++
			if option.node.Kind != yaml.MappingNode {
				object.ThanosRulerStorageInvalidSettingCount++
			}
		}
	}
	switch {
	case emptyDirDeclared:
		object.ThanosRulerStorageMode = "empty-dir"
	case ephemeralDeclared:
		object.ThanosRulerStorageMode = "ephemeral"
	case pvcDeclared:
		object.ThanosRulerStorageMode = "pvc"
	default:
		object.ThanosRulerStorageMode = "default-empty-dir"
	}

	if pvcDeclared && pvc != nil && pvc.Kind == yaml.MappingNode {
		pvcRequestNode := yamlMappingValue(yamlMappingValue(yamlMappingValue(yamlMappingValue(pvc, "spec"), "resources"), "requests"), "storage")
		object.ThanosRulerPVCRequestDeclared = yamlValueDeclared(pvcRequestNode)
		if object.ThanosRulerPVCRequestDeclared && pvcRequestNode.Kind == yaml.ScalarNode {
			object.ThanosRulerPVCRequestBytes, object.ThanosRulerPVCRequestValid = parseKubernetesStorageQuantity(strings.TrimSpace(pvcRequestNode.Value))
		}
		if !object.ThanosRulerPVCRequestDeclared || !object.ThanosRulerPVCRequestValid {
			object.ThanosRulerStorageInvalidSettingCount++
		}
	}

	retentionNode := yamlMappingValue(spec, "retention")
	object.ThanosRulerRetentionDeclared = yamlValueDeclared(retentionNode)
	if object.ThanosRulerRetentionDeclared && retentionNode.Kind == yaml.ScalarNode {
		retention := strings.TrimSpace(retentionNode.Value)
		if thanosRulerRetentionPattern.MatchString(retention) {
			object.ThanosRulerRetentionSeconds, object.ThanosRulerRetentionValid = parsePrometheusRetentionDuration(retention)
		}
	}
	object.ThanosRulerStatelessMode = len(object.RemoteWrites) > 0
}

func populateKubernetesThanosRulerStorageMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_storage_metadata"] = strconv.FormatBool(object.ThanosRulerStorageMetadata)
	resource.Metadata["thanos_ruler_storage_declared"] = strconv.FormatBool(object.ThanosRulerStorageDeclared)
	resource.Metadata["thanos_ruler_storage_object_valid"] = strconv.FormatBool(object.ThanosRulerStorageObjectValid)
	resource.Metadata["thanos_ruler_storage_mode"] = object.ThanosRulerStorageMode
	resource.Metadata["thanos_ruler_storage_option_count"] = strconv.Itoa(object.ThanosRulerStorageOptionCount)
	resource.Metadata["thanos_ruler_storage_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerStorageInvalidSettingCount)
	resource.Metadata["thanos_ruler_pvc_request_declared"] = strconv.FormatBool(object.ThanosRulerPVCRequestDeclared)
	resource.Metadata["thanos_ruler_pvc_request_valid"] = strconv.FormatBool(object.ThanosRulerPVCRequestValid)
	resource.Metadata["thanos_ruler_pvc_request_bytes"] = strconv.FormatInt(object.ThanosRulerPVCRequestBytes, 10)
	resource.Metadata["thanos_ruler_retention_declared"] = strconv.FormatBool(object.ThanosRulerRetentionDeclared)
	resource.Metadata["thanos_ruler_retention_valid"] = strconv.FormatBool(object.ThanosRulerRetentionValid)
	resource.Metadata["thanos_ruler_retention_seconds"] = strconv.FormatInt(object.ThanosRulerRetentionSeconds, 10)
	resource.Metadata["thanos_ruler_stateless_mode"] = strconv.FormatBool(object.ThanosRulerStatelessMode)
}
