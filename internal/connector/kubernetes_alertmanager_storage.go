package connector

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

var alertmanagerRetentionPattern = regexp.MustCompile(`^[0-9]+(?:ms|s|m|h)$`)

func populateKubernetesAlertmanagerStorageObject(object *kubernetesObject, spec *yaml.Node) {
	storage := yamlMappingValue(spec, "storage")
	object.AlertmanagerStorageDeclared = yamlValueDeclared(storage)
	emptyDirDeclared := yamlValueDeclared(yamlMappingValue(storage, "emptyDir"))
	ephemeralDeclared := yamlValueDeclared(yamlMappingValue(storage, "ephemeral"))
	pvc := yamlMappingValue(storage, "volumeClaimTemplate")
	pvcDeclared := yamlValueDeclared(pvc)
	for _, declared := range []bool{emptyDirDeclared, ephemeralDeclared, pvcDeclared} {
		if declared {
			object.AlertmanagerStorageOptionCount++
		}
	}
	switch {
	case emptyDirDeclared:
		object.AlertmanagerStorageMode = "empty-dir"
	case ephemeralDeclared:
		object.AlertmanagerStorageMode = "ephemeral"
	case pvcDeclared:
		object.AlertmanagerStorageMode = "pvc"
	default:
		object.AlertmanagerStorageMode = "default-empty-dir"
	}
	pvcRequest := yamlScalarValue(yamlMappingValue(yamlMappingValue(yamlMappingValue(yamlMappingValue(pvc, "spec"), "resources"), "requests"), "storage"))
	object.AlertmanagerPVCRequestDeclared = pvcRequest != ""
	object.AlertmanagerPVCRequestBytes, object.AlertmanagerPVCRequestValid = parseKubernetesStorageQuantity(pvcRequest)

	retention := yamlScalarValue(yamlMappingValue(spec, "retention"))
	object.AlertmanagerRetentionDeclared = retention != ""
	object.AlertmanagerRetentionMilliseconds, object.AlertmanagerRetentionValid = parseAlertmanagerRetention(retention)
	pvcRetention := parseKubernetesPVCRetentionPolicy(yamlMappingValue(spec, "persistentVolumeClaimRetentionPolicy"))
	object.AlertmanagerPVCRetentionPolicyDeclared = pvcRetention.Declared
	object.AlertmanagerPVCRetentionPolicyObjectValid = pvcRetention.ObjectValid
	object.AlertmanagerPVCWhenDeletedValid = pvcRetention.WhenDeletedValid
	object.AlertmanagerPVCWhenDeleted = pvcRetention.WhenDeleted
	object.AlertmanagerPVCWhenScaledValid = pvcRetention.WhenScaledValid
	object.AlertmanagerPVCWhenScaled = pvcRetention.WhenScaled
	object.AlertmanagerPVCRetentionInvalidSettingCount = pvcRetention.InvalidSettingCount
	termination := parseKubernetesTerminationGrace(spec)
	object.AlertmanagerTerminationGraceDeclared = termination.Declared
	object.AlertmanagerTerminationGraceValid = termination.Valid
	object.AlertmanagerTerminationGraceSeconds = termination.Seconds
	supported, evaluable := kubernetesPrometheusVersionAtLeast(object.AlertmanagerVersion, 0, 25)
	object.AlertmanagerTerminationGraceVersionEvaluable = evaluable
	object.AlertmanagerTerminationGraceVersionUnsupported = object.AlertmanagerTerminationGraceDeclared && object.AlertmanagerTerminationGraceValid && evaluable && !supported
}

func populateKubernetesAlertmanagerStorageMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_storage_declared"] = strconv.FormatBool(object.AlertmanagerStorageDeclared)
	resource.Metadata["alertmanager_storage_mode"] = object.AlertmanagerStorageMode
	resource.Metadata["alertmanager_storage_option_count"] = strconv.Itoa(object.AlertmanagerStorageOptionCount)
	resource.Metadata["alertmanager_pvc_request_declared"] = strconv.FormatBool(object.AlertmanagerPVCRequestDeclared)
	resource.Metadata["alertmanager_pvc_request_valid"] = strconv.FormatBool(object.AlertmanagerPVCRequestValid)
	resource.Metadata["alertmanager_pvc_request_bytes"] = strconv.FormatInt(object.AlertmanagerPVCRequestBytes, 10)
	resource.Metadata["alertmanager_retention_declared"] = strconv.FormatBool(object.AlertmanagerRetentionDeclared)
	resource.Metadata["alertmanager_retention_valid"] = strconv.FormatBool(object.AlertmanagerRetentionValid)
	resource.Metadata["alertmanager_retention_milliseconds"] = strconv.FormatInt(object.AlertmanagerRetentionMilliseconds, 10)
	resource.Metadata["alertmanager_pvc_retention_policy_declared"] = strconv.FormatBool(object.AlertmanagerPVCRetentionPolicyDeclared)
	resource.Metadata["alertmanager_pvc_retention_policy_object_valid"] = strconv.FormatBool(object.AlertmanagerPVCRetentionPolicyObjectValid)
	resource.Metadata["alertmanager_pvc_when_deleted_valid"] = strconv.FormatBool(object.AlertmanagerPVCWhenDeletedValid)
	resource.Metadata["alertmanager_pvc_when_deleted"] = object.AlertmanagerPVCWhenDeleted
	resource.Metadata["alertmanager_pvc_when_scaled_valid"] = strconv.FormatBool(object.AlertmanagerPVCWhenScaledValid)
	resource.Metadata["alertmanager_pvc_when_scaled"] = object.AlertmanagerPVCWhenScaled
	resource.Metadata["alertmanager_pvc_retention_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerPVCRetentionInvalidSettingCount)
	resource.Metadata["alertmanager_termination_grace_declared"] = strconv.FormatBool(object.AlertmanagerTerminationGraceDeclared)
	resource.Metadata["alertmanager_termination_grace_valid"] = strconv.FormatBool(object.AlertmanagerTerminationGraceValid)
	resource.Metadata["alertmanager_termination_grace_seconds"] = strconv.FormatInt(object.AlertmanagerTerminationGraceSeconds, 10)
	resource.Metadata["alertmanager_termination_grace_version_evaluable"] = strconv.FormatBool(object.AlertmanagerTerminationGraceVersionEvaluable)
	resource.Metadata["alertmanager_termination_grace_version_unsupported"] = strconv.FormatBool(object.AlertmanagerTerminationGraceVersionUnsupported)
}

func parseAlertmanagerRetention(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if !alertmanagerRetentionPattern.MatchString(value) {
		return 0, false
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed.Milliseconds(), true
}
