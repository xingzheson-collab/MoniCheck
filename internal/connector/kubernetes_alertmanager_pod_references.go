package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerPodReferenceObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodReferences(spec)
	object.AlertmanagerPodReferenceMetadata = true
	object.AlertmanagerSecretsDeclared = summary.SecretsDeclared
	object.AlertmanagerSecretCount = summary.SecretCount
	object.AlertmanagerConfigMapsDeclared = summary.ConfigMapsDeclared
	object.AlertmanagerConfigMapCount = summary.ConfigMapCount
	object.AlertmanagerPodReferenceInvalidSettingCount = summary.InvalidSettingCount
	object.AlertmanagerGeneratedVolumeCollisionCount = summary.GeneratedVolumeCollisionCount
	object.AlertmanagerServiceAccountNameDeclared = summary.ServiceAccountNameDeclared
	object.AlertmanagerServiceAccountNameValid = summary.ServiceAccountNameValid
	object.AlertmanagerCustomServiceAccount = summary.CustomServiceAccount
}

func populateKubernetesAlertmanagerPodReferenceMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_pod_reference_metadata"] = strconv.FormatBool(object.AlertmanagerPodReferenceMetadata)
	resource.Metadata["alertmanager_secrets_declared"] = strconv.FormatBool(object.AlertmanagerSecretsDeclared)
	resource.Metadata["alertmanager_secret_count"] = strconv.Itoa(object.AlertmanagerSecretCount)
	resource.Metadata["alertmanager_config_maps_declared"] = strconv.FormatBool(object.AlertmanagerConfigMapsDeclared)
	resource.Metadata["alertmanager_config_map_count"] = strconv.Itoa(object.AlertmanagerConfigMapCount)
	resource.Metadata["alertmanager_pod_reference_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerPodReferenceInvalidSettingCount)
	resource.Metadata["alertmanager_generated_volume_collision_count"] = strconv.Itoa(object.AlertmanagerGeneratedVolumeCollisionCount)
	resource.Metadata["alertmanager_service_account_name_declared"] = strconv.FormatBool(object.AlertmanagerServiceAccountNameDeclared)
	resource.Metadata["alertmanager_service_account_name_valid"] = strconv.FormatBool(object.AlertmanagerServiceAccountNameValid)
	resource.Metadata["alertmanager_custom_service_account"] = strconv.FormatBool(object.AlertmanagerCustomServiceAccount)
}
