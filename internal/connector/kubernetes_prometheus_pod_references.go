package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusPodReferenceObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodReferences(spec)
	object.PrometheusPodReferenceMetadata = true
	object.PrometheusSecretsDeclared = summary.SecretsDeclared
	object.PrometheusSecretCount = summary.SecretCount
	object.PrometheusConfigMapsDeclared = summary.ConfigMapsDeclared
	object.PrometheusConfigMapCount = summary.ConfigMapCount
	object.PrometheusPodReferenceInvalidSettingCount = summary.InvalidSettingCount
	object.PrometheusGeneratedVolumeCollisionCount = summary.GeneratedVolumeCollisionCount
	object.PrometheusServiceAccountNameDeclared = summary.ServiceAccountNameDeclared
	object.PrometheusServiceAccountNameValid = summary.ServiceAccountNameValid
	object.PrometheusCustomServiceAccount = summary.CustomServiceAccount
}

func populateKubernetesPrometheusPodReferenceMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_pod_reference_metadata"] = strconv.FormatBool(object.PrometheusPodReferenceMetadata)
	resource.Metadata["prometheus_secrets_declared"] = strconv.FormatBool(object.PrometheusSecretsDeclared)
	resource.Metadata["prometheus_secret_count"] = strconv.Itoa(object.PrometheusSecretCount)
	resource.Metadata["prometheus_config_maps_declared"] = strconv.FormatBool(object.PrometheusConfigMapsDeclared)
	resource.Metadata["prometheus_config_map_count"] = strconv.Itoa(object.PrometheusConfigMapCount)
	resource.Metadata["prometheus_pod_reference_invalid_setting_count"] = strconv.Itoa(object.PrometheusPodReferenceInvalidSettingCount)
	resource.Metadata["prometheus_generated_volume_collision_count"] = strconv.Itoa(object.PrometheusGeneratedVolumeCollisionCount)
	resource.Metadata["prometheus_service_account_name_declared"] = strconv.FormatBool(object.PrometheusServiceAccountNameDeclared)
	resource.Metadata["prometheus_service_account_name_valid"] = strconv.FormatBool(object.PrometheusServiceAccountNameValid)
	resource.Metadata["prometheus_custom_service_account"] = strconv.FormatBool(object.PrometheusCustomServiceAccount)
}
