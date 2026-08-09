package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesPrometheusImageObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesImageSettings(spec)
	object.PrometheusImageMetadata = true
	object.PrometheusImageDeclared = summary.ImageDeclared
	object.PrometheusImageValid = summary.ImageValid
	object.PrometheusImageDigestPinned = summary.ImageDigestPinned
	object.PrometheusImageLatestTag = summary.ImageLatestTag
	object.PrometheusImagePullPolicyDeclared = summary.ImagePullPolicyDeclared
	object.PrometheusImagePullPolicyValid = summary.ImagePullPolicyValid
	object.PrometheusImagePullPolicy = summary.ImagePullPolicy
	object.PrometheusLegacyImageFieldCount = summary.LegacyImageFieldCount
	object.PrometheusShadowedLegacyImageFieldCount = summary.ShadowedLegacyImageFieldCount
	object.PrometheusImagePullSecretsDeclared = summary.ImagePullSecretsDeclared
	object.PrometheusImagePullSecretCount = summary.ImagePullSecretCount
	object.PrometheusImageInvalidSettingCount = summary.InvalidCount
}

func populateKubernetesPrometheusImageMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_image_metadata"] = strconv.FormatBool(object.PrometheusImageMetadata)
	resource.Metadata["prometheus_image_declared"] = strconv.FormatBool(object.PrometheusImageDeclared)
	resource.Metadata["prometheus_image_valid"] = strconv.FormatBool(object.PrometheusImageValid)
	resource.Metadata["prometheus_image_digest_pinned"] = strconv.FormatBool(object.PrometheusImageDigestPinned)
	resource.Metadata["prometheus_image_latest_tag"] = strconv.FormatBool(object.PrometheusImageLatestTag)
	resource.Metadata["prometheus_image_pull_policy_declared"] = strconv.FormatBool(object.PrometheusImagePullPolicyDeclared)
	resource.Metadata["prometheus_image_pull_policy_valid"] = strconv.FormatBool(object.PrometheusImagePullPolicyValid)
	resource.Metadata["prometheus_image_pull_policy"] = object.PrometheusImagePullPolicy
	resource.Metadata["prometheus_legacy_image_field_count"] = strconv.Itoa(object.PrometheusLegacyImageFieldCount)
	resource.Metadata["prometheus_shadowed_legacy_image_field_count"] = strconv.Itoa(object.PrometheusShadowedLegacyImageFieldCount)
	resource.Metadata["prometheus_image_pull_secrets_declared"] = strconv.FormatBool(object.PrometheusImagePullSecretsDeclared)
	resource.Metadata["prometheus_image_pull_secret_count"] = strconv.Itoa(object.PrometheusImagePullSecretCount)
	resource.Metadata["prometheus_image_invalid_setting_count"] = strconv.Itoa(object.PrometheusImageInvalidSettingCount)
}
