package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesAlertmanagerImageObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesImageSettings(spec)
	object.AlertmanagerImageMetadata = true
	object.AlertmanagerImageDeclared = summary.ImageDeclared
	object.AlertmanagerImageValid = summary.ImageValid
	object.AlertmanagerImageDigestPinned = summary.ImageDigestPinned
	object.AlertmanagerImageLatestTag = summary.ImageLatestTag
	object.AlertmanagerImagePullPolicyDeclared = summary.ImagePullPolicyDeclared
	object.AlertmanagerImagePullPolicyValid = summary.ImagePullPolicyValid
	object.AlertmanagerImagePullPolicy = summary.ImagePullPolicy
	object.AlertmanagerLegacyImageFieldCount = summary.LegacyImageFieldCount
	object.AlertmanagerShadowedLegacyImageFieldCount = summary.ShadowedLegacyImageFieldCount
	object.AlertmanagerImagePullSecretsDeclared = summary.ImagePullSecretsDeclared
	object.AlertmanagerImagePullSecretCount = summary.ImagePullSecretCount
	object.AlertmanagerImageInvalidSettingCount = summary.InvalidCount
}

func populateKubernetesAlertmanagerImageMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_image_metadata"] = strconv.FormatBool(object.AlertmanagerImageMetadata)
	resource.Metadata["alertmanager_image_declared"] = strconv.FormatBool(object.AlertmanagerImageDeclared)
	resource.Metadata["alertmanager_image_valid"] = strconv.FormatBool(object.AlertmanagerImageValid)
	resource.Metadata["alertmanager_image_digest_pinned"] = strconv.FormatBool(object.AlertmanagerImageDigestPinned)
	resource.Metadata["alertmanager_image_latest_tag"] = strconv.FormatBool(object.AlertmanagerImageLatestTag)
	resource.Metadata["alertmanager_image_pull_policy_declared"] = strconv.FormatBool(object.AlertmanagerImagePullPolicyDeclared)
	resource.Metadata["alertmanager_image_pull_policy_valid"] = strconv.FormatBool(object.AlertmanagerImagePullPolicyValid)
	resource.Metadata["alertmanager_image_pull_policy"] = object.AlertmanagerImagePullPolicy
	resource.Metadata["alertmanager_legacy_image_field_count"] = strconv.Itoa(object.AlertmanagerLegacyImageFieldCount)
	resource.Metadata["alertmanager_shadowed_legacy_image_field_count"] = strconv.Itoa(object.AlertmanagerShadowedLegacyImageFieldCount)
	resource.Metadata["alertmanager_image_pull_secrets_declared"] = strconv.FormatBool(object.AlertmanagerImagePullSecretsDeclared)
	resource.Metadata["alertmanager_image_pull_secret_count"] = strconv.Itoa(object.AlertmanagerImagePullSecretCount)
	resource.Metadata["alertmanager_image_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerImageInvalidSettingCount)
}
