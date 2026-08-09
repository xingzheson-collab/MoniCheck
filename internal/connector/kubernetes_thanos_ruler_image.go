package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerImageObject(object *kubernetesObject, spec *yaml.Node) {
	summary := kubernetesImageSettingsSummary{}
	parseKubernetesImageReference(&summary, yamlMappingValue(spec, "image"))
	parseKubernetesImagePullPolicy(&summary, yamlMappingValue(spec, "imagePullPolicy"))
	parseKubernetesImagePullSecrets(&summary, yamlMappingValue(spec, "imagePullSecrets"))
	for _, field := range []string{"baseImage", "tag", "sha"} {
		if yamlValueDeclared(yamlMappingValue(spec, field)) {
			object.ThanosRulerUnsupportedLegacyImageFieldCount++
			summary.InvalidCount++
		}
	}
	object.ThanosRulerImageMetadata = true
	object.ThanosRulerImageDeclared = summary.ImageDeclared
	object.ThanosRulerImageValid = summary.ImageValid
	object.ThanosRulerImageDigestPinned = summary.ImageDigestPinned
	object.ThanosRulerImageLatestTag = summary.ImageLatestTag
	object.ThanosRulerImagePullPolicyDeclared = summary.ImagePullPolicyDeclared
	object.ThanosRulerImagePullPolicyValid = summary.ImagePullPolicyValid
	object.ThanosRulerImagePullPolicy = summary.ImagePullPolicy
	object.ThanosRulerImagePullSecretsDeclared = summary.ImagePullSecretsDeclared
	object.ThanosRulerImagePullSecretCount = summary.ImagePullSecretCount
	object.ThanosRulerImageInvalidSettingCount = summary.InvalidCount
}

func populateKubernetesThanosRulerImageMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_image_metadata"] = strconv.FormatBool(object.ThanosRulerImageMetadata)
	resource.Metadata["thanos_ruler_image_declared"] = strconv.FormatBool(object.ThanosRulerImageDeclared)
	resource.Metadata["thanos_ruler_image_valid"] = strconv.FormatBool(object.ThanosRulerImageValid)
	resource.Metadata["thanos_ruler_image_digest_pinned"] = strconv.FormatBool(object.ThanosRulerImageDigestPinned)
	resource.Metadata["thanos_ruler_image_latest_tag"] = strconv.FormatBool(object.ThanosRulerImageLatestTag)
	resource.Metadata["thanos_ruler_image_pull_policy_declared"] = strconv.FormatBool(object.ThanosRulerImagePullPolicyDeclared)
	resource.Metadata["thanos_ruler_image_pull_policy_valid"] = strconv.FormatBool(object.ThanosRulerImagePullPolicyValid)
	resource.Metadata["thanos_ruler_image_pull_policy"] = object.ThanosRulerImagePullPolicy
	resource.Metadata["thanos_ruler_image_pull_secrets_declared"] = strconv.FormatBool(object.ThanosRulerImagePullSecretsDeclared)
	resource.Metadata["thanos_ruler_image_pull_secret_count"] = strconv.Itoa(object.ThanosRulerImagePullSecretCount)
	resource.Metadata["thanos_ruler_unsupported_legacy_image_field_count"] = strconv.Itoa(object.ThanosRulerUnsupportedLegacyImageFieldCount)
	resource.Metadata["thanos_ruler_image_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerImageInvalidSettingCount)
}
