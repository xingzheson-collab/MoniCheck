package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerPodCustomizationObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodCustomization(spec, "thanos-ruler")
	object.ThanosRulerPodCustomizationMetadata = true
	object.ThanosRulerPodMetadataDeclared = summary.PodMetadataDeclared
	object.ThanosRulerPodMetadataObjectValid = summary.PodMetadataObjectValid
	object.ThanosRulerPodMetadataLabelCount = summary.PodMetadataLabelCount
	object.ThanosRulerPodMetadataAnnotationCount = summary.PodMetadataAnnotationCount
	object.ThanosRulerReservedLabelOverrideCount = summary.ReservedLabelOverrideCount
	object.ThanosRulerReservedAnnotationOverrideCount = summary.ReservedAnnotationOverrideCount
	object.ThanosRulerHostAliasesDeclared = summary.HostAliasesDeclared
	object.ThanosRulerHostAliasCount = summary.HostAliasCount
	object.ThanosRulerHostAliasHostnameCount = summary.HostAliasHostnameCount
	object.ThanosRulerLoopbackHostAliasCount = summary.LoopbackHostAliasCount
	object.ThanosRulerPodCustomizationInvalidSettingCount = summary.InvalidSettingCount
}

func populateKubernetesThanosRulerPodCustomizationMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_pod_customization_metadata"] = strconv.FormatBool(object.ThanosRulerPodCustomizationMetadata)
	resource.Metadata["thanos_ruler_pod_metadata_declared"] = strconv.FormatBool(object.ThanosRulerPodMetadataDeclared)
	resource.Metadata["thanos_ruler_pod_metadata_object_valid"] = strconv.FormatBool(object.ThanosRulerPodMetadataObjectValid)
	resource.Metadata["thanos_ruler_pod_metadata_label_count"] = strconv.Itoa(object.ThanosRulerPodMetadataLabelCount)
	resource.Metadata["thanos_ruler_pod_metadata_annotation_count"] = strconv.Itoa(object.ThanosRulerPodMetadataAnnotationCount)
	resource.Metadata["thanos_ruler_reserved_label_override_count"] = strconv.Itoa(object.ThanosRulerReservedLabelOverrideCount)
	resource.Metadata["thanos_ruler_reserved_annotation_override_count"] = strconv.Itoa(object.ThanosRulerReservedAnnotationOverrideCount)
	resource.Metadata["thanos_ruler_host_aliases_declared"] = strconv.FormatBool(object.ThanosRulerHostAliasesDeclared)
	resource.Metadata["thanos_ruler_host_alias_count"] = strconv.Itoa(object.ThanosRulerHostAliasCount)
	resource.Metadata["thanos_ruler_host_alias_hostname_count"] = strconv.Itoa(object.ThanosRulerHostAliasHostnameCount)
	resource.Metadata["thanos_ruler_loopback_host_alias_count"] = strconv.Itoa(object.ThanosRulerLoopbackHostAliasCount)
	resource.Metadata["thanos_ruler_pod_customization_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerPodCustomizationInvalidSettingCount)
}
