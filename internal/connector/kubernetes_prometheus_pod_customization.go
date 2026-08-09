package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusPodCustomizationObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodCustomization(spec, "prometheus")
	object.PrometheusPodCustomizationMetadata = true
	object.PrometheusPodMetadataDeclared = summary.PodMetadataDeclared
	object.PrometheusPodMetadataObjectValid = summary.PodMetadataObjectValid
	object.PrometheusPodMetadataLabelCount = summary.PodMetadataLabelCount
	object.PrometheusPodMetadataAnnotationCount = summary.PodMetadataAnnotationCount
	object.PrometheusReservedLabelOverrideCount = summary.ReservedLabelOverrideCount
	object.PrometheusReservedAnnotationOverrideCount = summary.ReservedAnnotationOverrideCount
	object.PrometheusHostAliasesDeclared = summary.HostAliasesDeclared
	object.PrometheusHostAliasCount = summary.HostAliasCount
	object.PrometheusHostAliasHostnameCount = summary.HostAliasHostnameCount
	object.PrometheusLoopbackHostAliasCount = summary.LoopbackHostAliasCount
	object.PrometheusPodCustomizationInvalidSettingCount = summary.InvalidSettingCount
}

func populateKubernetesPrometheusPodCustomizationMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_pod_customization_metadata"] = strconv.FormatBool(object.PrometheusPodCustomizationMetadata)
	resource.Metadata["prometheus_pod_metadata_declared"] = strconv.FormatBool(object.PrometheusPodMetadataDeclared)
	resource.Metadata["prometheus_pod_metadata_object_valid"] = strconv.FormatBool(object.PrometheusPodMetadataObjectValid)
	resource.Metadata["prometheus_pod_metadata_label_count"] = strconv.Itoa(object.PrometheusPodMetadataLabelCount)
	resource.Metadata["prometheus_pod_metadata_annotation_count"] = strconv.Itoa(object.PrometheusPodMetadataAnnotationCount)
	resource.Metadata["prometheus_reserved_label_override_count"] = strconv.Itoa(object.PrometheusReservedLabelOverrideCount)
	resource.Metadata["prometheus_reserved_annotation_override_count"] = strconv.Itoa(object.PrometheusReservedAnnotationOverrideCount)
	resource.Metadata["prometheus_host_aliases_declared"] = strconv.FormatBool(object.PrometheusHostAliasesDeclared)
	resource.Metadata["prometheus_host_alias_count"] = strconv.Itoa(object.PrometheusHostAliasCount)
	resource.Metadata["prometheus_host_alias_hostname_count"] = strconv.Itoa(object.PrometheusHostAliasHostnameCount)
	resource.Metadata["prometheus_loopback_host_alias_count"] = strconv.Itoa(object.PrometheusLoopbackHostAliasCount)
	resource.Metadata["prometheus_pod_customization_invalid_setting_count"] = strconv.Itoa(object.PrometheusPodCustomizationInvalidSettingCount)
}
