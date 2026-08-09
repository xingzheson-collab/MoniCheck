package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerPodCustomizationObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodCustomization(spec, "alertmanager")
	object.AlertmanagerPodCustomizationMetadata = true
	object.AlertmanagerPodMetadataDeclared = summary.PodMetadataDeclared
	object.AlertmanagerPodMetadataObjectValid = summary.PodMetadataObjectValid
	object.AlertmanagerPodMetadataLabelCount = summary.PodMetadataLabelCount
	object.AlertmanagerPodMetadataAnnotationCount = summary.PodMetadataAnnotationCount
	object.AlertmanagerReservedLabelOverrideCount = summary.ReservedLabelOverrideCount
	object.AlertmanagerReservedAnnotationOverrideCount = summary.ReservedAnnotationOverrideCount
	object.AlertmanagerHostAliasesDeclared = summary.HostAliasesDeclared
	object.AlertmanagerHostAliasCount = summary.HostAliasCount
	object.AlertmanagerHostAliasHostnameCount = summary.HostAliasHostnameCount
	object.AlertmanagerLoopbackHostAliasCount = summary.LoopbackHostAliasCount
	object.AlertmanagerPodCustomizationInvalidSettingCount = summary.InvalidSettingCount
}

func populateKubernetesAlertmanagerPodCustomizationMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_pod_customization_metadata"] = strconv.FormatBool(object.AlertmanagerPodCustomizationMetadata)
	resource.Metadata["alertmanager_pod_metadata_declared"] = strconv.FormatBool(object.AlertmanagerPodMetadataDeclared)
	resource.Metadata["alertmanager_pod_metadata_object_valid"] = strconv.FormatBool(object.AlertmanagerPodMetadataObjectValid)
	resource.Metadata["alertmanager_pod_metadata_label_count"] = strconv.Itoa(object.AlertmanagerPodMetadataLabelCount)
	resource.Metadata["alertmanager_pod_metadata_annotation_count"] = strconv.Itoa(object.AlertmanagerPodMetadataAnnotationCount)
	resource.Metadata["alertmanager_reserved_label_override_count"] = strconv.Itoa(object.AlertmanagerReservedLabelOverrideCount)
	resource.Metadata["alertmanager_reserved_annotation_override_count"] = strconv.Itoa(object.AlertmanagerReservedAnnotationOverrideCount)
	resource.Metadata["alertmanager_host_aliases_declared"] = strconv.FormatBool(object.AlertmanagerHostAliasesDeclared)
	resource.Metadata["alertmanager_host_alias_count"] = strconv.Itoa(object.AlertmanagerHostAliasCount)
	resource.Metadata["alertmanager_host_alias_hostname_count"] = strconv.Itoa(object.AlertmanagerHostAliasHostnameCount)
	resource.Metadata["alertmanager_loopback_host_alias_count"] = strconv.Itoa(object.AlertmanagerLoopbackHostAliasCount)
	resource.Metadata["alertmanager_pod_customization_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerPodCustomizationInvalidSettingCount)
}
