package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerVolumeObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesVolumes(spec)
	object.AlertmanagerVolumeMetadata = true
	object.AlertmanagerVolumesDeclared = summary.VolumesDeclared
	object.AlertmanagerVolumeMountsDeclared = summary.VolumeMountsDeclared
	object.AlertmanagerVolumeInvalidSettingCount = summary.InvalidSettingCount
	object.AlertmanagerVolumeCount = summary.VolumeCount
	object.AlertmanagerVolumeMountCount = summary.VolumeMountCount
	object.AlertmanagerHostPathVolumeCount = summary.HostPathVolumeCount
	object.AlertmanagerWritableHostPathMountCount = summary.WritableHostPathMountCount
	object.AlertmanagerBidirectionalMountCount = summary.BidirectionalMountCount
}

func populateKubernetesAlertmanagerVolumeMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_volume_metadata"] = strconv.FormatBool(object.AlertmanagerVolumeMetadata)
	resource.Metadata["alertmanager_volumes_declared"] = strconv.FormatBool(object.AlertmanagerVolumesDeclared)
	resource.Metadata["alertmanager_volume_mounts_declared"] = strconv.FormatBool(object.AlertmanagerVolumeMountsDeclared)
	resource.Metadata["alertmanager_volume_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerVolumeInvalidSettingCount)
	resource.Metadata["alertmanager_volume_count"] = strconv.Itoa(object.AlertmanagerVolumeCount)
	resource.Metadata["alertmanager_volume_mount_count"] = strconv.Itoa(object.AlertmanagerVolumeMountCount)
	resource.Metadata["alertmanager_host_path_volume_count"] = strconv.Itoa(object.AlertmanagerHostPathVolumeCount)
	resource.Metadata["alertmanager_writable_host_path_mount_count"] = strconv.Itoa(object.AlertmanagerWritableHostPathMountCount)
	resource.Metadata["alertmanager_bidirectional_mount_count"] = strconv.Itoa(object.AlertmanagerBidirectionalMountCount)
}
