package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerVolumeObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesVolumes(spec)
	object.ThanosRulerVolumeMetadata = true
	object.ThanosRulerVolumesDeclared = summary.VolumesDeclared
	object.ThanosRulerVolumeMountsDeclared = summary.VolumeMountsDeclared
	object.ThanosRulerVolumeInvalidSettingCount = summary.InvalidSettingCount
	object.ThanosRulerVolumeCount = summary.VolumeCount
	object.ThanosRulerVolumeMountCount = summary.VolumeMountCount
	object.ThanosRulerHostPathVolumeCount = summary.HostPathVolumeCount
	object.ThanosRulerWritableHostPathMountCount = summary.WritableHostPathMountCount
	object.ThanosRulerBidirectionalMountCount = summary.BidirectionalMountCount
}

func populateKubernetesThanosRulerVolumeMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_volume_metadata"] = strconv.FormatBool(object.ThanosRulerVolumeMetadata)
	resource.Metadata["thanos_ruler_volumes_declared"] = strconv.FormatBool(object.ThanosRulerVolumesDeclared)
	resource.Metadata["thanos_ruler_volume_mounts_declared"] = strconv.FormatBool(object.ThanosRulerVolumeMountsDeclared)
	resource.Metadata["thanos_ruler_volume_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerVolumeInvalidSettingCount)
	resource.Metadata["thanos_ruler_volume_count"] = strconv.Itoa(object.ThanosRulerVolumeCount)
	resource.Metadata["thanos_ruler_volume_mount_count"] = strconv.Itoa(object.ThanosRulerVolumeMountCount)
	resource.Metadata["thanos_ruler_host_path_volume_count"] = strconv.Itoa(object.ThanosRulerHostPathVolumeCount)
	resource.Metadata["thanos_ruler_writable_host_path_mount_count"] = strconv.Itoa(object.ThanosRulerWritableHostPathMountCount)
	resource.Metadata["thanos_ruler_bidirectional_mount_count"] = strconv.Itoa(object.ThanosRulerBidirectionalMountCount)
}
