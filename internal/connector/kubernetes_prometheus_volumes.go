package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusVolumeObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesVolumes(spec)
	object.PrometheusVolumeMetadata = true
	object.PrometheusVolumesDeclared = summary.VolumesDeclared
	object.PrometheusVolumeMountsDeclared = summary.VolumeMountsDeclared
	object.PrometheusVolumeInvalidSettingCount = summary.InvalidSettingCount
	object.PrometheusVolumeCount = summary.VolumeCount
	object.PrometheusVolumeMountCount = summary.VolumeMountCount
	object.PrometheusHostPathVolumeCount = summary.HostPathVolumeCount
	object.PrometheusWritableHostPathMountCount = summary.WritableHostPathMountCount
	object.PrometheusBidirectionalMountCount = summary.BidirectionalMountCount
}

func populateKubernetesPrometheusVolumeMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_volume_metadata"] = strconv.FormatBool(object.PrometheusVolumeMetadata)
	resource.Metadata["prometheus_volumes_declared"] = strconv.FormatBool(object.PrometheusVolumesDeclared)
	resource.Metadata["prometheus_volume_mounts_declared"] = strconv.FormatBool(object.PrometheusVolumeMountsDeclared)
	resource.Metadata["prometheus_volume_invalid_setting_count"] = strconv.Itoa(object.PrometheusVolumeInvalidSettingCount)
	resource.Metadata["prometheus_volume_count"] = strconv.Itoa(object.PrometheusVolumeCount)
	resource.Metadata["prometheus_volume_mount_count"] = strconv.Itoa(object.PrometheusVolumeMountCount)
	resource.Metadata["prometheus_host_path_volume_count"] = strconv.Itoa(object.PrometheusHostPathVolumeCount)
	resource.Metadata["prometheus_writable_host_path_mount_count"] = strconv.Itoa(object.PrometheusWritableHostPathMountCount)
	resource.Metadata["prometheus_bidirectional_mount_count"] = strconv.Itoa(object.PrometheusBidirectionalMountCount)
}
