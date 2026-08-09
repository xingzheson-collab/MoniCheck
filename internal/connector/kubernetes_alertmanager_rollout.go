package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerRolloutObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesRollout(spec)
	object.AlertmanagerRolloutMetadata = true
	object.AlertmanagerMinReadySeconds = summary.MinReadySeconds
	object.AlertmanagerMinReadySecondsDeclared = summary.MinReadySecondsDeclared
	object.AlertmanagerMinReadySecondsValid = summary.MinReadySecondsValid
	object.AlertmanagerAffinityDeclared = summary.AffinityDeclared
	object.AlertmanagerAffinityValid = summary.AffinityValid
	object.AlertmanagerPodAntiAffinityDeclared = summary.PodAntiAffinityDeclared
	object.AlertmanagerPodAntiAffinityTermCount = summary.PodAntiAffinityTermCount
	object.AlertmanagerTopologySpreadDeclared = summary.TopologySpreadDeclared
	object.AlertmanagerTopologySpreadCount = summary.TopologySpreadCount
	object.AlertmanagerSchedulingInvalidSettingCount = summary.SchedulingInvalidSettingCount
	object.AlertmanagerDispatchDelaySupported, object.AlertmanagerDispatchDelayVersionEvaluable = kubernetesPrometheusVersionAtLeast(object.AlertmanagerVersion, 0, 30)
}

func populateKubernetesAlertmanagerRolloutMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_rollout_metadata"] = strconv.FormatBool(object.AlertmanagerRolloutMetadata)
	resource.Metadata["alertmanager_min_ready_seconds_declared"] = strconv.FormatBool(object.AlertmanagerMinReadySecondsDeclared)
	resource.Metadata["alertmanager_min_ready_seconds_valid"] = strconv.FormatBool(object.AlertmanagerMinReadySecondsValid)
	resource.Metadata["alertmanager_min_ready_seconds"] = strconv.FormatInt(object.AlertmanagerMinReadySeconds, 10)
	resource.Metadata["alertmanager_dispatch_delay_version_evaluable"] = strconv.FormatBool(object.AlertmanagerDispatchDelayVersionEvaluable)
	resource.Metadata["alertmanager_dispatch_delay_supported"] = strconv.FormatBool(object.AlertmanagerDispatchDelaySupported)
	resource.Metadata["alertmanager_affinity_declared"] = strconv.FormatBool(object.AlertmanagerAffinityDeclared)
	resource.Metadata["alertmanager_affinity_valid"] = strconv.FormatBool(object.AlertmanagerAffinityValid)
	resource.Metadata["alertmanager_pod_anti_affinity_declared"] = strconv.FormatBool(object.AlertmanagerPodAntiAffinityDeclared)
	resource.Metadata["alertmanager_pod_anti_affinity_term_count"] = strconv.Itoa(object.AlertmanagerPodAntiAffinityTermCount)
	resource.Metadata["alertmanager_topology_spread_declared"] = strconv.FormatBool(object.AlertmanagerTopologySpreadDeclared)
	resource.Metadata["alertmanager_topology_spread_count"] = strconv.Itoa(object.AlertmanagerTopologySpreadCount)
	resource.Metadata["alertmanager_scheduling_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerSchedulingInvalidSettingCount)
	resource.Metadata["alertmanager_ha_scheduling_isolation"] = strconv.FormatBool(object.AlertmanagerPodAntiAffinityTermCount > 0 || object.AlertmanagerTopologySpreadCount > 0)
}
