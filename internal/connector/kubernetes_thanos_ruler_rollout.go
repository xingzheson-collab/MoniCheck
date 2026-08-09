package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerRolloutObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesRollout(spec)
	object.ThanosRulerRolloutMetadata = true
	object.ThanosRulerMinReadySeconds = summary.MinReadySeconds
	object.ThanosRulerMinReadySecondsDeclared = summary.MinReadySecondsDeclared
	object.ThanosRulerMinReadySecondsValid = summary.MinReadySecondsValid
	object.ThanosRulerAffinityDeclared = summary.AffinityDeclared
	object.ThanosRulerAffinityValid = summary.AffinityValid
	object.ThanosRulerPodAntiAffinityDeclared = summary.PodAntiAffinityDeclared
	object.ThanosRulerPodAntiAffinityTermCount = summary.PodAntiAffinityTermCount
	object.ThanosRulerTopologySpreadDeclared = summary.TopologySpreadDeclared
	object.ThanosRulerTopologySpreadCount = summary.TopologySpreadCount
	object.ThanosRulerSchedulingInvalidSettingCount = summary.SchedulingInvalidSettingCount
}

func populateKubernetesThanosRulerRolloutMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_rollout_metadata"] = strconv.FormatBool(object.ThanosRulerRolloutMetadata)
	resource.Metadata["thanos_ruler_min_ready_seconds_declared"] = strconv.FormatBool(object.ThanosRulerMinReadySecondsDeclared)
	resource.Metadata["thanos_ruler_min_ready_seconds_valid"] = strconv.FormatBool(object.ThanosRulerMinReadySecondsValid)
	resource.Metadata["thanos_ruler_min_ready_seconds"] = strconv.FormatInt(object.ThanosRulerMinReadySeconds, 10)
	resource.Metadata["thanos_ruler_affinity_declared"] = strconv.FormatBool(object.ThanosRulerAffinityDeclared)
	resource.Metadata["thanos_ruler_affinity_valid"] = strconv.FormatBool(object.ThanosRulerAffinityValid)
	resource.Metadata["thanos_ruler_pod_anti_affinity_declared"] = strconv.FormatBool(object.ThanosRulerPodAntiAffinityDeclared)
	resource.Metadata["thanos_ruler_pod_anti_affinity_term_count"] = strconv.Itoa(object.ThanosRulerPodAntiAffinityTermCount)
	resource.Metadata["thanos_ruler_topology_spread_declared"] = strconv.FormatBool(object.ThanosRulerTopologySpreadDeclared)
	resource.Metadata["thanos_ruler_topology_spread_count"] = strconv.Itoa(object.ThanosRulerTopologySpreadCount)
	resource.Metadata["thanos_ruler_scheduling_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerSchedulingInvalidSettingCount)
	resource.Metadata["thanos_ruler_ha_scheduling_isolation"] = strconv.FormatBool(object.ThanosRulerPodAntiAffinityTermCount > 0 || object.ThanosRulerTopologySpreadCount > 0)
}
