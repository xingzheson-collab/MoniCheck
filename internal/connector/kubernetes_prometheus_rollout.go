package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusRolloutObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesRollout(spec)
	object.PrometheusRolloutMetadata = true
	object.PrometheusMinReadySeconds = summary.MinReadySeconds
	object.PrometheusMinReadySecondsDeclared = summary.MinReadySecondsDeclared
	object.PrometheusMinReadySecondsValid = summary.MinReadySecondsValid
	object.PrometheusAffinityDeclared = summary.AffinityDeclared
	object.PrometheusAffinityValid = summary.AffinityValid
	object.PrometheusPodAntiAffinityDeclared = summary.PodAntiAffinityDeclared
	object.PrometheusPodAntiAffinityTermCount = summary.PodAntiAffinityTermCount
	object.PrometheusTopologySpreadDeclared = summary.TopologySpreadDeclared
	object.PrometheusTopologySpreadCount = summary.TopologySpreadCount
	object.PrometheusSchedulingInvalidSettingCount = summary.SchedulingInvalidSettingCount
}

func populateKubernetesPrometheusRolloutMetadata(resource *model.Resource, object kubernetesObject) {
	applicable := object.Kind == "Prometheus" || object.PrometheusAgentMode != "daemonset"
	resource.Metadata["prometheus_rollout_metadata"] = strconv.FormatBool(object.PrometheusRolloutMetadata)
	resource.Metadata["prometheus_rollout_applicable"] = strconv.FormatBool(applicable)
	resource.Metadata["prometheus_min_ready_seconds_declared"] = strconv.FormatBool(object.PrometheusMinReadySecondsDeclared)
	resource.Metadata["prometheus_min_ready_seconds_valid"] = strconv.FormatBool(object.PrometheusMinReadySecondsValid)
	resource.Metadata["prometheus_min_ready_seconds"] = strconv.FormatInt(object.PrometheusMinReadySeconds, 10)
	resource.Metadata["prometheus_affinity_declared"] = strconv.FormatBool(object.PrometheusAffinityDeclared)
	resource.Metadata["prometheus_affinity_valid"] = strconv.FormatBool(object.PrometheusAffinityValid)
	resource.Metadata["prometheus_pod_anti_affinity_declared"] = strconv.FormatBool(object.PrometheusPodAntiAffinityDeclared)
	resource.Metadata["prometheus_pod_anti_affinity_term_count"] = strconv.Itoa(object.PrometheusPodAntiAffinityTermCount)
	resource.Metadata["prometheus_topology_spread_declared"] = strconv.FormatBool(object.PrometheusTopologySpreadDeclared)
	resource.Metadata["prometheus_topology_spread_count"] = strconv.Itoa(object.PrometheusTopologySpreadCount)
	resource.Metadata["prometheus_scheduling_invalid_setting_count"] = strconv.Itoa(object.PrometheusSchedulingInvalidSettingCount)
	resource.Metadata["prometheus_ha_scheduling_isolation"] = strconv.FormatBool(object.PrometheusPodAntiAffinityTermCount > 0 || object.PrometheusTopologySpreadCount > 0)
}
